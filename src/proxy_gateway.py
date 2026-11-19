"""Revocable loopback HTTP proxy with a single fixed Clash upstream.

This is a process-local lifecycle gate, not an authentication boundary: any
local process can use it while open. No destination is ever dialed directly.
Failures are reported on the detecting worker thread after revocation. Normal
EOF after a successful handshake is not proof that the proxy has failed.
"""

import select
import socket
import threading
import time
from collections.abc import Callable


class _Revoked(Exception):
    pass


class _BadHeader(Exception):
    pass


class _ClientClosed(Exception):
    pass


class ProxyGateway:
    """Owns a loopback listener; start() leaves it closed until open().

    close() revokes accepted clients and in-flight upstream dials atomically.
    open() explicitly begins a new epoch. on_failure receives a fixed reason
    without URLs or credentials, once per open epoch. Callbacks must be brief.
    """

    MAX_HEADER = 64 * 1024
    MAX_CONNECTIONS = 64
    HANDSHAKE_TIMEOUT = 5.0
    BUFFER_SIZE = 64 * 1024

    def __init__(self, upstream_port: int,
                 on_failure: Callable[[str], None] | None = None):
        if (not isinstance(upstream_port, int)
                or isinstance(upstream_port, bool)
                or not 1 <= upstream_port <= 65535):
            raise ValueError("Invalid upstream port")
        self._upstream_port = upstream_port
        self._on_failure = on_failure
        self._lock = threading.RLock()
        self._listener = None
        self._accept_thread = None
        self._workers = set()
        self._sockets = set()
        self._connections = 0
        self._epoch = 0
        self._enabled = False

    @property
    def port(self) -> int:
        """Returns the listening port, or zero when stopped."""
        with self._lock:
            return self._listener.getsockname()[1] if self._listener else 0

    def start(self) -> int:
        """Starts a closed listener on an ephemeral IPv4 loopback port."""
        with self._lock:
            if self._listener is not None:
                return self.port
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.bind(("127.0.0.1", 0))
                listener.listen(self.MAX_CONNECTIONS)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise
            self._enabled = False
            self._listener = listener
            self._accept_thread = threading.Thread(
                target=self._accept, args=(listener,), daemon=True,
                name="proxy-gateway-accept")
            self._accept_thread.start()
            return self.port

    def open(self) -> None:
        """Enables business traffic; repeated calls while open are harmless."""
        with self._lock:
            if self._listener is None:
                raise RuntimeError("Gateway has not started")
            if not self._enabled:
                self._epoch += 1
                self._enabled = True

    @staticmethod
    def _shutdown(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _close_locked(self):
        self._enabled = False
        self._epoch += 1
        for sock in self._sockets:
            self._shutdown(sock)
        self._sockets.clear()

    def close(self, reason: str = "") -> None:
        """Latches closed and revokes all sockets; reason is never logged."""
        with self._lock:
            self._close_locked()

    def stop(self) -> None:
        """Closes traffic and listener and waits briefly for owned threads."""
        with self._lock:
            self._close_locked()
            listener = self._listener
            self._listener = None
            if listener is not None:
                self._shutdown(listener)
            threads = list(self._workers)
            if self._accept_thread:
                threads.append(self._accept_thread)
        deadline = time.monotonic() + 2.0
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(max(0, deadline - time.monotonic()))

    def _check(self, epoch):
        if not self._enabled or self._epoch != epoch:
            raise _Revoked()

    def _failure(self, epoch, reason):
        with self._lock:
            if not self._enabled or self._epoch != epoch:
                return
            self._close_locked()
        if self._on_failure:
            try:
                self._on_failure(reason)
            except Exception:
                pass

    def _accept(self, listener):
        while True:
            try:
                client, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                if (self._listener is not listener or not self._enabled
                        or self._connections >= self.MAX_CONNECTIONS):
                    self._shutdown(client)
                    continue
                self._sockets.add(client)
                self._connections += 1
                worker = threading.Thread(
                    target=self._serve, args=(client, self._epoch), daemon=True,
                    name="proxy-gateway-client")
                self._workers.add(worker)
                worker.start()

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Handshake timeout")
        return remaining

    def _header(self, sock, deadline):
        data = bytearray()
        while True:
            sock.settimeout(self._remaining(deadline))
            chunk = sock.recv(min(4096, self.MAX_HEADER + 1 - len(data)))
            if not chunk:
                raise _BadHeader()
            data.extend(chunk)
            end = data.find(b"\r\n\r\n")
            if end >= 0:
                end += 4
                if end > self.MAX_HEADER:
                    raise _BadHeader()
                return bytes(data[:end]), bytes(data[end:])
            if len(data) >= self.MAX_HEADER:
                raise _BadHeader()

    def _send(self, sock, data, deadline):
        sock.settimeout(self._remaining(deadline))
        sock.sendall(data)

    def _serve(self, client, epoch):
        upstream = None
        stage = "client"
        try:
            deadline = time.monotonic() + self.HANDSHAKE_TIMEOUT
            header, extra = self._header(client, deadline)
            parts = header.split(b"\r\n", 1)[0].split(b" ")
            if (len(parts) != 3 or not parts[0] or not parts[1]
                    or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1")):
                raise _BadHeader()
            stage = "upstream"
            with self._lock:
                self._check(epoch)
                upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sockets.add(upstream)
            upstream.settimeout(self._remaining(deadline))
            upstream.connect(("127.0.0.1", self._upstream_port))
            with self._lock:
                self._check(epoch)
            self._send(upstream, header + extra, deadline)
            if parts[0] != b"CONNECT":
                stage = "relay"
                self._relay(client, upstream, deadline)
                return
            response, extra = self._header(upstream, deadline)
            status = response.split(b"\r\n", 1)[0].split(b" ", 2)
            if (len(status) < 2 or status[0] not in
                    (b"HTTP/1.0", b"HTTP/1.1") or len(status[1]) != 3
                    or not status[1].isdigit()
                    or not 100 <= int(status[1]) <= 599):
                raise _BadHeader()
            code = int(status[1])
            if (parts[0] == b"CONNECT" and not 200 <= code < 300) or code == 407:
                raise _BadHeader()
            stage = "client"
            with self._lock:
                self._check(epoch)
            self._send(client, response + extra, deadline)
            stage = "relay"
            self._relay(client, upstream)
        except (_Revoked, _ClientClosed):
            pass
        except (OSError, _BadHeader, ValueError):
            if stage in ("upstream", "relay"):
                self._failure(epoch, "upstream_handshake_failed" if
                              stage == "upstream" else "proxy_transport_failed")
        finally:
            with self._lock:
                for sock in (client, upstream):
                    if sock is not None:
                        self._sockets.discard(sock)
                        self._shutdown(sock)
                self._connections -= 1
                self._workers.discard(threading.current_thread())

    def _relay(self, client, upstream, deadline=None):
        sockets = (client, upstream)
        buffers = {client: bytearray(), upstream: bytearray()}
        readable = set(sockets)
        response_header = bytearray()
        for sock in sockets:
            sock.setblocking(False)
        while readable or any(buffers.values()):
            timeout = min(0.2, self._remaining(deadline)) if deadline else 0.2
            readers = [sock for sock in readable
                       if len(buffers[sockets[1 - sockets.index(sock)]])
                       < self.BUFFER_SIZE]
            writers = [sock for sock in sockets if buffers[sock]]
            ready_read, ready_write, _ = select.select(
                readers, writers, [], timeout)
            for sock in ready_write:
                try:
                    sent = sock.send(buffers[sock])
                except BlockingIOError:
                    continue
                except OSError:
                    if sock is client:
                        raise _ClientClosed() from None
                    raise
                if not sent:
                    raise ConnectionError("Proxy transport closed")
                del buffers[sock][:sent]
                other = sockets[1 - sockets.index(sock)]
                if not buffers[sock] and other not in readable:
                    self._half_close(sock, client)
            for sock in ready_read:
                other = sockets[1 - sockets.index(sock)]
                try:
                    data = sock.recv(self.BUFFER_SIZE - len(buffers[other]))
                except BlockingIOError:
                    continue
                except OSError:
                    if sock is client:
                        raise _ClientClosed() from None
                    raise
                if data:
                    if sock is upstream and deadline:
                        response_header.extend(data)
                        end = response_header.find(b"\r\n\r\n")
                        if end < 0:
                            if len(response_header) >= self.MAX_HEADER:
                                raise _BadHeader()
                            continue
                        if end + 4 > self.MAX_HEADER:
                            raise _BadHeader()
                        status = response_header.split(b"\r\n", 1)[0].split()
                        if (len(status) < 2 or status[0] not in
                                (b"HTTP/1.0", b"HTTP/1.1")
                                or len(status[1]) != 3
                                or not status[1].isdigit()
                                or not 100 <= int(status[1]) <= 599
                                or status[1] == b"407"):
                            raise _BadHeader()
                        data = bytes(response_header)
                        deadline = None
                    buffers[other].extend(data)
                else:
                    if sock is upstream and deadline:
                        raise _BadHeader()
                    readable.remove(sock)
                    if not buffers[other]:
                        self._half_close(other, client)

    @staticmethod
    def _half_close(sock, client):
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            if sock is client:
                raise _ClientClosed() from None
            raise
