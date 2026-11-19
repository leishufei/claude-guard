"""Real loopback checks; no external network or operating system proxy edits."""

import concurrent.futures
import select
import socket
import socketserver
import struct
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxy_gateway import ProxyGateway


def read_header(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    header, extra = bytes(data).split(b"\r\n\r\n", 1)
    return header + b"\r\n\r\n", extra


def read_all(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


class LoopbackServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, handler):
        self.connections = 0
        self.requests = []
        self.sockets = set()
        self.lock = threading.Lock()
        self.accepted = threading.Event()
        self.release = threading.Event()
        server = self

        class Handler(socketserver.BaseRequestHandler):

            def handle(self):
                self.request.settimeout(3)
                with server.lock:
                    server.connections += 1
                    server.sockets.add(self.request)
                server.accepted.set()
                try:
                    handler(server, self.request)
                except (OSError, EOFError):
                    pass
                finally:
                    with server.lock:
                        server.sockets.discard(self.request)

        super().__init__(("127.0.0.1", 0), Handler)
        self.port = self.server_address[1]
        self.thread = threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.02},
            daemon=True)
        self.thread.start()

    def stop(self):
        self.release.set()
        self.shutdown()
        self.server_close()
        with self.lock:
            for sock in self.sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        self.thread.join(1)


def echo_target(server, sock):
    while True:
        data = sock.recv(65536)
        if not data:
            return
        sock.sendall(data)


def http_target(server, sock):
    header, body = read_header(sock)
    server.requests.append(header)
    length = 0
    for line in header.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    if b"Expect: 100-continue" in header:
        sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
    while len(body) < length:
        body += sock.recv(min(65536, length - len(body)))
    payload = body or b"via-upstream"
    status = b"404 Not Found" if b"/missing" in header else b"200 OK"
    sock.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                 + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n"
                 + payload)


def proxy_handler(target_port, mode="forward"):
    def handle(server, sock):
        header, extra = read_header(sock)
        server.requests.append(header)
        if mode == "stall":
            server.release.wait(3)
            return
        if mode == "bad":
            sock.sendall(b"not http\r\n\r\n")
            return
        if mode == "reject":
            sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        with socket.create_connection(("127.0.0.1", target_port), 2) as target:
            if header.startswith(b"CONNECT "):
                sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if extra:
                    target.sendall(extra)
            else:
                target.sendall(header + extra)
            while True:
                readers, _, _ = select.select([sock, target], [], [], 2)
                if not readers:
                    return
                for source in readers:
                    data = source.recv(65536)
                    if not data:
                        return
                    (target if source is sock else sock).sendall(data)
    return handle


class ProxyGatewayTests(unittest.TestCase):

    def server(self, handler):
        server = LoopbackServer(handler)
        self.addCleanup(server.stop)
        return server

    def gateway(self, port, callback=None):
        gateway = ProxyGateway(port, callback)
        gateway.start()
        self.addCleanup(gateway.stop)
        return gateway

    def client(self, gateway):
        sock = socket.create_connection(("127.0.0.1", gateway.port), 2)
        self.addCleanup(sock.close)
        return sock

    def tunnel(self, gateway, target):
        sock = self.client(gateway)
        sock.sendall(f"CONNECT 127.0.0.1:{target.port} HTTP/1.1\r\n\r\n".encode())
        header, extra = read_header(sock)
        self.assertIn(b"200", header)
        self.assertEqual(extra, b"")
        return sock

    def assert_closed(self, sock):
        try:
            self.assertEqual(sock.recv(1), b"")
        except (ConnectionResetError, ConnectionAbortedError):
            pass

    def drain_workers(self, gateway):
        with gateway._lock:
            workers = list(gateway._workers)
        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())

    def test_initial_closed_and_connect_traffic_uses_upstream(self):
        target = self.server(echo_target)
        upstream = self.server(proxy_handler(target.port))
        gateway = self.gateway(upstream.port)
        self.assert_closed(self.client(gateway))
        self.assertEqual(upstream.connections, 0)
        gateway.open()
        with mock.patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:1",
                                           "HTTPS_PROXY": "http://127.0.0.1:1"}):
            sock = self.tunnel(gateway, target)
            sock.sendall(b"tunnel payload")
            self.assertEqual(sock.recv(100), b"tunnel payload")
        self.assertEqual(upstream.connections, 1)
        self.assertEqual(target.connections, 1)

    def test_http_404_does_not_latch_and_large_upload_works(self):
        failures = []
        target = self.server(http_target)
        upstream = self.server(proxy_handler(target.port))
        gateway = self.gateway(upstream.port, failures.append)
        gateway.open()
        for path, body in (("/missing", b""), ("/upload", b"x" * 200000)):
            sock = self.client(gateway)
            request = (f"POST http://127.0.0.1:{target.port}{path} HTTP/1.1\r\n"
                       f"Host: 127.0.0.1:{target.port}\r\n"
                       f"Content-Length: {len(body)}\r\n"
                       "Expect: 100-continue\r\n\r\n").encode()
            sock.sendall(request)
            header, extra = read_header(sock)
            self.assertIn(b"100 Continue", header)
            sock.sendall(body)
            response = extra + read_all(sock)
            self.assertIn(b"404" if not body else b"200", response)
            self.assertTrue(response.endswith(body or b"via-upstream"))
        self.assertEqual(failures, [])
        self.assertEqual(upstream.connections, 2)
        self.assertEqual(len(target.requests), 2)

    def test_dead_upstream_never_dials_target_and_callback_is_closed(self):
        target = self.server(echo_target)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            dead_port = reserved.getsockname()[1]
        called = threading.Event()
        failures = []
        callback_errors = []
        gateway = self.gateway(dead_port)
        gateway.HANDSHAKE_TIMEOUT = 0.3

        def failure(reason):
            failures.append((reason, threading.current_thread().name))
            try:
                self.assert_closed(self.client(gateway))
            except Exception as error:
                callback_errors.append(error)
            finally:
                called.set()

        gateway._on_failure = failure
        gateway.open()
        clients = [self.client(gateway) for _ in range(8)]
        for sock in clients:
            try:
                sock.sendall(f"CONNECT 127.0.0.1:{target.port} HTTP/1.1\r\n\r\n".encode())
            except OSError:
                pass
        self.assertTrue(called.wait(2))
        self.assertEqual(callback_errors, [])
        for sock in clients:
            self.assert_closed(sock)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0][1], "proxy-gateway-client")
        self.assertEqual(target.connections, 0)

    def test_bad_handshake_and_timeout_latch_once(self):
        for mode in ("bad", "reject", "stall"):
            with self.subTest(mode=mode):
                event = threading.Event()
                failures = []
                upstream = self.server(proxy_handler(1, mode))
                gateway = self.gateway(
                    upstream.port, lambda reason: (failures.append(reason), event.set()))
                gateway.HANDSHAKE_TIMEOUT = 0.15
                gateway.open()
                sock = self.client(gateway)
                sock.sendall(b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n")
                self.assertTrue(event.wait(2))
                self.assert_closed(sock)
                self.assert_closed(self.client(gateway))
                self.assertEqual(len(failures), 1)

    def test_close_revokes_pending_and_established_and_measures_latency(self):
        target = self.server(echo_target)
        upstream = self.server(proxy_handler(target.port))
        gateway = self.gateway(upstream.port)
        gateway.open()
        active = [self.tunnel(gateway, target) for _ in range(8)]
        pending = self.client(gateway)
        pending.sendall(b"CONNECT partial")
        started = time.perf_counter()
        gateway.close("test")
        for sock in active + [pending]:
            self.assert_closed(sock)
        elapsed = (time.perf_counter() - started) * 1000
        print(f"loopback close-to-observed-EOF: {elapsed:.3f} ms")
        self.assertLess(elapsed, 1000)
        self.assert_closed(self.client(gateway))
        gateway.open()
        sock = self.tunnel(gateway, target)
        sock.sendall(b"new epoch")
        self.assertEqual(sock.recv(20), b"new epoch")

    def test_pending_handshake_is_revoked(self):
        upstream = self.server(proxy_handler(1, "stall"))
        failures = []
        gateway = self.gateway(upstream.port, failures.append)
        gateway.open()
        sock = self.client(gateway)
        sock.sendall(b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(upstream.accepted.wait(1))
        gateway.close()
        self.assert_closed(sock)
        gateway.open()
        upstream.release.set()
        self.drain_workers(gateway)
        self.assertEqual(failures, [])

    def test_old_dial_cannot_resurrect_after_reopen(self):
        upstream = self.server(proxy_handler(1, "stall"))
        failures = []
        gateway = self.gateway(upstream.port, failures.append)
        entered = threading.Event()
        release = threading.Event()
        exited = threading.Event()
        real_socket = socket.socket

        class DelayedSocket(real_socket):

            def connect(self, address):
                if address[1] == upstream.port:
                    entered.set()
                    release.wait(2)
                    try:
                        return super().connect(address)
                    finally:
                        exited.set()
                return super().connect(address)

        gateway.open()
        with mock.patch("proxy_gateway.socket.socket", DelayedSocket):
            sock = self.client(gateway)
            sock.sendall(b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(entered.wait(1))
            gateway.close()
            self.assert_closed(sock)
            gateway.open()
            release.set()
            self.assertTrue(exited.wait(1))
            self.drain_workers(gateway)
        self.assertEqual(upstream.connections, 0)
        self.assertEqual(failures, [])

    def test_upstream_reset_latches_but_normal_tunnel_eof_does_not(self):
        for reset in (False, True):
            with self.subTest(reset=reset):
                def handler(server, sock):
                    read_header(sock)
                    sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                    server.release.wait(2)
                    if reset:
                        linger = struct.pack("hh" if sys.platform == "win32"
                                             else "ii", 1, 0)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                        sock.close()

                upstream = self.server(handler)
                failures = []
                called = threading.Event()
                gateway = self.gateway(
                    upstream.port,
                    lambda reason: (failures.append(reason), called.set()))
                gateway.open()
                sock = self.tunnel(gateway, upstream)
                upstream.release.set()
                self.assert_closed(sock)
                sock.close()
                self.drain_workers(gateway)
                self.assertEqual(len(failures), int(reset))
                if reset:
                    self.assertTrue(called.is_set())
                    self.assert_closed(self.client(gateway))

    def test_concurrent_close_open_and_requests(self):
        target = self.server(echo_target)
        upstream = self.server(proxy_handler(target.port))
        failures = []
        gateway = self.gateway(upstream.port, failures.append)
        gateway.open()
        barrier = threading.Barrier(9)

        def traffic(_index):
            barrier.wait(2)
            for _ in range(8):
                try:
                    with socket.create_connection(
                            ("127.0.0.1", gateway.port), 1) as sock:
                        sock.sendall(b"CONNECT local.invalid:443 HTTP/1.1\r\n\r\n")
                        read_header(sock)
                        sock.sendall(b"concurrent")
                        sock.recv(100)
                except (OSError, EOFError):
                    pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(traffic, index) for index in range(8)]
            barrier.wait(2)
            for _ in range(30):
                gateway.close()
                gateway.open()
            for future in futures:
                future.result(5)
        gateway.close()
        self.drain_workers(gateway)
        with gateway._lock:
            self.assertEqual(gateway._sockets, set())
        self.assertEqual(failures, [])
        gateway.open()
        sock = self.tunnel(gateway, target)
        sock.sendall(b"still usable")
        self.assertEqual(sock.recv(100), b"still usable")

    def test_limits_client_timeout_and_parallel_tunnels(self):
        target = self.server(echo_target)
        upstream = self.server(proxy_handler(target.port))
        failures = []
        gateway = self.gateway(upstream.port, failures.append)
        gateway.MAX_CONNECTIONS = 4
        gateway.MAX_HEADER = 128
        gateway.HANDSHAKE_TIMEOUT = 0.15
        gateway.open()
        oversized = self.client(gateway)
        oversized.sendall(b"X" * 129)
        self.assert_closed(oversized)
        idle = self.client(gateway)
        self.assert_closed(idle)
        active = [self.tunnel(gateway, target) for _ in range(4)]
        self.assert_closed(self.client(gateway))
        gateway.close()
        for sock in active:
            self.assert_closed(sock)
        gateway.MAX_CONNECTIONS = 64
        gateway.HANDSHAKE_TIMEOUT = 2
        gateway.open()

        def exchange(index):
            sock = self.tunnel(gateway, target)
            payload = f"parallel-{index}".encode()
            try:
                sock.sendall(payload)
                self.assertEqual(sock.recv(100), payload)
            finally:
                sock.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(exchange, range(24)))
        self.assertEqual(failures, [])
        gateway.stop()
        self.assertEqual(gateway.port, 0)


if __name__ == "__main__":
    unittest.main()
