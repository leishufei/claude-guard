"""Own the gateway, native policy and background monitor for one launch."""

import threading

from proxy_gateway import ProxyGateway
from runtime_guard import RuntimeGuard
import network_isolation


_lock = threading.RLock()
_session = None


class ProtectedSession:
    """Keep protection independent of Qt event delivery and busy states."""

    def __init__(self, monitor, upstream_port, on_failure):
        self.monitor = monitor
        self.on_failure = on_failure
        self.failed = threading.Event()
        self._failure_lock = threading.Lock()
        self._retired = False
        self._ready = False
        self.gateway = ProxyGateway(upstream_port, on_failure=self.fail)
        self.guard = RuntimeGuard(
            monitor,
            self.fail,
            local_interval=.1,
            remote_interval=2.5,
            remote_timeout=7.0,
            remote_failure_threshold=3,
        )

    def start(self, binaries):
        """Install policy before allowing workload traffic."""
        port = self.gateway.start()
        try:
            network_isolation.ensure_proxy_isolation(binaries, port)
            self.guard.start()
            if not self.guard.wait_ready(10.0):
                raise RuntimeError("首次独立守护复核未通过，已拒绝开放网关。")
            with self._failure_lock:
                if self.failed.is_set() or self._retired:
                    raise RuntimeError("保护会话已失效，已拒绝开放网关。")
                self.gateway.open()
                self._ready = True
        except Exception:
            self.stop()
            raise
        return port

    def fail(self, reason):
        """Close data paths and kill immediately, before notifying the UI."""
        with self._failure_lock:
            if self.failed.is_set() or self._retired:
                return
            self.failed.set()
            self._dispatch_failure(reason)

    def _dispatch_failure(self, reason):
        """Finish a failure before a replacement session may be installed."""
        error = None
        try:
            self.gateway.close(reason)
        except Exception as failure:
            error = failure
        try:
            import claude_desktop
            claude_desktop.cut_off_claude_traffic(reason)
        except Exception as failure:
            error = failure
        finally:
            self.on_failure(reason, error)

    def stop(self):
        """Retire the session without authorizing any subsequent launch."""
        with self._failure_lock:
            self._retired = True
            self._ready = False
        self._stop_resources()

    def _stop_resources(self):
        try:
            self.gateway.close("保护会话已停止")
        finally:
            self.guard.stop()
            try:
                self.gateway.stop()
            finally:
                pool = getattr(self.monitor, "_session_pool", None)
                if type(pool).__name__ == "ProxyConnectionPool":
                    pool.close_all()
                network_isolation.revoke_proxy_access()


def start(monitor, upstream_port, binaries, on_failure):
    """Replace an old session only during an explicit safe launch."""
    global _session
    stop()
    session = ProtectedSession(monitor, upstream_port, on_failure)
    with _lock:
        _session = session
    try:
        session.start(binaries)
    except Exception:
        with _lock:
            if _session is session:
                _session = None
        raise
    return session


def active_port():
    with _lock:
        if (_session is None or _session.failed.is_set()
                or not _session._ready or _session._retired):
            raise RuntimeError("受控代理网关未就绪，已拒绝启动。")
        return _session.gateway.port


def close_gate(reason=""):
    with _lock:
        session = _session
    if session is not None:
        session.gateway.close(reason)


def stop():
    global _session
    with _lock:
        session, _session = _session, None
    if session is not None:
        session.stop()
