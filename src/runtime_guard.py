"""Thread-based environment protection independent of the GUI event loop."""

import queue
import threading
import time


def _is_transient_remote_failure(reason):
    text = str(reason or "")
    if "异常变化" in text or "基准" in text:
        return False
    return "超时" in text or text.startswith("无法确认出口 IP")


class RuntimeGuard:
    """Run independent probes with bounded waits and one failure callback.

    Intervals are delays between completed probes, not detection guarantees.
    Blocking platform calls cannot be cancelled; their daemon workers are
    abandoned on timeout. A failed session starts no further probes.
    """

    CHECK_TIMEOUT = 2.0

    def __init__(self, monitor, on_failure, local_interval=.1,
                 remote_interval=1.0, remote_timeout=None,
                 remote_failure_threshold=1):
        if local_interval <= 0 or remote_interval <= 0:
            raise ValueError("Guard intervals must be positive")
        self.monitor = monitor
        self.on_failure = on_failure
        self.local_interval = local_interval
        self.remote_interval = remote_interval
        self.remote_timeout = remote_timeout
        self.remote_failure_threshold = max(1, int(remote_failure_threshold))
        self._lock = threading.Lock()
        self._stop = None
        self.failed = False
        self.failure_reason = ""
        self._ready = threading.Event()
        self._initial_passed = set()

    def start(self):
        """Start a new session; repeated starts of an active session do nothing."""
        with self._lock:
            if self._stop is not None and not self._stop.is_set():
                return
            stop = threading.Event()
            self._stop = stop
            self.failed = False
            self.failure_reason = ""
            self._ready.clear()
            self._initial_passed.clear()
        for remote, interval in ((False, self.local_interval),
                                 (True, self.remote_interval)):
            threading.Thread(target=self._watch, args=(stop, remote, interval),
                             daemon=True).start()

    def stop(self):
        """Invalidate this session without waiting on blocking platform calls."""
        with self._lock:
            if self._stop is not None:
                self._stop.set()
            self._ready.set()

    def wait_ready(self, timeout):
        """Wait until both first probes succeed in the current session."""
        self._ready.wait(timeout)
        with self._lock:
            return (self._stop is not None and not self._stop.is_set()
                    and not self.failed and len(self._initial_passed) == 2)

    def _fail(self, stop, reason):
        with self._lock:
            if self._stop is not stop or stop.is_set() or self.failed:
                return
            self.failed = True
            self.failure_reason = reason
            stop.set()
            self._ready.set()
        self.on_failure(reason)

    def _watch(self, stop, remote, interval):
        transient_failures = 0
        while not stop.is_set():
            result = queue.Queue(maxsize=1)
            timeout = (self.CHECK_TIMEOUT
                       if not remote or self.remote_timeout is None
                       else self.remote_timeout)
            deadline = time.monotonic() + timeout

            def probe(result=result, deadline=deadline):
                try:
                    if remote:
                        observation = self.monitor.check_remote_ip(
                            deadline=deadline)
                    else:
                        observation = self.monitor.check_local()
                    ok, reason = observation
                    result.put((ok is True, str(reason)))
                except Exception as error:
                    result.put((False, "检查异常：{}".format(error)))

            threading.Thread(target=probe, daemon=True).start()
            timed_out = False
            ok = False
            reason = ""
            while not stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    reason = "无法确认{}环境：检查超时".format(
                        "远端" if remote else "本地")
                    break
                try:
                    ok, reason = result.get(timeout=min(.05, remaining))
                    break
                except queue.Empty:
                    continue
            if stop.is_set():
                return
            if timed_out or not ok:
                with self._lock:
                    initialized = (
                        self._stop is stop and remote in self._initial_passed)
                can_retry = (
                    remote
                    and initialized
                    and self.remote_failure_threshold > 1
                    and _is_transient_remote_failure(reason)
                )
                if can_retry:
                    transient_failures += 1
                    if transient_failures < self.remote_failure_threshold:
                        if stop.wait(min(.5, interval)):
                            return
                        continue
                self._fail(stop, reason)
                return
            transient_failures = 0
            with self._lock:
                if self._stop is stop and not stop.is_set():
                    self._initial_passed.add(remote)
                    if len(self._initial_passed) == 2:
                        self._ready.set()
            if stop.wait(interval):
                return
