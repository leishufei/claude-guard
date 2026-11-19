"""Real thread scheduling tests with controlled, non-system probes."""

import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from runtime_guard import RuntimeGuard


class RuntimeGuardTests(unittest.TestCase):

    def test_first_local_success_cannot_authorize_pending_remote_probe(self):
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def remote(**kwargs):
            entered.set()
            release.wait(1)
            return True, "ok"

        guard, called, _ = self.make_guard(lambda: (True, "ok"), remote)
        guard.start()
        self.assertTrue(entered.wait(1))
        self.assertFalse(guard.wait_ready(.02))
        release.set()
        self.assertTrue(guard.wait_ready(1))
        self.assertFalse(called.is_set())

    def make_guard(self, local, remote, callback=None):
        called = threading.Event()
        failures = []

        def failed(reason):
            failures.append(reason)
            if callback:
                callback(reason)
            called.set()

        monitor = SimpleNamespace(check_local=local, check_remote_ip=remote)
        guard = RuntimeGuard(monitor, failed, .01, .01)
        self.addCleanup(guard.stop)
        return guard, called, failures

    def test_remote_failure_dispatches_while_local_probe_is_blocked(self):
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def local():
            entered.set()
            release.wait(5)
            return True, "ok"

        def remote(**kwargs):
            self.assertTrue(entered.wait(1))
            self.assertLessEqual(kwargs["deadline"] - time.monotonic(), 2)
            return False, "remote failed"

        guard, called, failures = self.make_guard(local, remote)
        guard.start()
        self.assertTrue(called.wait(1))
        self.assertTrue(guard.failed)
        self.assertEqual(failures, ["remote failed"])

    def test_simultaneous_failures_latch_before_exactly_one_callback(self):
        barrier = threading.Barrier(2)

        def fail(**_kwargs):
            barrier.wait(1)
            return False, "failed"

        snapshots = []
        guard, called, failures = self.make_guard(
            fail, fail, lambda _reason: snapshots.append(guard.failed))
        guard.start()
        self.assertTrue(called.wait(1))
        self.assertEqual(snapshots, [True])
        self.assertEqual(failures, ["failed"])

    def test_probe_exception_fails_closed(self):
        guard, called, failures = self.make_guard(
            Mock(side_effect=RuntimeError("read failed")),
            Mock(return_value=(True, "ok")))
        guard.start()
        self.assertTrue(called.wait(1))
        self.assertIn("read failed", failures[0])

    def test_local_hang_has_real_two_second_wait_bound(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def local():
            release.wait(5)
            return True, "late"

        guard, called, failures = self.make_guard(
            local, Mock(return_value=(True, "ok")))
        start = time.monotonic()
        guard.start()
        self.assertTrue(called.wait(3))
        self.assertLess(time.monotonic() - start, 3)
        self.assertIn("本地", failures[0])
        self.assertIn("超时", failures[0])

    def test_remote_hang_has_watchdog_even_if_probe_ignores_deadline(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def remote(**_kwargs):
            release.wait(5)
            return True, "late"

        guard, called, failures = self.make_guard(
            Mock(return_value=(True, "ok")), remote)
        guard.CHECK_TIMEOUT = .1
        guard.start()
        self.assertTrue(called.wait(1))
        self.assertIn("远端", failures[0])

    def test_stop_does_not_wait_for_probe_and_discards_late_failure(self):
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        self.addCleanup(release.set)

        def local():
            entered.set()
            release.wait(5)
            finished.set()
            return False, "old session"

        guard, called, failures = self.make_guard(
            local, Mock(return_value=(True, "ok")))
        guard.start()
        self.assertTrue(entered.wait(1))
        start = time.monotonic()
        guard.stop()
        self.assertLess(time.monotonic() - start, .2)
        guard.monitor.check_local = Mock(return_value=(True, "ok"))
        guard.start()
        release.set()
        self.assertTrue(finished.wait(1))
        self.assertFalse(called.wait(.1))
        self.assertEqual(failures, [])

    def test_transient_remote_failures_recover_without_cutoff_until_threshold(self):
        responses = iter([
            (True, "ok"),
            (False, "无法确认出口 IP，疑似代理断流"),
            (False, "无法确认出口 IP：远端检查超时"),
            (True, "ok"),
            (False, "无法确认出口 IP，疑似代理断流"),
            (False, "无法确认出口 IP，疑似代理断流"),
            (False, "无法确认出口 IP，疑似代理断流"),
        ])
        calls = []
        done = threading.Event()
        failures = []

        def remote(**_kwargs):
            res = next(responses)
            calls.append(res)
            return res

        monitor = SimpleNamespace(
            check_local=lambda: (True, "ok"),
            check_remote_ip=remote,
        )
        guard = RuntimeGuard(
            monitor,
            lambda reason: (failures.append(reason), done.set()),
            local_interval=.01,
            remote_interval=.01,
            remote_timeout=1.0,
            remote_failure_threshold=3,
        )
        self.addCleanup(guard.stop)
        guard.start()
        self.assertTrue(guard.wait_ready(1))
        self.assertTrue(done.wait(2))
        self.assertEqual(len(calls), 7)
        self.assertEqual(failures, ["无法确认出口 IP，疑似代理断流"])

    def test_ip_mismatch_cuts_off_immediately_even_with_transient_threshold(self):
        responses = iter([
            (True, "ok"),
            (False, "出口 IP 异常变化：当前 9.9.9.9（期望 8.8.8.8）"),
        ])
        done = threading.Event()
        failures = []
        monitor = SimpleNamespace(
            check_local=lambda: (True, "ok"),
            check_remote_ip=lambda **_kwargs: next(responses),
        )
        guard = RuntimeGuard(
            monitor,
            lambda reason: (failures.append(reason), done.set()),
            local_interval=.01,
            remote_interval=.01,
            remote_timeout=1.0,
            remote_failure_threshold=3,
        )
        self.addCleanup(guard.stop)
        guard.start()
        self.assertTrue(done.wait(1))
        self.assertIn("9.9.9.9", failures[0])


if __name__ == "__main__":
    unittest.main()
