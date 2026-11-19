"""Mock guard dispatch regressions; timings do not measure network blocking."""

import sys
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import claude_tool


class GuardDispatchTests(unittest.TestCase):
    """Exercise real Controller methods without starting UI or system tasks."""

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.controller = SimpleNamespace(
            busy=False, preview=False, cutoff_triggered=False,
            _cutoff_lock=threading.Lock(), _launch_task=None,
            window=Mock(), read_state=Mock(), emergency_cutoff=Mock(),
            background_failure=Mock(), _on_background_cutoff=Mock(),
            state_changed=Mock(), workflow=Mock(), service=Mock(), proxy=Mock(),
            _on_progress=Mock(), _on_safe_launch_risk_ready=Mock(),
            _on_safe_launch_done=Mock(), _on_safe_launch_failed=Mock())
        for name in ("_on_ip_guard_result", "_trigger_emergency_cutoff",
                     "safe_launch_claude"):
            setattr(self.controller, name, MethodType(
                getattr(claude_tool.Controller, name), self.controller))
        desktop = claude_tool.claude_desktop
        self.cutoff = stack.enter_context(patch.object(
            desktop, "cut_off_claude_traffic", return_value=0))
        self.blocked = stack.enter_context(patch.object(
            desktop, "is_traffic_blocked", return_value=True))
        self.processes = stack.enter_context(patch.object(
            desktop, "list_claude_processes", return_value=[]))
        stack.enter_context(patch.object(
            desktop, "_run_system", side_effect=AssertionError(
                "System commands must not run in guard dispatch tests")))

    def test_ip_worker_exception_is_reported_as_failure(self):
        for error in (TimeoutError("timeout"), RuntimeError("probe failed")):
            with self.subTest(error=type(error).__name__):
                task = SimpleNamespace(
                    monitor=Mock(), result_ready=Mock())
                task.monitor.check_remote_ip.side_effect = error
                claude_tool.IpMonitorTask.run(task)
                task.result_ready.emit.assert_called_once_with(False, str(error))

    def test_destroyed_qt_launch_worker_cannot_skip_cutoff(self):
        import shiboken6
        task = claude_tool.SafeLaunchTask(Mock(), Mock(), Mock())
        shiboken6.delete(task)
        self.controller._launch_task = task
        self.controller._on_ip_guard_result(False, "bad IP")
        self.cutoff.assert_called_once_with("bad IP")
        self.assertIsNone(self.controller._launch_task)

    def test_success_does_not_trigger_or_rearm_protection(self):
        self.controller.cutoff_triggered = True
        self.controller._on_ip_guard_result(True, "ok")
        self.cutoff.assert_not_called()
        self.assertTrue(self.controller.cutoff_triggered)

    def test_failure_is_protected_while_busy_and_without_processes(self):
        self.controller.busy = True
        self.controller._on_ip_guard_result(False, "unexpected IP")
        self.cutoff.assert_called_once_with("unexpected IP")
        self.assertTrue(self.controller.cutoff_triggered)

    def test_latch_precedes_all_blocking_calls_and_launch_interruption(self):
        events = []

        def observe(name, result):
            def callback(*args, **kwargs):
                self.assertTrue(self.controller.cutoff_triggered, name)
                events.append(name)
                return result
            return callback

        self.controller._launch_task = Mock()
        self.controller._launch_task.requestInterruption.side_effect = observe(
            "interrupt", None)
        self.cutoff.side_effect = observe("cutoff", 0)
        self.blocked.side_effect = observe("firewall_status", True)
        self.processes.side_effect = observe("process_status", [])
        self.controller._on_ip_guard_result(False, "environment changed")
        self.assertEqual(events, [
            "interrupt", "cutoff", "firewall_status", "process_status"])

    def test_repeated_and_reentrant_failures_dispatch_once(self):
        self.cutoff.side_effect = lambda reason: (
            self.controller._on_ip_guard_result(False, "reentrant"))
        for _ in range(100):
            self.controller._on_ip_guard_result(False, "repeated")
        self.cutoff.assert_called_once_with("repeated")

    def test_concurrent_duplicates_do_not_repeat_blocked_cutoff(self):
        entered = threading.Event()
        release = threading.Event()
        errors = []

        def block_cutoff(reason):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("Test did not release mock cutoff")

        def receive_failure():
            try:
                self.controller._on_ip_guard_result(False, "concurrent")
            except Exception as error:
                errors.append(error)

        self.cutoff.side_effect = block_cutoff
        first = threading.Thread(target=receive_failure, daemon=True)
        duplicates = [threading.Thread(target=receive_failure, daemon=True)
                      for _ in range(16)]
        first.start()
        try:
            self.assertTrue(entered.wait(2))
            for thread in duplicates:
                thread.start()
            for thread in duplicates:
                thread.join(2)
                self.assertFalse(thread.is_alive())
            self.assertTrue(first.is_alive())
            self.cutoff.assert_called_once_with("concurrent")
        finally:
            release.set()
            first.join(2)
            for thread in duplicates:
                if thread.ident is not None:
                    thread.join(2)
        self.assertFalse(first.is_alive())
        self.assertEqual(errors, [])

    def test_cutoff_exception_keeps_latch_and_prevents_repeat(self):
        self.cutoff.side_effect = RuntimeError("mock cutoff failed")
        with self.assertRaisesRegex(RuntimeError, "mock cutoff failed"):
            self.controller._on_ip_guard_result(False, "bad IP")
        self.assertTrue(self.controller.cutoff_triggered)
        self.controller._on_ip_guard_result(False, "duplicate")
        self.cutoff.assert_called_once_with("bad IP")

    def test_explicit_safe_launch_rearms_protection(self):
        self.controller._on_ip_guard_result(False, "first failure")
        with patch.object(claude_tool, "SafeLaunchTask") as task_class:
            self.controller.safe_launch_claude()
        self.assertFalse(self.controller.cutoff_triggered)
        task_class.return_value.start.assert_called_once_with()
        self.controller._on_ip_guard_result(False, "new failure")
        self.assertEqual(self.cutoff.call_count, 2)
        task_class.return_value.requestInterruption.assert_called_once_with()

    def test_mock_failure_to_cutoff_dispatch_is_under_100ms(self):
        samples = []
        started = 0

        def record_dispatch(reason):
            samples.append((time.perf_counter_ns() - started) / 1_000_000)

        self.cutoff.side_effect = record_dispatch
        for _ in range(1000):
            # Each sample represents a fresh, armed controller session.
            self.controller.cutoff_triggered = False
            started = time.perf_counter_ns()
            self.controller._on_ip_guard_result(False, "mock anomaly")
        self.assertEqual(len(samples), 1000)
        self.assertLess(max(samples), 100.0,
                        "Mock Python dispatch only; not network cutoff latency")
        samples.sort()
        print("\nMock dispatch only (ms): "
              f"n={len(samples)}, p50={samples[500]:.4f}, "
              f"p99={samples[990]:.4f}, max={samples[-1]:.4f}")


if __name__ == "__main__":
    unittest.main()
