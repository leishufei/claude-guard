"""Verify protection order and failure delivery without changing system policy."""

import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import protected_session


class ProtectedSessionTests(unittest.TestCase):

    def setUp(self):
        for name in ("ProxyGateway", "RuntimeGuard"):
            patcher = patch.object(protected_session, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        self.session = protected_session.ProtectedSession(Mock(), 7890, Mock())

    def test_policy_is_installed_before_business_opens(self):
        events = []
        self.session.gateway.start.return_value = 12345
        self.session.gateway.open.side_effect = lambda: events.append("open")
        self.session.guard.start.side_effect = lambda: events.append("guard")
        with patch.object(protected_session.network_isolation,
                          "ensure_proxy_isolation",
                          side_effect=lambda *args: events.append("policy")):
            self.assertEqual(self.session.start(["claude.exe"]), 12345)
        self.assertEqual(events, ["policy", "guard", "open"])

    def test_initial_guard_failure_never_opens_gateway(self):
        self.session.guard.wait_ready.return_value = False
        with patch.object(protected_session.network_isolation,
                          "ensure_proxy_isolation"), patch.object(
                              protected_session.network_isolation,
                              "revoke_proxy_access"):
            with self.assertRaises(RuntimeError):
                self.session.start(["claude.exe"])
        self.session.gateway.open.assert_not_called()

    def test_retired_session_cannot_kill_or_notify_new_session(self):
        with patch.object(protected_session.network_isolation,
                          "revoke_proxy_access"), patch(
                              "claude_desktop.cut_off_claude_traffic") as cutoff:
            self.session.stop()
            self.session.fail("stale callback")
        cutoff.assert_not_called()
        self.session.on_failure.assert_not_called()

    def test_failure_closes_gate_before_kill_and_ui_notification(self):
        events = []
        self.session.gateway.close.side_effect = lambda reason: events.append("gate")
        self.session.on_failure.side_effect = lambda *args: events.append("ui")
        with patch("claude_desktop.cut_off_claude_traffic",
                   side_effect=lambda reason: events.append("kill")) as cutoff:
            threads = [threading.Thread(target=self.session.fail, args=("bad IP",))
                       for _ in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)
            cutoff.assert_called_once_with("bad IP")
        self.assertEqual(events, ["gate", "kill", "ui"])
        self.assertTrue(self.session.failed.is_set())

    def test_cutoff_failure_stays_latched_and_is_reported(self):
        failure = RuntimeError("policy unavailable")
        with patch("claude_desktop.cut_off_claude_traffic", side_effect=failure):
            self.session.fail("bad IP")
            self.session.fail("duplicate")
        self.session.on_failure.assert_called_once_with("bad IP", failure)
        self.assertTrue(self.session.failed.is_set())

    def test_gateway_error_does_not_skip_killing_processes(self):
        failure = RuntimeError("gateway close failed")
        self.session.gateway.close.side_effect = failure
        with patch("claude_desktop.cut_off_claude_traffic") as cutoff:
            self.session.fail("bad IP")
        cutoff.assert_called_once_with("bad IP")
        self.session.on_failure.assert_called_once_with("bad IP", failure)

    def test_policy_error_does_not_open_gateway(self):
        with patch.object(protected_session.network_isolation,
                          "ensure_proxy_isolation", side_effect=RuntimeError), \
                patch.object(protected_session.network_isolation,
                             "revoke_proxy_access"):
            with self.assertRaises(RuntimeError):
                self.session.start(["claude.exe"])
        self.session.gateway.open.assert_not_called()
        self.session.guard.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
