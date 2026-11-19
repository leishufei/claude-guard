"""Tests for Edge process snapshots during concurrent monitoring."""

import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import edge_lifecycle


class BrowserProcessTests(unittest.TestCase):

    def setUp(self):
        self.browser = edge_lifecycle.WindowsBrowserLifecycle.__new__(
            edge_lifecycle.WindowsBrowserLifecycle)
        self.browser.sid = "test-user"
        self.browser.session_id = 1
        self.browser.executable = r"C:\Edge\msedge.exe"
        self.browser.checked_arguments = {}
        self.process = Mock()
        self.process.pid = 42
        self.snapshot = {
            "pid": 42,
            "name": "msedge.exe",
            "exe": self.browser.executable,
            "create_time": 123.0,
        }
        self.process.info = self.snapshot.copy()
        self.process.as_dict.return_value = self.snapshot.copy()
        self.process.cmdline.return_value = [self.browser.executable]
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(patch.object(
            edge_lifecycle.psutil, "process_iter",
            return_value=iter([self.process])))
        contexts.enter_context(patch.object(
            edge_lifecycle.win32util, "process_session_id", return_value=1))
        contexts.enter_context(patch.object(
            edge_lifecycle.win32util, "process_sid", return_value="test-user"))

    def test_concurrent_scan_replaces_info_during_identity_check(self):
        def read_sid(pid):
            self.process.info = {
                "pid": pid, "name": "msedge.exe",
                "exe": self.browser.executable,
            }
            return "test-user"

        with patch.object(edge_lifecycle.win32util, "process_sid",
                          side_effect=read_sid):
            result = self.browser.processes()

        self.assertEqual(result, [edge_lifecycle.BrowserProcessInfo(
            42, 123.0, self.browser.executable)])

    def test_concurrent_scan_replaces_info_before_iteration(self):
        self.process.info = {"pid": 42, "name": "msedge.exe"}
        with patch.object(edge_lifecycle.win32util, "process_sid",
                          return_value="test-user"):
            result = self.browser.processes()

        self.assertEqual(result, [edge_lifecycle.BrowserProcessInfo(
            42, 123.0, self.browser.executable)])

    def test_exited_process_is_skipped(self):
        self.process.as_dict.side_effect = edge_lifecycle.psutil.NoSuchProcess(42)
        self.assertEqual(self.browser.processes(), [])


if __name__ == "__main__":
    unittest.main()
