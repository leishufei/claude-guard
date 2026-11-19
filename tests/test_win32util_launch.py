"""Mocked checks for generic standard-user process launching."""

import subprocess
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import win32util


class ExplorerTokenLaunchTests(unittest.TestCase):

    def setUp(self):
        self.contexts = ExitStack()
        self.addCleanup(self.contexts.close)
        self.contexts.enter_context(patch("win32util.current_sid", return_value="user"))
        self.contexts.enter_context(patch("win32util.current_session_id", return_value=1))
        self.contexts.enter_context(patch("win32util.process_sid", return_value="user"))
        self.contexts.enter_context(patch("win32util.process_session_id", return_value=1))
        self.elevated = self.contexts.enter_context(patch(
            "win32util.is_process_elevated", return_value=False))
        self.contexts.enter_context(patch("win32util.enable_privilege"))
        self.duplicate = self.contexts.enter_context(patch(
            "win32util._duplicate_explorer_token", return_value=123))
        self.close = self.contexts.enter_context(patch("win32util.kernel32.CloseHandle"))
        self.create = self.contexts.enter_context(patch(
            "win32util.advapi32.CreateProcessWithTokenW", return_value=False))
        self.contexts.enter_context(patch(
            "win32util._last_error", side_effect=lambda message: OSError(5, message)))
        self.processes = self.contexts.enter_context(patch(
            "win32util.psutil.process_iter", return_value=[SimpleNamespace(
                info={"pid": 10, "name": "explorer.exe"})]))

    def test_missing_or_elevated_explorer_uses_generic_error(self):
        self.elevated.return_value = True
        with self.assertRaisesRegex(RuntimeError, "无法启动目标程序") as caught:
            win32util.start_process_with_explorer_token("claude.exe", [], "C:\\app")
        self.assertNotIn("Edge", str(caught.exception))
        self.create.assert_not_called()
        self.duplicate.assert_not_called()

    def test_create_failure_preserves_alias_arguments_and_generic_error(self):
        alias = r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\claude-desktop.exe"
        arguments = ["--proxy-server=http://127.0.0.1:18080", "--proxy-bypass-list=<-loopback>"]
        with self.assertRaises(OSError) as caught:
            win32util.start_process_with_explorer_token(alias, arguments, r"C:\app")
        self.assertIn("无法以普通权限启动目标程序", str(caught.exception))
        self.assertNotIn("Edge", str(caught.exception))
        self.assertEqual(caught.exception.errno, 5)
        self.assertEqual(self.create.call_args.args[3].value,
                         subprocess.list2cmdline([alias] + arguments))
        self.duplicate.assert_called_once_with(10)
        self.close.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
