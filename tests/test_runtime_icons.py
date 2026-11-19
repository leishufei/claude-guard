"""Regression checks for runtime application identity and icon loading."""

import ctypes
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QSystemTrayIcon

import claude_tool


class RuntimeIconTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_resource_location_in_source_and_frozen_modes(self):
        source = Path(claude_tool.__file__).read_text(encoding="utf-8")
        for frozen in (False, True):
            with self.subTest(frozen=frozen):
                module_file = (Path("C:/bundle/_MEI123/claude_tool.py")
                               if frozen else Path(claude_tool.__file__))
                namespace = {"__file__": str(module_file),
                             "__name__": "runtime_icon_probe"}
                with (
                    patch.object(sys, "frozen", frozen, create=True),
                    patch.object(sys, "_MEIPASS", str(module_file.parent),
                                 create=True),
                    patch.object(sys, "executable", "C:/elsewhere/app.exe"),
                ):
                    exec(compile(source, str(module_file), "exec"), namespace)
                expected_icon = (
                    module_file.parent / "App.ico"
                    if frozen
                    else module_file.resolve().parent.parent / "assets" / "App.ico"
                )
                self.assertEqual(namespace["ICON_PATH"], expected_icon)

    def test_application_identity_is_set_before_qt_and_default_icon(self):
        events = []
        set_app_id = Mock(side_effect=lambda value: events.append(value) or 0)
        shell = Mock(SetCurrentProcessExplicitAppUserModelID=set_app_id)
        app = Mock()
        with (
            patch.object(sys, "platform", "win32"),
            patch.object(ctypes, "windll", Mock(shell32=shell), create=True),
            patch.object(claude_tool, "QApplication",
                         side_effect=lambda argv: events.append("qt") or app),
            patch.object(claude_tool, "GuardStyle"),
        ):
            self.assertIs(claude_tool._create_application(), app)
        self.assertEqual(events, [claude_tool.APP_USER_MODEL_ID, "qt"])
        self.assertEqual(set_app_id.argtypes, [ctypes.wintypes.LPCWSTR])
        self.assertIs(set_app_id.restype, ctypes.c_long)
        icon = app.setWindowIcon.call_args.args[0]
        self._assert_resource_pixels(icon)

    def test_identity_failure_does_not_create_qt_windows(self):
        shell = Mock()
        shell.SetCurrentProcessExplicitAppUserModelID.return_value = -2147024809
        with (
            patch.object(sys, "platform", "win32"),
            patch.object(ctypes, "windll", Mock(shell32=shell), create=True),
            patch.object(claude_tool, "QApplication") as create_app,
        ):
            with self.assertRaises(OSError):
                claude_tool._create_application()
        create_app.assert_not_called()

    def _assert_resource_pixels(self, icon):
        expected = QIcon(str(claude_tool.ICON_PATH))
        self.assertFalse(icon.isNull())
        self.assertEqual(len(expected.availableSizes()), 9)
        self.assertEqual(icon.availableSizes(), expected.availableSizes())
        for size in expected.availableSizes():
            with self.subTest(size=size):
                actual_image = icon.pixmap(size).toImage()
                self.assertFalse(actual_image.isNull())
                self.assertEqual(actual_image, expected.pixmap(size).toImage())

    def test_window_and_tray_icons_ignore_working_directory(self):
        previous_directory = Path.cwd()
        self.addCleanup(os.chdir, previous_directory)
        os.chdir(Path(sys.executable).parent)
        window = claude_tool.MainWindow()
        self.addCleanup(window.deleteLater)
        controller = Mock(is_busy=False, tray_status_text="Claude Guard")
        with patch.object(QSystemTrayIcon, "show"):
            host = claude_tool.TrayHost(window, controller)
        self.addCleanup(host.deleteLater)
        self.addCleanup(host.menu.deleteLater)
        self.addCleanup(host.tray.deleteLater)
        self._assert_resource_pixels(window.windowIcon())
        self._assert_resource_pixels(host.tray.icon())


if __name__ == "__main__":
    unittest.main()
