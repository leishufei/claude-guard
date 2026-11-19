"""Regression coverage for native focus painting and keyboard activation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import (
    QApplication, QPushButton, QStyle, QStyleOptionFocusRect, QVBoxLayout,
    QWidget,
)

import claude_tool


class FocusTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_native_focus_rectangle_does_not_paint_over_button_label(self):
        style = claude_tool.GuardStyle("Fusion")
        self.addCleanup(style.deleteLater)
        button = QPushButton("Save")
        self.addCleanup(button.deleteLater)
        image = QImage(80, 30, QImage.Format_ARGB32)
        image.fill(QColor("white"))
        before = image.copy()
        option = QStyleOptionFocusRect()
        option.rect = image.rect().adjusted(4, 4, -4, -4)
        option.state = (QStyle.State_Enabled | QStyle.State_HasFocus
                        | QStyle.State_KeyboardFocusChange)
        painter = QPainter(image)
        style.drawPrimitive(QStyle.PE_FrameFocusRect, option, painter, button)
        painter.end()
        self.assertEqual(image, before)

    def test_mouse_and_tab_keep_keyboard_navigation_and_activation(self):
        host = QWidget()
        self.addCleanup(host.deleteLater)
        style = claude_tool.GuardStyle("Fusion")
        style.setParent(host)
        layout = QVBoxLayout(host)
        first = QPushButton("Refresh")
        second = QPushButton("Save")
        for button in (first, second):
            button.setStyle(style)
            layout.addWidget(button)
        host.show()
        host.activateWindow()
        self.app.processEvents()
        QTest.mouseClick(first, Qt.LeftButton)
        self.assertTrue(first.hasFocus())
        QTest.keyClick(first, Qt.Key_Tab)
        self.app.processEvents()
        self.assertTrue(second.hasFocus())
        clicked = QSignalSpy(second.clicked)
        QTest.keyClick(second, Qt.Key_Space)
        self.assertEqual(clicked.count(), 1)
        host.close()


if __name__ == "__main__":
    unittest.main()
