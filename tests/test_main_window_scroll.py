"""Regression checks for scrolling without changes to content width."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import QPoint, QPointF, QRect, Qt
from PySide6.QtGui import QFont, QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFrame

import claude_tool


class MainWindowScrollTests(unittest.TestCase):
    """Exercise the real window in preview mode without system changes."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or claude_tool._create_application()

    def setUp(self):
        # Let native combo animations from earlier tests finish before cleanup.
        QTest.qWait(500)
        popup = self.app.activePopupWidget()
        if popup is not None:
            popup.close()
            self.app.processEvents()
        self.assertIsNone(self.app.activePopupWidget())
        with patch("claude_tool.risk_check.load_settings", return_value={}), patch(
                "claude_tool.read_proxy_server", return_value=""):
            self.window = claude_tool.MainWindow()
        self.window.setStyleSheet(claude_tool.QSS)
        self.window.setFont(QFont("Microsoft YaHei UI"))
        screen_patch = patch.object(self.window, "screen", return_value=Mock(
            availableGeometry=Mock(return_value=QRect(0, 0, 1280, 800))))
        screen_patch.start()
        self.addCleanup(screen_patch.stop)
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=claude_tool.USA_TZ)
        self.controller = claude_tool.Controller(
            self.window, preview=True, service=service)
        self.controller.timer.stop()
        self.window.resize(700, 800)
        self.window.show()
        self._settle()
        self.addCleanup(self._close)

    def _close(self):
        self.window.exit_allowed = True
        self.window.close()
        self.controller.deleteLater()
        self.window.deleteLater()

    def _settle(self):
        for _ in range(5):
            self.app.processEvents()

    def _widths(self):
        window = self.window
        return tuple(widget.width() for widget in (
            window, window.scroll.viewport(), window.root, window.claude_card,
            window.china_card, window.usa_card, window.risk_card))

    def _expand(self):
        self.window.set_risk_items([
            {"name": name, "status": "pass", "detail": "Preview check passed."}
            for name in claude_tool.risk_check.ITEM_NAMES
        ])
        self.window.settings_card.show()
        self.window.risk_card.set_expanded(True)
        self.window.fit_height()
        self._settle()

    def _wheel(self, delta):
        viewport = self.window.scroll.viewport()
        position = viewport.rect().center()
        event = QWheelEvent(
            QPointF(position), QPointF(viewport.mapToGlobal(position)),
            QPoint(), QPoint(0, delta), Qt.NoButton, Qt.NoModifier,
            Qt.NoScrollPhase, False)
        self.app.sendEvent(viewport, event)
        self._settle()

    def test_widths_stay_constant_when_content_overflows_and_collapses(self):
        bar = self.window.scroll.verticalScrollBar()
        for width in (640, 700, 900):
            with self.subTest(width=width):
                self.window.resize(width, 800)
                self._settle()
                self.assertEqual(bar.maximum(), 0)
                widths = self._widths()
                self._expand()
                self.assertGreater(bar.maximum(), 0)
                self.assertFalse(bar.isVisible())
                self.assertEqual(self._widths(), widths)
                self.window.settings_card.hide()
                self.window.risk_card.set_expanded(False)
                self.window.fit_height()
                self._settle()
                self.assertEqual(bar.maximum(), 0)
                self.assertFalse(bar.isVisible())
                self.assertEqual(self._widths(), widths)

    def test_wheel_reaches_bottom_and_returns_to_top_with_hidden_bar(self):
        self._expand()
        bar = self.window.scroll.verticalScrollBar()
        self.assertGreater(bar.maximum(), 0)
        widths = self._widths()
        self._wheel(-120)
        self.assertGreater(bar.value(), 0)
        for _ in range(bar.maximum() // max(bar.singleStep(), 1) + 1):
            self._wheel(-120)
            if bar.value() == bar.maximum():
                break
        self.assertEqual(bar.value(), bar.maximum())
        bottom = self.window.root.mapTo(
            self.window.scroll.viewport(), self.window.root.rect().bottomLeft())
        self.assertEqual(bottom.y(), self.window.scroll.viewport().height() - 1)
        self.assertFalse(bar.isVisible())
        self.assertEqual(self._widths(), widths)
        self._wheel(120)
        self.assertLess(bar.value(), bar.maximum())
        for _ in range(bar.maximum() // max(bar.singleStep(), 1) + 1):
            self._wheel(120)
            if bar.value() == 0:
                break
        self.assertEqual(bar.value(), 0)

    def test_visible_window_grows_and_shrinks_with_details(self):
        self.window.settings_card.hide()
        self.window.risk_card.set_expanded(False)
        self.window.hide_status()
        self.window.fit_height()
        self._settle()
        compact_height = self.window.height()
        self._expand()
        self.assertGreater(self.window.height(), compact_height)
        self.assertLessEqual(self.window.height(), 720)
        self.window.settings_card.hide()
        self.window.risk_card.set_expanded(False)
        self.window.fit_height()
        self._settle()
        self.assertLessEqual(self.window.height(), compact_height + 4)
        footer = self.window.findChild(QFrame, "Footer")
        risk_bottom = self.window.risk_card.mapTo(
            self.window.centralWidget(),
            self.window.risk_card.rect().bottomLeft(),
        ).y()
        bottom_gap = footer.y() - risk_bottom - 1
        self.assertLessEqual(bottom_gap, 24)

    def test_collapsing_and_clearing_cards_never_leaves_stale_bottom_whitespace(self):
        footer = self.window.findChild(QFrame, "Footer")

        def bottom_gap():
            risk_bottom = self.window.risk_card.mapTo(
                self.window.centralWidget(),
                self.window.risk_card.rect().bottomLeft(),
            ).y()
            return footer.y() - risk_bottom - 1

        # 1. Expand 9 risk items -> collapse & clear (China switch) -> re-expand empty RiskCard
        self.window.set_risk_items([
            {"name": name, "status": "risk", "detail": "检测到风险详情说明"}
            for name in claude_tool.risk_check.ITEM_NAMES
        ])
        self._settle()
        self.window.risk_card.set_expanded(False)
        self.window.clear_risk()
        self.window.set_status("已切回中国模式", "系统时区与 Edge 网页语言配置已切换。", False, tone="china")
        self._settle()
        self.window.risk_card.set_expanded(True)
        self._settle()
        self.assertLessEqual(bottom_gap(), 24)

        # 2. Expand 9 risk items -> clear_risk while still expanded
        self.window.set_risk_items([
            {"name": name, "status": "risk", "detail": "检测到风险详情说明"}
            for name in claude_tool.risk_check.ITEM_NAMES
        ])
        self._settle()
        self.window.clear_risk()
        self._settle()
        self.assertLessEqual(bottom_gap(), 24)

        # 3. Long wrapped status -> hide_status -> short status
        self.window.risk_card.set_expanded(False)
        self._settle()
        self.window.set_status("错误", "很长的异常描述信息。" * 30, True)
        self._settle()
        self.window.hide_status()
        self._settle()
        self.assertLessEqual(bottom_gap(), 24)
        self.window.set_status("正常", "短提示", False)
        self._settle()
        self.assertLessEqual(bottom_gap(), 24)

    def test_topbar_and_footer_stay_pinned_when_content_scrolls(self):
        self._expand()
        bar = self.window.scroll.verticalScrollBar()
        self.assertGreater(bar.maximum(), 0)
        self._wheel(-120)
        self.assertGreater(bar.value(), 0)
        shell_rect = self.window.centralWidget().rect()
        self.assertTrue(shell_rect.contains(self.window.top_frame.geometry()))
        self.assertTrue(shell_rect.contains(self.window.footer.geometry()))
        self.assertEqual(
            self.window.footer.geometry().bottom(), shell_rect.bottom())


if __name__ == "__main__":
    unittest.main()
