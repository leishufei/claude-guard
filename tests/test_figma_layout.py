"""UI regression tests for Figma Make layout parity and interactive controls."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

import claude_tool
from region_core import USA_TZ


class FigmaLayoutTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or claude_tool._create_application()

    def _window(self):
        with (
            patch("claude_tool.risk_check.load_settings", return_value={
                "targetNode": "NodeA", "staticIpMode": "manual", "staticIp": "93.184.216.34",
            }),
            patch("claude_tool.read_proxy_server", return_value="93.184.216.34"),
        ):
            window = claude_tool.MainWindow()
        window.setStyleSheet(claude_tool.QSS)
        self.addCleanup(self.app.processEvents)
        self.addCleanup(window.deleteLater)
        self.addCleanup(window.close)
        window.exit_allowed = True
        return window

    def test_topbar_and_settings_proportions_match_figma(self):
        window = self._window()
        window.show()
        self.app.processEvents()
        self.assertEqual(window.width(), 700)
        self.assertFalse(hasattr(window, "width_toggle_btn"))
        self.assertFalse(hasattr(window.settings_card, "node_meta_pill"))
        self.assertFalse(hasattr(window.claude_card, "refresh_proc_btn"))
        self.assertLessEqual(window.settings_card.ip_input.width(), 230)
        self.assertIn("93.184.216.34", window.footer_endpoint.text())

    def test_settings_collapse_shows_endpoint_pill_and_updates_header_button(self):
        window = self._window()
        window.show()
        self.app.processEvents()
        self.assertFalse(window.settings_card.isVisible())
        self.assertTrue(window.endpoint_pill.isVisible())
        self.assertEqual(window.endpoint_pill.text(), "NodeA · 93.184.216.34")
        self.assertEqual(window.settings_button.objectName(), "CompactOutlineBtn")

        window.settings_button.click()
        self.app.processEvents()
        self.assertTrue(window.settings_card.isVisible())
        self.assertFalse(window.endpoint_pill.isVisible())
        self.assertEqual(window.settings_button.objectName(), "CompactActiveBtn")

        window.settings_card.close_btn.click()
        self.app.processEvents()
        self.assertFalse(window.settings_card.isVisible())
        self.assertTrue(window.endpoint_pill.isVisible())
        self.assertEqual(window.settings_button.objectName(), "CompactOutlineBtn")

    def test_mode_help_toggles_inline_guide_without_breaking_tab_order(self):
        window = self._window()
        window.show()
        window.settings_button.click()
        self.app.processEvents()
        card = window.settings_card
        self.assertTrue(card.isVisible())
        self.assertFalse(card.mode_guide_panel.isVisible())

        QTest.mouseClick(card.mode_help, Qt.LeftButton)
        self.app.processEvents()
        self.assertTrue(card.mode_guide_panel.isVisible())
        self.assertTrue(card.rect().contains(card.mode_guide_panel.geometry()))

        QTest.mouseClick(card.mode_help, Qt.LeftButton)
        self.app.processEvents()
        self.assertFalse(card.mode_guide_panel.isVisible())

    def test_cutoff_shows_quick_fix_and_drift_badge(self):
        window = self._window()
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=USA_TZ)
        controller = claude_tool.Controller(window, preview=True, service=service)
        controller.timer.stop()
        controller.preview = False
        self.addCleanup(setattr, controller, "preview", True)
        self.addCleanup(controller.deleteLater)

        with (
            patch("claude_tool.claude_desktop.cut_off_claude_traffic"),
            patch("claude_tool.claude_desktop.is_traffic_blocked", return_value=True),
            patch("claude_tool.claude_desktop.list_claude_processes", return_value=[]),
        ):
            controller._trigger_emergency_cutoff("Clash 代理模式已变更为 rule")
        window.show()
        self.app.processEvents()

        self.assertTrue(window.claude_card.quick_fix_btn.isVisibleTo(window.claude_card))
        self.assertGreater(
            window.claude_card.quick_fix_btn.y(),
            window.status_detail.geometry().bottom(),
        )
        self.assertTrue(window.usa_card.drift_badge.isVisibleTo(window.usa_card))
        self.assertTrue(window.usa_card.drift_tag.isVisibleTo(window.usa_card))
        self.assertEqual(window.usa_card.drift_tag.text(), "→ rule")
        self.assertEqual(window.usa_card.badge.text(), "当前")
        self.assertEqual(window.usa_card.lang_label.styleSheet(), "")
        self.assertIn("line-through", window.usa_card.meta.styleSheet())
        self.assertEqual(window.firewall_badge.text(), "已锁出站防漏")
        self.assertFalse(hasattr(window, "network_status"))

    def test_close_claude_clears_cutoff_and_hides_quick_fix(self):
        window = self._window()
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=USA_TZ)
        controller = claude_tool.Controller(window, preview=True, service=service)
        controller.timer.stop()
        controller.preview = False
        self.addCleanup(setattr, controller, "preview", True)
        self.addCleanup(controller.deleteLater)

        with (
            patch("claude_tool.claude_desktop.cut_off_claude_traffic"),
            patch("claude_tool.claude_desktop.is_traffic_blocked", return_value=True),
            patch("claude_tool.claude_desktop.list_claude_processes", return_value=[]),
        ):
            controller._trigger_emergency_cutoff("Clash 代理模式已变更为 rule")
        window.show()
        self.app.processEvents()
        self.assertTrue(window.claude_card.quick_fix_btn.isVisibleTo(window.claude_card))

        with (
            patch("claude_tool.claude_desktop.is_traffic_blocked", return_value=True),
            patch("claude_tool.claude_desktop.list_claude_processes", return_value=[]),
        ):
            controller._on_close_claude_done()
        self.app.processEvents()
        self.assertFalse(controller.cutoff_triggered)
        self.assertFalse(window.claude_card.quick_fix_btn.isVisibleTo(window.claude_card))
        self.assertFalse(window.usa_card.drift_badge.isVisibleTo(window.usa_card))

    def test_switching_to_china_mode_clears_risk_report(self):
        window = self._window()
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=claude_tool.CHINA_TZ)
        controller = claude_tool.Controller(window, preview=True, service=service)
        controller.timer.stop()
        controller.preview = False
        self.addCleanup(setattr, controller, "preview", True)
        self.addCleanup(controller.deleteLater)

        window.set_risk_items([
            {"name": name, "status": "pass", "detail": "OK"}
            for name in claude_tool.risk_check.ITEM_NAMES
        ])
        window.risk_card.set_expanded(True)
        self.assertEqual(window.risk_card.summary_pill.text(), "9/9 安全通过")

        with (
            patch("claude_tool.claude_desktop.is_traffic_blocked", return_value=True),
            patch("claude_tool.claude_desktop.list_claude_processes", return_value=[]),
        ):
            controller._on_apply_done("china", False)
        self.app.processEvents()
        self.assertEqual(window.risk_card.summary_pill.text(), "未检测")
        self.assertEqual(window.risk_card.checked_label.text(), "最近检测：尚未检测")
        self.assertFalse(window.risk_card.body.isVisibleTo(window.risk_card))

    def test_idle_standby_hides_status_banner_and_subtitle(self):
        window = self._window()
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=claude_tool.CHINA_TZ)
        controller = claude_tool.Controller(window, preview=True, service=service)
        controller.timer.stop()
        self.addCleanup(controller.deleteLater)
        window.show()
        self.app.processEvents()
        self.assertFalse(window.claude_card.guard_summary.isVisibleTo(window.claude_card))
        self.assertFalse(window.status_panel.isVisibleTo(window.claude_card))

    def test_bundled_figma_fonts_are_loaded(self):
        self._window()
        families = set(QFontDatabase.families())
        for family in ("Inter", "Noto Sans SC", "JetBrains Mono"):
            self.assertIn(family, families)

    def test_risk_rows_prioritize_risk_and_unknown_first_while_keeping_provenance(self):
        window = self._window()
        items = [
            {"name": "ItemPass", "status": "pass", "detail": "OK"},
            {"name": "ItemUnknown", "status": "unknown", "detail": "Pending"},
            {"name": "ItemRisk", "status": "risk", "detail": "Blocked"},
        ]
        window.set_risk_items(items)
        self.assertEqual(window.risk_card._items, items)
        rendered_names = [
            lbl.text() for lbl in window.risk_card.rows_box.findChildren(claude_tool.QLabel)
            if lbl.objectName() == "RiskName"
        ]
        self.assertEqual(rendered_names, ["ItemRisk", "ItemUnknown", "ItemPass"])

    def test_settings_dirty_state_and_action_hierarchy(self):
        window = self._window()
        window.show()
        window.settings_button.click()
        self.app.processEvents()
        card = window.settings_card
        self.assertFalse(card.unsaved_badge.isVisibleTo(card))
        self.assertEqual(card.save_btn.objectName(), "CompactOutlineBtn")

        card.ip_input.setText("1.1.1.1")
        self.app.processEvents()
        self.assertTrue(card.unsaved_badge.isVisibleTo(card))
        self.assertEqual(card.save_btn.objectName(), "CompactPrimaryBtn")

        card.mark_saved({
            "targetNode": "NodeA",
            "staticIpMode": "manual",
            "staticIp": "1.1.1.1",
        })
        self.assertFalse(card.unsaved_badge.isVisibleTo(card))
        self.assertEqual(card.save_btn.objectName(), "CompactOutlineBtn")

        self.assertEqual(window.kill_button.objectName(), "DangerIdleBtn")
        window.claude_card.update_claude_state(True, 1, False, False, "守护中")
        self.assertEqual(window.kill_button.objectName(), "DangerBtn")

    def test_initial_show_does_not_focus_topbar_buttons(self):
        window = self._window()
        window.show()
        window.activateWindow()
        self.app.processEvents()
        self.assertNotIn(
            self.app.focusWidget(),
            (window.endpoint_pill, window.settings_button),
        )


if __name__ == "__main__":
    unittest.main()
