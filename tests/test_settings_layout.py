"""Layout and interaction checks for the settings form."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

import claude_tool


class SettingsLayoutTests(unittest.TestCase):
    """Exercise the form without touching system configuration or networking."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.server_patch = patch("claude_tool.read_proxy_server", return_value="")
        self.server_patch.start()
        self.addCleanup(self.server_patch.stop)
        self.card = claude_tool.SettingsCard()
        self.card.setStyleSheet(claude_tool.QSS)
        self.addCleanup(self.card.deleteLater)
        self.addCleanup(self.card.close)

    def _show(self, width, mode="auto", node="Static proxy"):
        self.card.load_values({
            "targetNode": node,
            "staticIpMode": mode,
            "staticIp": "8.8.8.8",
        }, [node])
        self.card.resize(width, self.card.sizeHint().height())
        self.card.show()
        self.app.processEvents()

    def test_two_row_settings_remain_inside_supported_widths(self):
        long_node = "A very long fixed exit node / " * 12
        for width in (600, 640, 660, 900):
            for mode in ("auto", "manual"):
                with self.subTest(width=width, mode=mode):
                    self._show(width, mode, long_node)
                    card = self.card
                    self.assertEqual(card.width(), width)
                    self.assertTrue(card.mode_combo.isHidden())
                    self.assertTrue(card.mode_tip.isHidden())
                    first_row = (card.node_combo, card.refresh_nodes_btn,
                                 card.mode_segments)
                    second_row = (card.ip_input, card.detect_ip_btn,
                                  card.save_btn)
                    self.assertEqual(card.node_combo.x(), card.ip_input.x())
                    self.assertGreater(card.ip_input.y(),
                                       card.node_combo.geometry().bottom())
                    for row in (first_row, second_row):
                        centers = [widget.geometry().center().y()
                                   for widget in row]
                        self.assertLessEqual(max(centers) - min(centers), 2)
                    for child in card.findChildren(QLabel) + list(first_row + second_row):
                        if child.isVisibleTo(card):
                            self.assertTrue(card.rect().contains(child.geometry()))
                    self.assertLess(card.node_combo.geometry().right(),
                                    card.refresh_nodes_btn.x())
                    self.assertLess(card.ip_input.geometry().right(),
                                    card.detect_ip_btn.x())

    def test_segments_sync_with_compatible_mode_combo(self):
        self._show(640)
        card = self.card
        self.assertTrue(card.auto_mode_btn.isChecked())
        QTest.mouseClick(card.manual_mode_btn, Qt.LeftButton)
        self.assertEqual(card.mode_combo.currentData(), "manual")
        self.assertTrue(card.ip_input.isEnabled())
        self.assertTrue(card.manual_mode_btn.isChecked())
        self.assertFalse(card.auto_mode_btn.isChecked())
        QTest.mouseClick(card.manual_mode_btn, Qt.LeftButton)
        self.assertTrue(card.manual_mode_btn.isChecked())
        card.mode_combo.setCurrentIndex(0)
        self.assertTrue(card.auto_mode_btn.isChecked())
        self.assertFalse(card.manual_mode_btn.isChecked())
        self.assertFalse(card.ip_input.isEnabled())

    def test_mode_explanation_and_manual_value_survive_switches(self):
        self._show(640)
        card = self.card
        self.assertFalse(card.ip_input.isEnabled())
        self.assertFalse(card.detect_ip_btn.isEnabled())
        self.assertIn("实测代理出口", card.mode_tip.text())
        self.assertIn("绑定基准", card.mode_tip.text())
        self.assertIn("不可手动编辑", card.mode_tip.text())
        for index, mode in enumerate(("auto", "manual")):
            card.mode_combo.setCurrentIndex(index)
            self.assertEqual(card.mode_tip.toolTip(), card._MODE_TIPS[mode])
            self.assertEqual(card.mode_combo.toolTip(), card._MODE_TIPS[mode])
            self.assertEqual(card.mode_combo.itemData(index, Qt.ToolTipRole),
                             card._MODE_TIPS[mode])
            self.assertNotIn("\n", card.mode_tip.text())
            self.assertNotIn("•", card.mode_tip.text())
        card.mode_combo.setCurrentIndex(1)
        self.assertTrue(card.ip_input.isEnabled())
        self.assertTrue(card.detect_ip_btn.isEnabled())
        self.assertIn("填写", card.mode_tip.text())
        self.assertIn("固定公网 IPv4", card.mode_tip.text())
        self.assertIn("严格校验", card.mode_tip.text())
        card.ip_input.setFocus()
        card.ip_input.selectAll()
        QTest.keyClicks(card.ip_input, "9.9.9.9")
        card.mode_combo.setCurrentIndex(0)
        emitted = []
        card.saved.connect(emitted.append)
        card.save_btn.click()
        self.assertEqual(emitted[-1]["staticIp"], "9.9.9.9")
        self.assertEqual(emitted[-1]["staticIpMode"], "auto")
        card.mode_combo.setCurrentIndex(1)
        self.assertEqual(card.ip_input.text(), "9.9.9.9")
        card.save_btn.click()
        self.assertEqual(emitted[-1], {
            "targetNode": "Static proxy",
            "staticIpMode": "manual",
            "staticIp": "9.9.9.9",
        })

    def test_tab_order_skips_disabled_ip_controls_and_labels_have_buddies(self):
        self._show(660, "manual")
        card = self.card
        expected = (card.node_combo, card.refresh_nodes_btn, card.auto_mode_btn,
                    card.manual_mode_btn, card.ip_input, card.detect_ip_btn,
                    card.save_btn)
        card.activateWindow()
        card.node_combo.setFocus()
        self.app.processEvents()
        for current, following in zip(expected, expected[1:]):
            self.assertEqual(self.app.focusWidget(), current)
            QTest.keyClick(current, Qt.Key_Tab)
            self.assertEqual(self.app.focusWidget(), following)
        card.mode_combo.setCurrentIndex(0)
        card.manual_mode_btn.setFocus()
        QTest.keyClick(card.manual_mode_btn, Qt.Key_Tab)
        self.assertEqual(self.app.focusWidget(), card.save_btn)
        buddies = {label.buddy() for label in card.findChildren(QLabel)}
        for field in (card.node_combo, card.mode_combo, card.ip_input):
            self.assertIn(field, buddies)
            self.assertTrue(field.accessibleName())

    @patch("claude_tool.read_proxy_server", return_value="exit." + "long." * 40 + "net")
    def test_long_domain_stays_inside_disabled_field(self, _read_server):
        for width in (640, 660, 900):
            with self.subTest(width=width):
                self._show(width)
                self.assertEqual(self.card.width(), width)
                self.assertIn("实测出口", self.card.ip_input.placeholderText())
                self.assertFalse(self.card.ip_input.isEnabled())
                self.assertTrue(self.card.rect().contains(self.card.ip_input.geometry()))
                self.assertLess(self.card.ip_input.geometry().right(),
                                self.card.detect_ip_btn.x())


if __name__ == "__main__":
    unittest.main()
