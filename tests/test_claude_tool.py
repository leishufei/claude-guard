import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

import claude_tool
import risk_check
from region_core import CHINA_TZ, USA_TZ, RegionState


class FakeRegionService:
    def __init__(self, timezone_id=USA_TZ):
        self.timezone_id = timezone_id

    def read(self):
        lang = "zh-CN,zh" if self.timezone_id == CHINA_TZ else "en-US,en"
        return RegionState(
            timezone_id=self.timezone_id,
            languages=lang,
            machine_languages=lang,
            browser_languages=lang,
            browser_profile="Default",
            browser_is_running=False,
        )


class SafeLaunchUiTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _sample_report(self, ip="93.184.216.34"):
        items = [
            {"name": name, "status": "pass", "detail": ip if i == 1 else "正常"}
            for i, name in enumerate(risk_check.ITEM_NAMES)
        ]
        return risk_check.build_report(items)

    def _cleanup_window(self, window):
        """Close and delete a test MainWindow while draining any active popups."""
        window.exit_allowed = True
        window.close()
        window.deleteLater()
        self.app.processEvents()
        while (popup := self.app.activePopupWidget()) is not None:
            popup.close()
            self.app.processEvents()

    def test_running_state_and_busy_state_both_gate_launch(self):
        window = claude_tool.MainWindow()
        self.addCleanup(window.deleteLater)
        card = window.claude_card

        card.update_claude_state(True, 4, False, False, "守护中")
        self.assertEqual(window.launch_button.text(), "Claude 已运行")
        self.assertFalse(window.launch_button.isEnabled())
        window.set_apply_enabled(False)
        card.update_claude_state(False, 0, True, False, "操作中")
        self.assertEqual(window.launch_button.text(), "安全启动 Claude")
        self.assertFalse(window.launch_button.isEnabled())
        self.assertFalse(window.kill_button.isEnabled())
        self.assertFalse(window.apply_button.isEnabled())
        window.set_apply_enabled(True)
        self.assertTrue(window.launch_button.isEnabled())

        window.set_apply_enabled(False)
        card.update_claude_state(True, 3, False, False, "守护中")
        self.assertFalse(window.launch_button.isEnabled())
        window.set_apply_enabled(True)
        self.assertFalse(window.launch_button.isEnabled())
        self.assertTrue(window.kill_button.isEnabled())
        self.assertTrue(window.apply_button.isEnabled())

    def _profile_switch_window(self, timezone_id=USA_TZ):
        window = claude_tool.MainWindow()
        self.addCleanup(self._cleanup_window, window)
        with patch("claude_desktop.inspect_claude_runtime", return_value={
                "processes": [], "service_running": False,
                "firewall_blocked": False}):
            controller = claude_tool.Controller(
                window, preview=True, service=FakeRegionService(timezone_id))
        controller.timer.stop()
        self.addCleanup(controller.deleteLater)
        controller.preview = False
        self.addCleanup(setattr, controller, "preview", True)
        self.addCleanup(setattr, controller, "busy", False)
        controller.read_state()
        window.show()
        window.activateWindow()
        self.app.processEvents()
        return window, controller

    def test_profile_mouse_and_keyboard_request_correct_controller_mode(self):
        for current_tz, target_mode in ((USA_TZ, "china"), (CHINA_TZ, "usa")):
            window, controller = self._profile_switch_window(current_tz)
            inactive_card = (window.china_card if target_mode == "china"
                             else window.usa_card)
            active_card = (window.usa_card if target_mode == "china"
                           else window.china_card)
            self.assertEqual(active_card.cursor().shape(), Qt.ArrowCursor)
            self.assertEqual(inactive_card.cursor().shape(), Qt.PointingHandCursor)
            with patch.object(controller, "switch_mode") as switch_mode:
                for key in (None, Qt.Key_Return, Qt.Key_Space):
                    with self.subTest(tz=current_tz, target=target_mode, key=key):
                        switch_mode.reset_mock()
                        self.assertTrue(inactive_card.isEnabled())
                        if key is None:
                            QTest.mouseClick(inactive_card, Qt.LeftButton,
                                             pos=QPoint(12, 12))
                        else:
                            inactive_card.setFocus()
                            self.app.processEvents()
                            self.assertIs(self.app.focusWidget(), inactive_card)
                            QTest.keyClick(inactive_card, key)
                        switch_mode.assert_called_once_with(target_mode)

                        switch_mode.reset_mock()
                        if key is None:
                            QTest.mouseClick(active_card, Qt.LeftButton,
                                             pos=QPoint(12, 12))
                        else:
                            active_card.setFocus()
                            self.app.processEvents()
                            QTest.keyClick(active_card, key)
                        switch_mode.assert_not_called()

    def test_switch_mode_skips_active_mode_unless_forced_or_cutoff(self):
        for current_tz, current_mode, other_mode in (
                (CHINA_TZ, "china", "usa"),
                (USA_TZ, "usa", "china"),
        ):
            window, controller = self._profile_switch_window(current_tz)
            with patch.object(controller, "_apply") as apply_mock:
                controller.switch_mode(current_mode)
                apply_mock.assert_not_called()
                controller.switch_mode(current_mode, force=True)
                apply_mock.assert_called_once_with(current_mode)
                apply_mock.reset_mock()
                controller.cutoff_triggered = True
                controller.switch_mode(current_mode)
                apply_mock.assert_called_once_with(current_mode)
                apply_mock.reset_mock()
                controller.cutoff_triggered = False
                controller.switch_mode(other_mode)
                apply_mock.assert_called_once_with(other_mode)

    def test_busy_profiles_ignore_mouse_and_keyboard_until_ready(self):
        for current_tz, mode in ((USA_TZ, "china"), (CHINA_TZ, "usa")):
            window, controller = self._profile_switch_window(current_tz)
            card = window.china_card if mode == "china" else window.usa_card
            with patch.object(controller, "switch_mode") as switch_mode:
                with self.subTest(mode=mode):
                    card.setFocus()
                    self.app.processEvents()
                    self.assertIs(self.app.focusWidget(), card)
                    controller.busy = True
                    controller.read_state()
                    self.app.processEvents()
                    self.assertFalse(window.china_card.isEnabled())
                    self.assertFalse(window.usa_card.isEnabled())
                    self.assertFalse(card.hasFocus())
                    QTest.mouseClick(card, Qt.LeftButton,
                                     pos=QPoint(12, 12))
                    for key in (Qt.Key_Return, Qt.Key_Space):
                        QTest.keyClick(self.app.focusWidget() or window, key)
                    switch_mode.assert_not_called()
                    controller.busy = False
                    controller.read_state()
                    self.app.processEvents()
                    self.assertTrue(window.china_card.isEnabled())
                    self.assertTrue(window.usa_card.isEnabled())
                    QTest.mouseClick(card, Qt.LeftButton,
                                     pos=QPoint(12, 12))
                    switch_mode.assert_called_once_with(mode)
                    switch_mode.reset_mock()

    def test_cutoff_pill_preserves_reported_process_count(self):
        card = claude_tool.ClaudeControlCard()
        self.addCleanup(card.deleteLater)
        card.update_claude_state(False, 2, True, True, "正在确认进程")
        self.assertIn("2 进程", card.process_pill.text())

    def test_report_time_tracks_completed_results_and_risk_expands(self):
        card = claude_tool.RiskCard()
        self.addCleanup(card.deleteLater)
        self.assertFalse(card._expanded)
        self.assertEqual(card.checked_label.text(), "最近检测：尚未检测")
        completed = datetime(2026, 11, 15, 10, 20, 30, tzinfo=timezone.utc)
        with patch("claude_tool.datetime") as mock_datetime:
            mock_datetime.now.return_value = completed
            card.set_items(self._sample_report()["items"])
        expected = completed.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(card.checked_label.text(), "最近检测：" + expected)
        self.assertFalse(card._expanded)
        card.set_checking()
        self.assertIn("上次报告（非本次结果）：" + expected,
                      card.checked_label.text())
        report = self._sample_report()
        report["items"][0]["status"] = "risk"
        card.set_items(report["items"])
        self.assertTrue(card._expanded)
        card.reset()
        self.assertEqual(card.checked_label.text(), "最近检测：尚未检测")

    def test_narrow_and_wide_layouts_keep_details_within_viewport(self):
        window = claude_tool.MainWindow()
        self.addCleanup(self._cleanup_window, window)
        window.setStyleSheet(claude_tool.QSS)
        window.show()
        report = self._sample_report()
        report["items"][0]["status"] = "risk"
        report["items"][0]["detail"] = "出口环境与预期不一致，请检查目标节点后重新检测。" * 6
        for expanded in (False, True):
            if expanded:
                window.settings_card.setVisible(True)
                window.set_risk_items(report)
                window.claude_card.set_processes_expanded(True)
                window.set_status("操作失败", "请检查配置并重试：" * 25, True)
            for width in (640, 660, 900):
                with self.subTest(expanded=expanded, width=width):
                    window.resize(width, 800)
                    self.app.processEvents()
                    self.assertLessEqual(
                        window.root.width(), window.scroll.viewport().width())
                    for widget in window.root.findChildren(QLabel):
                        if not widget.isVisibleTo(window.root):
                            continue
                        left = widget.mapTo(window.root, QPoint(0, 0)).x()
                        self.assertGreaterEqual(left, 0)
                        self.assertLessEqual(left + widget.width(), window.root.width())
                    if expanded:
                        self.assertIs(window.status_panel.parent(), window.claude_card)
                        self.assertGreaterEqual(
                            window.status_detail.height(),
                            window.status_detail.heightForWidth(
                                window.status_detail.width()))

    def test_set_risk_items_accepts_report_dict_and_clears_checking(self):
        window = claude_tool.MainWindow()
        self.addCleanup(self._cleanup_window, window)
        window.risk_card.set_checking()
        self.assertEqual(window.risk_card.summary_pill.text(), "检测中…")

        report = self._sample_report()
        window.set_risk_items(report)
        self.assertEqual(window.risk_card.summary_pill.text(), "9/9 安全通过")
        self.assertEqual(len(window.risk_card._items), 9)

    @patch("claude_desktop.is_traffic_blocked", return_value=False)
    @patch(
        "claude_desktop.inspect_claude_runtime",
        return_value={"processes": [], "service_running": False, "firewall_blocked": False},
    )
    def test_safe_launch_callbacks_update_risk_card_from_checking(
        self, _mock_runtime, _mock_fw
    ):
        window = claude_tool.MainWindow()
        self.addCleanup(self._cleanup_window, window)
        controller = claude_tool.Controller(
            window, preview=True, service=FakeRegionService()
        )
        controller.timer.stop()
        self.addCleanup(controller.deleteLater)

        window.risk_card.set_checking()
        self.assertEqual(window.risk_card.summary_pill.text(), "检测中…")

        report = self._sample_report("8.8.8.8")
        controller._on_safe_launch_risk_ready(report)
        self.assertEqual(window.risk_card.summary_pill.text(), "9/9 安全通过")

        window.risk_card.set_checking()
        controller._on_safe_launch_done(report)
        self.assertEqual(window.risk_card.summary_pill.text(), "9/9 安全通过")
        self.assertEqual(controller.monitor.baseline_ip, "8.8.8.8")

    def test_settings_card_auto_vs_manual_and_click_open_combos(self):
        window = claude_tool.MainWindow()
        self.addCleanup(self._cleanup_window, window)
        card = window.settings_card
        card.load_values(
            {"targetNode": "NodeA", "staticIpMode": "auto", "staticIp": "8.8.8.8"},
            ["NodeA", "US-Node"],
        )

        # Requirement 1 & 2f: Only two modes, clean names
        modes = [card.mode_combo.itemData(i) for i in range(card.mode_combo.count())]
        texts = [card.mode_combo.itemText(i) for i in range(card.mode_combo.count())]
        self.assertEqual(modes, ["auto", "manual"])
        self.assertEqual(texts, ["自动识别", "手动指定 IP"])
        self.assertEqual(card.close_btn.text(), "收起")

        # Requirement 2b: Both dropdowns are display-only (not editable/selectable)
        self.assertFalse(card.node_combo.isEditable())
        self.assertFalse(card.mode_combo.isEditable())

        # Requirement 2g: auto disables manual IP input & button; manual restores IP
        self.assertFalse(card.ip_input.isEnabled())
        self.assertFalse(card.detect_ip_btn.isEnabled())

        card.mode_combo.setCurrentIndex(1)
        self.assertTrue(card.ip_input.isEnabled())
        self.assertTrue(card.detect_ip_btn.isEnabled())
        self.assertEqual(card.ip_input.text(), "8.8.8.8")

        # Requirement 2c: clicking left side of combobox triggers dropdown popup
        window.show()
        card.setVisible(True)
        self.app.processEvents()
        for combo in (card.node_combo, card.mode_combo):
            left_point = QPoint(12, combo.height() // 2)
            with patch.object(combo, "showPopup", wraps=combo.showPopup) as spy:
                QTest.mouseClick(combo, Qt.LeftButton, pos=left_point)
                self.app.processEvents()
                spy.assert_called_once()
                combo.hidePopup()
                self.app.processEvents()

        # Requirement 3 & 4: Profile labels and button dimensions
        self.assertIn("规则代理", window.china_card._base_detail)
        self.assertIn("全局 TUN 代理", window.usa_card._base_detail)
        buttons = (window.launch_button, window.kill_button, window.apply_button)
        self.assertLessEqual(max(button.width() for button in buttons)
                             - min(button.width() for button in buttons), 1)
        self.assertTrue(all(button.height() == 40 for button in buttons))

    @patch("risk_check.resolve_node_ip", return_value="")
    @patch("risk_check.save_settings")
    def test_auto_settings_do_not_resolve_proxy_entry_as_exit(self, mock_save, mock_resolve):
        window = claude_tool.MainWindow()
        self.addCleanup(self._cleanup_window, window)
        controller = claude_tool.Controller(
            window, preview=True, service=FakeRegionService()
        )
        controller.timer.stop()
        self.addCleanup(controller.deleteLater)
        window.settings_card.setVisible(True)

        controller._save_settings({
            "targetNode": "MissingNode",
            "staticIpMode": "auto",
            "staticIp": "8.8.8.8",
        })
        mock_resolve.assert_not_called()
        mock_save.assert_called_once()
        self.assertIn("保存", window.status_title.text())

    def test_opening_settings_refreshes_nodes_asynchronously_without_overwriting_edits(self):
        window, controller = self._profile_switch_window(CHINA_TZ)
        proxy = controller.proxy
        with patch.object(proxy, "list_global_nodes", return_value=["NodeA", "NodeB"]) as list_nodes, \
                patch("claude_tool.LoadNodesTask") as task_cls:
            window.settings_button.click()
            self.app.processEvents()
            self.assertTrue(window.settings_card.isVisible())
            list_nodes.assert_not_called()
            task_cls.return_value.start.assert_called_once_with()

        window.settings_card.auto_mode_btn.click()
        window.settings_card.manual_mode_btn.click()
        window.settings_card.ip_input.setText("1.2.3.4")
        controller._on_nodes_loaded(["NodeA", "NodeB"])
        self.assertEqual(window.settings_card.ip_input.text(), "1.2.3.4")
        self.assertEqual(window.settings_card.mode_combo.currentData(), "manual")
        self.assertEqual(
            [window.settings_card.node_combo.itemText(i)
             for i in range(window.settings_card.node_combo.count())],
            ["NodeA", "NodeB"],
        )


if __name__ == "__main__":
    unittest.main()
