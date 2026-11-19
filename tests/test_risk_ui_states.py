"""Regression coverage for report provenance during safety checks."""

import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtWidgets import QApplication, QLabel

import claude_tool
import risk_check


class RiskUiStateTests(unittest.TestCase):

    def test_queued_old_guard_notification_cannot_interrupt_new_launch(self):
        window, controller = self._controller()
        old_generation = object()
        controller._launch_generation = old_generation
        worker = threading.Thread(target=lambda: controller.background_failure.emit(
            old_generation, "old failure", None))
        worker.start()
        worker.join(1)
        controller._launch_generation = object()
        controller._launch_task = Mock()
        self.app.processEvents()
        controller._launch_task.requestInterruption.assert_not_called()
        self.assertFalse(controller.cutoff_triggered)

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        blocked_patch = patch(
            "claude_tool.claude_desktop.is_traffic_blocked", return_value=False)
        process_patch = patch(
            "claude_tool.claude_desktop.list_claude_processes", return_value=[])
        settings_patch = patch(
            "claude_tool.risk_check.load_settings",
            return_value={"targetNode": "", "staticIpMode": "auto", "staticIp": ""})
        self.blocked = blocked_patch.start()
        self.processes = process_patch.start()
        self.settings = settings_patch.start()
        self.addCleanup(blocked_patch.stop)
        self.addCleanup(process_patch.stop)
        self.addCleanup(settings_patch.stop)
        self.card = claude_tool.RiskCard()
        self.addCleanup(self.card.deleteLater)

    def test_first_check_replaces_empty_instructions(self):
        self.card.set_checking()
        text = " ".join(label.text() for label in
                        self.card.findChildren(QLabel))
        self.assertNotIn("尚未执行检测", text)
        self.assertNotIn("最近检测：尚未检测", text)
        self.assertIn("正在执行安全检测", text)

    def test_recheck_identifies_previous_report_without_retimestamping(self):
        items = [{"name": name, "status": "pass", "detail": "OK"}
                 for name in risk_check.ITEM_NAMES]
        self.card.set_items(items)
        checked = self.card.checked_label.text().split("：", 1)[1]
        self.card.set_checking()
        self.assertIn("上次报告", self.card.checked_label.text())
        self.assertIn(checked, self.card.checked_label.text())
        self.card.set_incomplete()
        self.assertIn("非本次结果", self.card.checked_label.text())
        self.assertEqual(self.card._items, items)

    def test_preparing_and_failed_first_attempt_do_not_claim_a_result(self):
        self.card.set_preparing()
        self.assertEqual(self.card.summary_pill.text(), "准备中…")
        self.assertIn("尚未开始", " ".join(label.text() for label in
                                         self.card.findChildren(QLabel)))
        self.card.set_incomplete()
        self.assertEqual(self.card.summary_pill.text(), "检测未完成")
        self.assertNotIn("最近检测", self.card.checked_label.text())

    def _controller(self):
        window = claude_tool.MainWindow()
        self.addCleanup(window.deleteLater)
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=claude_tool.USA_TZ)
        controller = claude_tool.Controller(window, preview=True, service=service)
        controller.timer.stop()
        controller.preview = False
        self.addCleanup(controller.deleteLater)
        return window, controller

    def test_all_check_entry_points_and_failure_preserve_old_report(self):
        items = [{"name": name, "status": "pass", "detail": "OK"}
                 for name in risk_check.ITEM_NAMES]
        with patch("claude_tool.SafeLaunchTask") as launch_type, patch(
                "claude_tool.ApplyTask"), patch("claude_tool.RiskTask"), patch(
                "claude_tool.write_error"):
            window, controller = self._controller()
            window.set_risk_items(items)
            controller.safe_launch_claude()
            self.assertEqual(window.risk_card.summary_pill.text(), "准备中…")
            started = launch_type.return_value.checking_started.connect.call_args[0][0]
            started()
            self.assertEqual(window.risk_card.summary_pill.text(), "检测中…")
            controller._on_progress("Checking")
            self.assertEqual(window.status_detail.text(), "Checking")
            controller._on_safe_launch_failed(RuntimeError("Stopped"), None)
            self.assertEqual(window.risk_card._items, items)
            self.assertIn("非本次结果", window.risk_card.checked_label.text())
            controller.manual_recheck()
            self.assertEqual(window.risk_card.summary_pill.text(), "检测中…")
            controller._on_risk_failed(RuntimeError("Cancelled"))
            self.assertEqual(window.risk_card.summary_pill.text(), "检测未完成")
            self.assertEqual(window.risk_card._items, items)
            controller._apply("usa")
            self.assertEqual(window.risk_card.summary_pill.text(), "准备中…")
            controller._on_apply_failed(RuntimeError("Stopped"))
            self.assertEqual(window.risk_card.summary_pill.text(), "检测未完成")
            controller._apply("usa")
            controller._on_apply_done("usa", False)
            self.assertEqual(window.risk_card.summary_pill.text(), "检测中…")
            report = risk_check.build_report(items)
            controller._on_risk_done(report)
            self.assertEqual(window.risk_card.summary_pill.text(), "9/9 安全通过")
            self.assertNotIn("非本次", window.risk_card.checked_label.text())
            report["items"][0]["status"] = "risk"
            controller._on_safe_launch_failed(RuntimeError("Blocked"), report)
            self.assertIn("发现 1 项异常", window.risk_card.summary_pill.text())

    def test_safe_launch_notifies_only_when_checks_really_start(self):
        service = Mock()
        service.read.return_value = SimpleNamespace(timezone_id=claude_tool.USA_TZ)
        proxy = Mock()
        proxy.verify_usa_active.return_value = (False, "Switch required")
        workflow = Mock()
        task = claude_tool.SafeLaunchTask(workflow, service, proxy)
        isolation_patch = patch(
            "claude_tool.claude_desktop.network_isolation.ensure_proxy_isolation")
        isolation_patch.start()
        self.addCleanup(isolation_patch.stop)
        events = []
        task.checking_started.connect(lambda: events.append("checking"))
        workflow.apply.side_effect = lambda *args: events.append("preparing")
        with patch("protected_session.start"), patch("protected_session.stop"), patch(
                "claude_tool.risk_check._clash_mixed_port", return_value=7890), patch(
                "claude_tool.claude_desktop.close_claude_desktop"), patch(
                "claude_tool.risk_check.run_checks",
                side_effect=lambda **kwargs: events.append("run") or {}), patch(
                "claude_tool.claude_desktop.validate_prelaunch_report",
                return_value=(True, "OK")), patch(
                "claude_tool.claude_desktop.launch_claude_desktop"):
            task.run()
        self.assertEqual(events, ["preparing", "checking", "run"])
        events.clear()
        workflow.apply.side_effect = RuntimeError("Preparation failed")
        with patch("claude_tool.claude_desktop.close_claude_desktop"), patch(
                "claude_tool.risk_check.run_checks") as checks:
            task.run()
        self.assertEqual(events, [])
        checks.assert_not_called()

    def test_unverified_isolation_prevents_launch(self):
        service, proxy, workflow = Mock(), Mock(), Mock()
        service.read.return_value.timezone_id = claude_tool.USA_TZ
        proxy.verify_usa_active.return_value = (True, "OK")
        task = claude_tool.SafeLaunchTask(workflow, service, proxy)
        failures = []
        task.failed.connect(lambda error, report: failures.append(error))
        failure = claude_tool.claude_desktop.network_isolation.IsolationError(
            "WFP installation failed")
        items = [{"name": name, "status": "pass", "detail": "8.8.8.8"}
                 for name in risk_check.ITEM_NAMES]
        items[7] = risk_check.webrtc_item([], "8.8.8.8")
        report = risk_check.build_report(items)
        with patch("protected_session.start", side_effect=failure), patch(
                "protected_session.stop"), patch(
                "claude_tool.claude_desktop.close_claude_desktop"), patch(
                "claude_tool.claude_desktop.find_all_claude_binaries",
                   return_value=[r"C:\Claude\Claude.exe"]), patch(
                "claude_tool.risk_check._clash_mixed_port", return_value=7890), patch(
                "claude_tool.risk_check.run_checks", return_value=report) as checks, patch(
                "claude_tool.claude_desktop.launch_claude_desktop") as launch:
            task.run()
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0], claude_tool.claude_desktop.network_isolation.IsolationError)
        workflow.apply.assert_not_called()
        checks.assert_called_once()
        launch.assert_not_called()

    def test_other_timezone_has_no_active_profile(self):
        window, controller = self._controller()
        controller.service.read.return_value.timezone_id = "Tokyo Standard Time"
        controller.read_state()
        self.assertEqual(window.china_card.property("active"), "false")
        self.assertEqual(window.usa_card.property("active"), "false")
        self.assertEqual(controller.target_mode, "usa")
        self.assertEqual(window.china_card.badge.text(), "当前")

    def test_launch_and_close_do_not_leave_permanent_running_tray_text(self):
        window, controller = self._controller()
        report = risk_check.build_report([
            {"name": name, "status": "pass", "detail": "OK"}
            for name in risk_check.ITEM_NAMES])
        controller._on_safe_launch_done(report)
        self.assertIn("已发送", window.status_title.text())
        self.assertIsNone(controller.risk_status)
        self.assertIn("已关闭", controller.tray_status)
        self.assertIn("未确认", window.firewall_badge.text())
        controller.risk_status = "Claude 安全运行中"
        controller._on_close_claude_done()
        self.assertIsNone(controller.risk_status)
        self.assertIn("已关闭", controller.tray_status)

    def test_cutoff_preserves_observed_process_count_and_rule_state(self):
        window, controller = self._controller()
        controller.risk_status = "Claude 安全运行中"
        self.processes.return_value = [{"pid": 123}, {"pid": 456}]
        with patch("claude_tool.claude_desktop.cut_off_claude_traffic"):
            controller._trigger_emergency_cutoff("Changed")
        self.assertIsNone(controller.risk_status)
        self.assertIn("2 进程", window.claude_card.process_pill.text())
        self.assertIn("未确认", window.firewall_badge.text())
        self.assertIn("紧急保护", controller.tray_status)
        self.assertIn("已尝试", window.status_detail.text())

    def test_running_claude_transitions_launch_banner_and_resets_on_exit(self):
        window, controller = self._controller()
        report = risk_check.build_report([
            {"name": name, "status": "pass",
             "detail": "93.184.216.34" if i == 1 else "OK"}
            for i, name in enumerate(risk_check.ITEM_NAMES)])
        self.processes.return_value = [SimpleNamespace(pid=101)]
        with patch("protected_session.active_port", return_value=18080):
            controller._on_safe_launch_done(report)
        self.assertIn("受控运行", window.status_title.text())
        self.assertIn("WFP 代理隔离中", window.firewall_badge.text())
        self.assertEqual(controller.monitor.baseline_ip, "93.184.216.34")

        self.processes.return_value = []
        with patch("protected_session.stop") as stop_session:
            controller._refresh_claude_status()
        stop_session.assert_called_once()
        self.assertFalse(window.status_panel.isVisible())
        self.assertEqual(controller.monitor.baseline_ip, "")
        self.assertEqual(window.endpoint_pill.text(), "未指定节点 · 自动识别")

    def test_unknown_only_recheck_is_not_red_error_and_mismatch_not_bound(self):
        window, controller = self._controller()
        items = [
            {"name": name, "status": "pass", "detail": "OK"}
            for name in risk_check.ITEM_NAMES]
        items[1] = {"name": risk_check.ITEM_NAMES[1], "status": "risk",
                    "detail": "实际 1.2.3.4，期望 5.6.7.8"}
        items[7] = risk_check.webrtc_item([], "5.6.7.8")
        report = risk_check.build_report(items)
        controller._on_risk_done(report)
        self.assertEqual(controller.monitor.baseline_ip, "")
        self.assertEqual(window.status_panel.property("error"), "true")

        items[1] = {"name": risk_check.ITEM_NAMES[1], "status": "pass",
                    "detail": "5.6.7.8"}
        report_unknown = risk_check.build_report(items)
        controller._on_risk_done(report_unknown)
        self.assertEqual(window.status_panel.property("error"), "false")
        self.assertEqual(controller.monitor.baseline_ip, "5.6.7.8")

    def test_china_switch_clears_whitelist_display_and_runtime_details_show_wfp(self):
        window, controller = self._controller()
        controller.monitor.set_baseline_ip("93.184.216.34")
        window.set_endpoint(risk_check.load_settings(), "93.184.216.34")
        self.assertIn("93.184.216.34", window.footer_endpoint.text())
        controller._on_apply_done("china", False)
        self.assertNotIn("93.184.216.34", window.footer_endpoint.text())

        window.claude_card.set_runtime_details({
            "processes": [{"pid": 77, "name": "claude.exe", "role": "主进程",
                           "memory_mb": 128.0}],
            "service_running": True,
            "firewall_blocked": False,
        }, active_ip="93.184.216.34", wfp_isolated=True)
        meta = window.claude_card.proc_meta_label.text()
        self.assertIn("WFP 代理隔离中", meta)
        self.assertIn("Cowork 服务运行中", meta)
        labels = [lbl.text() for lbl in window.claude_card.process_panel.findChildren(QLabel)]
        self.assertTrue(any("128 MB" in text for text in labels))
        self.assertTrue(any("WFP 网关隔离 → 93.184.216.34" in text for text in labels))

    def test_background_cutoff_updates_controls_and_drift_label(self):
        window, controller = self._controller()
        gen = object()
        controller._launch_generation = gen
        controller._on_background_cutoff(gen, "Clash TUN 内核已关闭", None)
        self.assertEqual(window.usa_card.drift_tag.text(), "→ TUN 关闭")
        self.assertTrue(window.claude_card.quick_fix_btn.isVisibleTo(window.claude_card))

    def test_safe_launch_auto_fixes_edge_language_drift_and_tray_mirrors_running(self):
        service = Mock()
        service.read.return_value = SimpleNamespace(
            timezone_id=claude_tool.USA_TZ, languages="zh-CN,zh")
        proxy = Mock()
        proxy.verify_usa_active.return_value = (True, "OK")
        workflow = Mock()
        task = claude_tool.SafeLaunchTask(workflow, service, proxy)
        with patch("protected_session.start"), patch("protected_session.stop"), \
                patch("claude_tool.risk_check._clash_mixed_port", return_value=7890), \
                patch("claude_tool.claude_desktop.close_claude_desktop"), \
                patch("claude_tool.claude_desktop.find_all_claude_binaries",
                      return_value=[r"C:\Claude\Claude.exe"]), \
                patch("claude_tool.risk_check.run_checks", return_value={"items": []}), \
                patch("claude_tool.claude_desktop.validate_prelaunch_report",
                      return_value=(True, "OK")), \
                patch("claude_tool.claude_desktop.launch_claude_desktop"):
            task.run()
        workflow.apply.assert_called_once()
        self.assertEqual(workflow.apply.call_args.args[0], "usa")

        window, controller = self._controller()
        tray = claude_tool.TrayHost(window, controller)
        self.addCleanup(tray.tray.hide)
        self.addCleanup(tray.deleteLater)
        window.claude_card.update_claude_state(True, 3, False, False, "守护中")
        tray.update_state()
        self.assertFalse(tray.launch_action.isEnabled())
        self.assertEqual(tray.launch_action.text(), "Claude 已运行")


if __name__ == "__main__":
    unittest.main()
