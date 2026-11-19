import json
import os
import sys
import queue
import socketserver
import threading
import time
import unittest
import urllib.error
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import claude_desktop
import risk_check
from region_core import CHINA_TZ, USA_TZ, RegionState


class BinaryDiscoveryTests(unittest.TestCase):

    def setUp(self):
        self.contexts = ExitStack()
        self.addCleanup(self.contexts.close)
        self.full_name = "Claude_5.11492.5.0_x64__pzs8sxrjxfjjc"
        self.root = os.path.join(r"C:\Program Files\WindowsApps", self.full_name)
        self.app = os.path.join(self.root, "app")
        self.resources = os.path.join(self.app, "resources")
        self.package = {
            "Name": "Claude", "PackageFullName": self.full_name,
            "PackageFamilyName": "Claude_pzs8sxrjxfjjc",
            "InstallLocation": self.root,
        }
        self.query = self.contexts.enter_context(patch(
            "claude_desktop.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps([self.package]))))
        self.contexts.enter_context(patch(
            "claude_desktop.os.path.isdir", return_value=True))
        self.isfile = self.contexts.enter_context(patch(
            "claude_desktop.os.path.isfile", return_value=True))
        self.contexts.enter_context(patch(
            "claude_desktop.os.path.realpath", side_effect=os.path.abspath))
        self.walk = self.contexts.enter_context(patch(
            "claude_desktop.os.walk", return_value=[
                (self.root, ["app"], []),
                (self.app, ["resources"], ["claude.exe"]),
                (self.resources, [], sorted(
                    claude_desktop.CLAUDE_EXE_NAMES - {"claude.exe"})
                 + ["github-mcp-server.exe"]),
            ]))
        self.manifest = '''<Package
            xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
            xmlns:uap5="http://schemas.microsoft.com/appx/manifest/uap/windows10/5">
          <Identity Name="Claude" Version="5.11492.5.0" ProcessorArchitecture="x64"/>
          <Applications><Application Id="Claude" Executable="app\\claude.exe">
            <Extensions><uap5:Extension Category="windows.appExecutionAlias"
                Executable="app\\claude.exe">
              <uap5:AppExecutionAlias>
                <uap5:ExecutionAlias Alias="claude-desktop.exe"/>
              </uap5:AppExecutionAlias>
            </uap5:Extension></Extensions>
          </Application></Applications>
        </Package>'''
        self.parse = self.contexts.enter_context(patch(
            "claude_desktop.ET.parse", side_effect=lambda _path:
            claude_desktop.ET.ElementTree(
                claude_desktop.ET.fromstring(self.manifest))))

    def test_exact_registered_directory_survives_denied_root_glob(self):
        with patch("glob.glob", side_effect=PermissionError("root denied")) as glob:
            binaries = claude_desktop.find_all_claude_binaries()
            target, working_dir = claude_desktop.find_claude_launch_target()
        glob.assert_not_called()
        msix_binaries = claude_desktop._find_msix_executables()
        self.assertTrue(set(msix_binaries).issubset(binaries))
        self.assertEqual(len(msix_binaries), len(claude_desktop.CLAUDE_EXE_NAMES) + 1)
        self.assertEqual({os.path.basename(path) for path in msix_binaries},
                         claude_desktop.CLAUDE_EXE_NAMES | {"github-mcp-server.exe"})
        self.assertEqual(target, os.path.join(
            os.environ["LOCALAPPDATA"], "Microsoft", "WindowsApps",
            "claude-desktop.exe"))
        self.assertEqual(working_dir, self.app)
        self.parse.assert_called_once_with(os.path.join(self.root, "AppxManifest.xml"))
        self.assertEqual(self.walk.call_args.args, (self.root,))
        command = self.query.call_args.args[0]
        self.assertTrue(command[0].endswith(
            r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        self.assertIn("Get-AppxPackage -Name Claude", command[-1])

    def test_invalid_registered_results_are_rejected(self):
        invalid = [
            {"Name": "Other"}, {"PackageFamilyName": "Claude_other"},
            {"PackageFullName": "Claude_fake"},
            {"InstallLocation": os.path.join(r"\\server\share", self.full_name)},
            {"InstallLocation": os.path.join("relative", self.full_name)},
            {"InstallLocation": os.path.join(
                r"C:\Users\user\Microsoft\WindowsApps", "claude-desktop.exe")},
            {"InstallLocation": self.root + "\\..\\" + self.full_name},
        ]
        for changes in invalid:
            with self.subTest(changes=changes):
                self.query.return_value.stdout = json.dumps([
                    dict(self.package, **changes)])
                with self.assertRaises(RuntimeError):
                    claude_desktop._find_msix_executables()

    def test_missing_binary_or_main_is_rejected(self):
        self.isfile.return_value = False
        with self.assertRaises(RuntimeError):
            claude_desktop._find_msix_executables()
        self.isfile.return_value = True
        self.walk.return_value = [(self.app, [], ["cowork-svc.exe"])]
        with self.assertRaises(RuntimeError):
            claude_desktop._find_msix_executables()

    def test_missing_package_directory_is_rejected(self):
        with patch("claude_desktop.os.path.isdir", return_value=False):
            with self.assertRaises(RuntimeError):
                claude_desktop._find_msix_executables()

    def test_binary_resolving_outside_package_is_rejected(self):
        resolve = os.path.abspath

        def realpath(path):
            if path.endswith("claude.exe"):
                return r"C:\Users\user\Microsoft\WindowsApps\claude.exe"
            return resolve(path)

        with patch("claude_desktop.os.path.realpath", side_effect=realpath):
            with self.assertRaisesRegex(RuntimeError, "安装目录之外"):
                claude_desktop._find_msix_executables()

    def test_subdirectory_access_error_rejects_partial_results(self):
        def walk(_root, onerror):
            yield self.app, ["resources"], ["claude.exe"]
            onerror(PermissionError("resources denied"))

        self.walk.side_effect = walk
        with self.assertRaisesRegex(RuntimeError, "无法完整枚举"):
            claude_desktop.find_all_claude_binaries()

    def test_query_failure_and_malformed_output_are_rejected(self):
        for returncode, stdout in ((1, ""), (0, "not json"), (0, "{}")):
            with self.subTest(returncode=returncode, stdout=stdout):
                self.query.return_value = SimpleNamespace(
                    returncode=returncode, stdout=stdout)
                with self.assertRaises(RuntimeError):
                    claude_desktop._find_msix_executables()

    def test_alias_only_cannot_be_used_as_binary(self):
        self.query.return_value.stdout = "[]"
        self.isfile.side_effect = lambda path: path.endswith("claude-desktop.exe")
        self.assertEqual(claude_desktop.find_all_claude_binaries(), [])
        with self.assertRaisesRegex(RuntimeError, "应用执行别名"):
            claude_desktop.find_claude_launch_target()

    def test_alias_manifest_must_match_registered_package_and_main(self):
        original = self.manifest
        for old, new in (
                ('Name="Claude"', 'Name="Other"'),
                ('Version="5.11492.5.0"', 'Version="1.0.0.0"'),
                ('ProcessorArchitecture="x64"', 'ProcessorArchitecture="arm64"'),
                ('Id="Claude"', 'Id="Other"'),
                ('Alias="claude-desktop.exe"', 'Alias="other.exe"'),
                ('Category="windows.appExecutionAlias"', 'Category="other"'),
                ('Executable="app\\claude.exe"',
                 'Executable="app\\resources\\cowork-svc.exe"'),
                ('Executable="app\\claude.exe"',
                 'Executable="..\\claude.exe"')):
            with self.subTest(replacement=new):
                self.manifest = original.replace(old, new)
                with self.assertRaises(RuntimeError):
                    claude_desktop.find_claude_launch_target()

    def test_alias_extension_cannot_override_main_with_another_binary(self):
        self.manifest = self.manifest.replace(
            'Executable="app\\claude.exe"',
            'Executable="app\\resources\\cowork-svc.exe"', 1)
        with self.assertRaisesRegex(RuntimeError, "未映射"):
            claude_desktop.find_claude_launch_target()

    def test_unreadable_or_invalid_alias_manifest_rejects_launch(self):
        for error in (PermissionError("denied"), claude_desktop.ET.ParseError("bad")):
            with self.subTest(error=error):
                self.parse.side_effect = error
                with self.assertRaisesRegex(RuntimeError, "无法验证"):
                    claude_desktop.find_claude_launch_target()

    def test_missing_alias_or_ambiguous_registration_rejects_launch(self):
        alias = os.path.join(os.environ["LOCALAPPDATA"], "Microsoft", "WindowsApps",
                             "claude-desktop.exe")
        self.isfile.side_effect = lambda path: path != alias
        with self.assertRaisesRegex(RuntimeError, "别名缺失"):
            claude_desktop.find_claude_launch_target()
        self.isfile.side_effect = None
        self.query.return_value.stdout = json.dumps([self.package, self.package])
        with self.assertRaisesRegex(RuntimeError, "注册不唯一"):
            claude_desktop.find_claude_launch_target()

    def test_verified_alias_launch_preserves_proxy_flags_and_actual_wfp_paths(self):
        binaries = claude_desktop._find_msix_executables()
        with patch("claude_desktop._FIREWALL_LOCK", threading.RLock()), \
                patch("claude_desktop._EMERGENCY_CUTOFF", threading.Event()), \
                patch("protected_session.active_port", return_value=18080), \
                patch("claude_desktop.network_isolation.ensure_proxy_isolation") as isolate, \
                patch("claude_desktop.allow_claude_traffic", return_value=True), \
                patch("win32util.start_process_with_explorer_token") as start, \
                patch("claude_desktop.list_claude_processes", return_value=[Mock()]):
            self.assertTrue(claude_desktop.launch_claude_desktop())
        target = os.path.join(os.environ["LOCALAPPDATA"], "Microsoft", "WindowsApps",
                              "claude-desktop.exe")
        start.assert_called_once_with(
            target, claude_desktop.network_isolation.build_launch_args(18080), self.app)
        self.assertIn("--proxy-server=http://127.0.0.1:18080", start.call_args.args[1])
        self.assertTrue(set(binaries).issubset(isolate.call_args.args[0]))
        self.assertNotIn(target, isolate.call_args.args[0])


class ProcessMatchTests(unittest.TestCase):

    def test_identifies_msix_claude_exe(self):
        info = {
            "pid": 1234,
            "name": "claude.exe",
            "exe": r"C:\Program Files\WindowsApps\Claude_5.1_x64__pzs8sxrjxfjjc\app\Claude.exe",
        }
        self.assertTrue(
            claude_desktop._is_claude_desktop_process(info, 9999))

    def test_identifies_helper_processes(self):
        for helper in ("cowork-svc.exe", "claude-ssh-proxy.exe",
                       "claude-ssh-broker.exe"):
            info = {"pid": 2000, "name": helper, "exe": ""}
            self.assertTrue(
                claude_desktop._is_claude_desktop_process(info, 9999))

    def test_ignores_claudeguard_and_claudecode_cli(self):
        tool_info = {
            "pid": 3000,
            "name": "ClaudeGuard.exe",
            "exe": r"F:\ClaudeGuard\dist\ClaudeGuard.exe",
        }
        cli_info = {
            "pid": 3001,
            "name": "claude.exe",
            "exe": r"C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\Anthropic.ClaudeCode\claude.exe",
        }
        self.assertFalse(
            claude_desktop._is_claude_desktop_process(tool_info, 9999))
        self.assertFalse(
            claude_desktop._is_claude_desktop_process(cli_info, 9999))
        self.assertFalse(
            claude_desktop._is_claude_desktop_process(
                {"pid": 9999, "name": "claude.exe", "exe": ""}, 9999))


class FirewallGuardTests(unittest.TestCase):

    def setUp(self):
        self.contexts = ExitStack()
        self.addCleanup(self.contexts.close)
        self.run_system = self.contexts.enter_context(patch(
            "claude_desktop._run_system",
            return_value=SimpleNamespace(returncode=0)))
        self.find_binaries = self.contexts.enter_context(patch(
            "claude_desktop.find_all_claude_binaries",
            return_value=[r"C:\Claude\claude.exe", r"C:\Claude\helper.exe"]))
        self.contexts.enter_context(patch(
            "claude_desktop._FIREWALL_LOCK", threading.RLock()))
        self.contexts.enter_context(patch(
            "claude_desktop._EMERGENCY_CUTOFF", threading.Event()))
        self.contexts.enter_context(patch(
            "protected_session.active_port", return_value=18080))
        self.contexts.enter_context(patch("protected_session.close_gate"))
        self.contexts.enter_context(patch(
            "claude_desktop.network_isolation.revoke_proxy_access"))
        self.isolation_patch = patch(
            "claude_desktop.network_isolation.ensure_proxy_isolation")
        self.isolation_patch.start()
        self.addCleanup(self.isolation_patch.stop)

    def test_unverified_isolation_never_unlocks_or_starts(self):
        self.isolation_patch.stop()
        with patch("claude_desktop.find_claude_launch_target",
                   return_value=(r"C:\Claude\claude.exe", r"C:\Claude")), \
                patch("claude_desktop.allow_claude_traffic") as allow, \
                patch("win32util.start_process_with_explorer_token") as start:
            with self.assertRaises(claude_desktop.network_isolation.IsolationError):
                claude_desktop.launch_claude_desktop()
        allow.assert_not_called()
        start.assert_not_called()

    def test_repeated_blocks_only_add_rules(self):
        self.assertTrue(claude_desktop.block_claude_traffic())
        self.assertTrue(claude_desktop.block_claude_traffic())
        self.assertEqual(self.run_system.call_count, 4)
        for call in self.run_system.call_args_list:
            self.assertEqual(call.args[0][3], "add")

    def test_block_failure_keeps_attempting_other_binaries(self):
        for failure in (SimpleNamespace(returncode=1), TimeoutError()):
            with self.subTest(failure=failure):
                self.run_system.reset_mock()
                self.run_system.side_effect = [
                    failure, SimpleNamespace(returncode=0)]
                self.assertFalse(claude_desktop.block_claude_traffic())
                self.assertEqual(self.run_system.call_count, 2)

    def test_block_without_binaries_fails(self):
        self.find_binaries.return_value = []
        self.assertFalse(claude_desktop.block_claude_traffic())
        self.run_system.assert_not_called()

    def test_unlock_checks_exit_status_and_exception(self):
        self.run_system.return_value.returncode = 1
        self.assertFalse(claude_desktop.allow_claude_traffic())
        self.run_system.side_effect = TimeoutError()
        self.assertFalse(claude_desktop.allow_claude_traffic())
        self.run_system.side_effect = None
        self.run_system.return_value.returncode = 0
        self.assertTrue(claude_desktop.allow_claude_traffic())

    def test_unlock_does_not_wait_behind_active_block(self):
        entered = threading.Event()
        release = threading.Event()
        results = []

        def run_system(arguments, **_kwargs):
            entered.set()
            if not release.wait(2):
                raise TimeoutError("Test did not release firewall command")
            self.assertEqual(arguments[3], "add")
            return SimpleNamespace(returncode=0)

        self.run_system.side_effect = run_system
        worker = threading.Thread(target=lambda: results.append(
            claude_desktop.block_claude_traffic()))
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assertFalse(claude_desktop.allow_claude_traffic())
            with self.assertRaises(RuntimeError):
                claude_desktop.begin_safe_launch()
            self.assertEqual(self.run_system.call_count, 1)
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results, [True])

    def test_concurrent_blocks_preserve_existing_rules(self):
        entered = threading.Event()
        release = threading.Event()
        second_started = threading.Event()
        results = []

        def run_system(arguments, **_kwargs):
            if threading.current_thread().name == "first":
                entered.set()
                if not release.wait(2):
                    raise TimeoutError("Test did not release firewall command")
            self.assertEqual(arguments[3], "add")
            return SimpleNamespace(returncode=0)

        def block_second():
            second_started.set()
            results.append(claude_desktop.block_claude_traffic())

        self.run_system.side_effect = run_system
        first = threading.Thread(name="first", target=lambda: results.append(
            claude_desktop.block_claude_traffic()))
        second = threading.Thread(target=block_second)
        first.start()
        try:
            self.assertTrue(entered.wait(2))
            second.start()
            self.assertTrue(second_started.wait(2))
            self.assertEqual(self.run_system.call_count, 1)
        finally:
            release.set()
            first.join(2)
            if second.ident is not None:
                second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(results, [True, True])
        self.assertEqual(self.run_system.call_count, 4)

    def test_cutoff_kills_before_block_and_before_service_stop(self):
        events = []
        proc = Mock()
        proc.kill.side_effect = lambda: events.append("kill")
        with patch("claude_desktop.list_claude_processes",
                   side_effect=[[proc], [proc], []]), \
                patch("claude_desktop.block_claude_traffic",
                      side_effect=lambda: events.append("block") or True), \
                patch("claude_desktop.stop_cowork_service",
                      side_effect=lambda: events.append("service")), \
                patch("claude_desktop._refresh_tray_icons"):
            self.assertEqual(claude_desktop.cut_off_claude_traffic(), 1)
        self.assertEqual(events, ["kill", "block", "kill", "service"])
        self.assertFalse(claude_desktop.allow_claude_traffic())
        self.run_system.assert_not_called()

    def test_failed_cutoff_still_kills_and_stops_service(self):
        proc = Mock()
        with patch("claude_desktop.list_claude_processes", return_value=[proc]), \
                patch("claude_desktop.block_claude_traffic", return_value=False), \
                patch("claude_desktop.stop_cowork_service") as stop_service, \
                patch("claude_desktop._refresh_tray_icons"):
            with self.assertRaises(RuntimeError):
                claude_desktop.cut_off_claude_traffic()
        self.assertEqual(proc.kill.call_count, 2)
        stop_service.assert_called_once()
        self.assertTrue(claude_desktop._EMERGENCY_CUTOFF.is_set())

    def test_close_blocks_before_process_work_and_reports_failure(self):
        events = []
        with patch("claude_desktop.block_claude_traffic",
                   side_effect=lambda: events.append("block") or False), \
                patch("claude_desktop.list_claude_processes",
                      side_effect=lambda **_kwargs: events.append("list") or []), \
                patch("claude_desktop.stop_cowork_service",
                      side_effect=lambda: events.append("service")), \
                patch("claude_desktop._refresh_tray_icons"):
            with self.assertRaises(RuntimeError):
                claude_desktop.close_claude_desktop()
        self.assertEqual(events[0], "block")
        self.assertIn("service", events)

    def test_close_claude_desktop_stops_protected_session(self):
        with patch("claude_desktop.block_claude_traffic", return_value=True), \
                patch("claude_desktop.list_claude_processes", return_value=[]), \
                patch("claude_desktop.stop_cowork_service"), \
                patch("claude_desktop._refresh_tray_icons"), \
                patch("protected_session.stop") as stop_session:
            self.assertTrue(claude_desktop.close_claude_desktop())
        stop_session.assert_called_once()

    def test_latched_launch_cannot_unlock_or_start(self):
        claude_desktop._EMERGENCY_CUTOFF.set()
        with patch("claude_desktop.find_claude_launch_target",
                   return_value=("claude.exe", "C:\\Claude")), \
                patch("claude_desktop.allow_claude_traffic") as allow, \
                patch("win32util.start_process_with_explorer_token") as start:
            with self.assertRaises(RuntimeError):
                claude_desktop.launch_claude_desktop()
        allow.assert_not_called()
        start.assert_not_called()

    def test_explicit_new_launch_clears_old_latch(self):
        claude_desktop._EMERGENCY_CUTOFF.set()
        claude_desktop.begin_safe_launch()
        with patch("claude_desktop.find_claude_launch_target",
                   return_value=("claude.exe", "C:\\Claude")), \
                patch("win32util.start_process_with_explorer_token") as start, \
                patch("claude_desktop.list_claude_processes", return_value=[Mock()]):
            self.assertTrue(claude_desktop.launch_claude_desktop())
        start.assert_called_once()

    def test_failed_unlock_cancels_launch(self):
        self.run_system.return_value.returncode = 1
        with patch("claude_desktop.find_claude_launch_target",
                   return_value=("claude.exe", "C:\\Claude")), \
                patch("win32util.start_process_with_explorer_token") as start:
            with self.assertRaises(RuntimeError):
                claude_desktop.launch_claude_desktop()
        start.assert_not_called()

    def test_emergency_during_unlock_cancels_inflight_launch(self):
        unlocking = threading.Event()
        release = threading.Event()
        launch_errors = []
        cutoff_results = []

        def run_system(arguments, **_kwargs):
            if arguments[3] == "delete":
                unlocking.set()
                if not release.wait(2):
                    raise TimeoutError("Test did not release unlock command")
            return SimpleNamespace(returncode=0)

        def launch():
            try:
                claude_desktop.launch_claude_desktop()
            except RuntimeError as error:
                launch_errors.append(error)

        self.run_system.side_effect = run_system
        with patch("claude_desktop.find_claude_launch_target",
                   return_value=("claude.exe", "C:\\Claude")), \
                patch("win32util.start_process_with_explorer_token") as start, \
                patch("claude_desktop.list_claude_processes", return_value=[]), \
                patch("claude_desktop.stop_cowork_service"), \
                patch("claude_desktop._refresh_tray_icons"):
            launch_worker = threading.Thread(target=launch)
            cutoff_worker = threading.Thread(target=lambda: cutoff_results.append(
                claude_desktop.cut_off_claude_traffic()))
            launch_worker.start()
            try:
                self.assertTrue(unlocking.wait(2))
                cutoff_worker.start()
                self.assertTrue(claude_desktop._EMERGENCY_CUTOFF.wait(2))
            finally:
                release.set()
                launch_worker.join(2)
                if cutoff_worker.ident is not None:
                    cutoff_worker.join(2)
            self.assertFalse(launch_worker.is_alive())
            self.assertFalse(cutoff_worker.is_alive())
            start.assert_not_called()
        self.assertEqual(len(launch_errors), 1)
        self.assertEqual(cutoff_results, [0])
        self.assertEqual(
            [call.args[0][3] for call in self.run_system.call_args_list],
            ["delete", "add", "add"])
        self.assertFalse(claude_desktop.allow_claude_traffic())


class PrelaunchValidationTests(unittest.TestCase):

    def test_empty_or_malformed_report_cannot_authorize_launch(self):
        for report in ({"items": []}, {"items": [None]}):
            self.assertFalse(claude_desktop.validate_prelaunch_report(report)[0])

    def test_stun_unknown_alone_cannot_authorize_launch(self):
        entry = claude_desktop.risk_check.webrtc_item([], "8.8.8.8")
        report = claude_desktop.risk_check.build_report([entry])
        ok, reason = claude_desktop.validate_prelaunch_report(report)
        self.assertFalse(ok)
        self.assertIn("缺少已通过的检查", reason)

    def test_stun_unknown_does_not_block_other_passed_checks(self):
        items = [{"name": name, "status": "pass", "detail": "OK"}
                 for name in claude_desktop.risk_check.ITEM_NAMES]
        items[7] = claude_desktop.risk_check.webrtc_item([], "8.8.8.8")
        report = claude_desktop.risk_check.build_report(items)
        ok, reason = claude_desktop.validate_prelaunch_report(report)
        self.assertTrue(ok)
        self.assertTrue(report["hasRisk"])
        self.assertEqual(items[7]["status"], "unknown")
        self.assertIn("STUN 出口待确认", reason)

    def test_stun_mismatch_still_blocks_launch(self):
        items = [{"name": name, "status": "pass", "detail": "OK"}
                 for name in claude_desktop.risk_check.ITEM_NAMES]
        items[7] = claude_desktop.risk_check.webrtc_item(["1.1.1.1"], "8.8.8.8")
        ok, reason = claude_desktop.validate_prelaunch_report({"items": items})
        self.assertFalse(ok)
        self.assertIn("UDP 出口检测（STUN）", reason)

    def test_stun_unknown_does_not_hide_other_failures(self):
        for status in ("unknown", "risk"):
            with self.subTest(status=status):
                items = [
                    {"name": name, "status": "pass", "detail": "OK"}
                    for name in claude_desktop.risk_check.ITEM_NAMES]
                items[7] = claude_desktop.risk_check.webrtc_item([], "8.8.8.8")
                items[6]["status"] = status
                ok, reason = claude_desktop.validate_prelaunch_report(
                    {"items": items})
                self.assertFalse(ok)
                self.assertIn("DNS 泄露检测", reason)

    def test_passes_when_all_items_pass(self):
        report = {
            "items": [
                {"name": "Claude AI出口IP", "status": "pass", "detail": "93.184.216.34"},
                {"name": "DNS泄露检测", "status": "pass", "detail": "DNS 加密"},
            ]
        }
        ok, msg = claude_desktop.validate_prelaunch_report(report)
        self.assertTrue(ok)
        self.assertIn("全部通过", msg)

    def test_blocks_when_any_item_fails(self):
        report = {
            "items": [
                {"name": "Claude AI出口IP", "status": "risk", "detail": "实际 1.1.1.1"},
                {"name": "DNS泄露检测", "status": "pass", "detail": "正常"},
            ]
        }
        ok, msg = claude_desktop.validate_prelaunch_report(report)
        self.assertFalse(ok)
        self.assertIn("Claude AI出口IP", msg)


class FakeRegionService:
    def __init__(self, timezone_id=USA_TZ, languages="en-US,en"):
        self.timezone_id = timezone_id
        self.languages = languages

    def read(self):
        return RegionState(
            timezone_id=self.timezone_id,
            languages=self.languages,
            machine_languages="",
            browser_languages=self.languages,
            browser_profile="Default",
            browser_is_running=False,
        )


class FakeClashSwitch:
    def __init__(self, ok=True, reason="正常"):
        self.ok = ok
        self.reason = reason

    def verify_usa_active(self):
        return self.ok, self.reason


class EnvironmentMonitorTests(unittest.TestCase):

    def test_local_check_passes_in_valid_usa_state(self):
        monitor = claude_desktop.EnvironmentMonitor(
            FakeRegionService(USA_TZ, "en-US,en"),
            FakeClashSwitch(True, "正常"))
        ok, _reason = monitor.check_local()
        self.assertTrue(ok)

    def test_local_summary_describes_english_web_language(self):
        monitor = claude_desktop.EnvironmentMonitor(
            FakeRegionService(USA_TZ, "en-GB,en"), FakeClashSwitch())
        ok, reason = monitor.check_local()
        self.assertTrue(ok)
        self.assertIn("英语网页语言", reason)
        self.assertNotIn("en-US", reason)

    def test_local_check_detects_timezone_drift(self):
        monitor = claude_desktop.EnvironmentMonitor(
            FakeRegionService(CHINA_TZ, "en-US,en"),
            FakeClashSwitch(True, "正常"))
        ok, reason = monitor.check_local()
        self.assertFalse(ok)
        self.assertIn("时区", reason)

    def test_local_check_detects_language_drift(self):
        monitor = claude_desktop.EnvironmentMonitor(
            FakeRegionService(USA_TZ, "zh-CN,zh"),
            FakeClashSwitch(True, "正常"))
        ok, reason = monitor.check_local()
        self.assertFalse(ok)
        self.assertIn("语言", reason)
        self.assertIn("Edge 网页", reason)

    def test_local_check_detects_clash_drift(self):
        monitor = claude_desktop.EnvironmentMonitor(
            FakeRegionService(USA_TZ, "en-US,en"),
            FakeClashSwitch(False, "Clash TUN 内核已关闭"))
        ok, reason = monitor.check_local()
        self.assertFalse(ok)
        self.assertIn("TUN", reason)

    @patch("risk_check.load_settings", return_value={"staticIp": "8.8.8.8"})
    def test_remote_missing_result_is_failure_immediately(self, _settings):
        monitor = claude_desktop.EnvironmentMonitor(proxy_port=18080)
        with patch("risk_check.fetch_trace_ip", return_value=""):
            ok, reason = monitor.check_remote_ip()
        self.assertFalse(ok)
        self.assertIn("无法确认", reason)

    @patch("risk_check.load_settings", return_value={"staticIp": "8.8.8.8"})
    def test_remote_fallback_shares_deadline_and_explicit_proxy(self, _settings):
        monitor = claude_desktop.EnvironmentMonitor(proxy_port=18080)
        clients = []

        def trace(client, url):
            clients.append(client)
            return "" if url == risk_check.CLAUDE_TRACE_URL else "8.8.8.8"

        deadline = claude_desktop.time.monotonic() + .5
        with patch("risk_check.fetch_trace_ip", side_effect=trace):
            self.assertTrue(monitor.check_remote_ip(deadline=deadline)[0])
        self.assertIs(clients[0], clients[1])
        self.assertEqual(clients[0].proxy_port, 18080)
        self.assertLessEqual(clients[0].deadline, deadline)
        self.assertLess(clients[0].deadline, deadline - .02)

    @patch("risk_check.load_settings", return_value={"staticIp": "8.8.8.8"})
    def test_endpoint_timeout_finishes_before_supervisor_deadline(self, _settings):
        monitor = claude_desktop.EnvironmentMonitor(proxy_port=18080)
        release = threading.Event()
        self.addCleanup(release.set)

        def download(_client, url, timeout):
            if url == risk_check.CLAUDE_TRACE_URL:
                release.wait(2)
                raise TimeoutError("stalled endpoint")
            return b"ip=8.8.8.8\n"

        deadline = time.monotonic() + .4
        with patch("risk_check.HttpClient._download", autospec=True,
                   side_effect=download):
            ok, _ = monitor.check_remote_ip(deadline=deadline)
        self.assertTrue(ok)
        self.assertLess(time.monotonic(), deadline)

    @patch("risk_check.load_settings", return_value={"staticIp": "8.8.8.8"})
    def test_parallel_results_never_accept_conflicting_exit(self, _settings):
        monitor = claude_desktop.EnvironmentMonitor(proxy_port=18080)
        release = threading.Event()
        self.addCleanup(release.set)

        def trace(_client, url):
            if url == risk_check.CLAUDE_TRACE_URL:
                release.wait(.1)
                return "9.9.9.9"
            release.set()
            return "8.8.8.8"

        with patch("risk_check.fetch_trace_ip", side_effect=trace):
            ok, reason = monitor.check_remote_ip()
        self.assertFalse(ok)
        self.assertIn("9.9.9.9", reason)

    @patch("risk_check.load_settings", return_value={"staticIp": "8.8.8.8"})
    def test_healthy_result_waits_for_hung_peer_and_timeout_fails(self, _settings):
        monitor = claude_desktop.EnvironmentMonitor(proxy_port=18080)
        release = threading.Event()
        self.addCleanup(release.set)

        def trace(_client, url):
            if url == risk_check.CLAUDE_TRACE_URL:
                release.wait(2)
                return ""
            return "8.8.8.8"

        start = time.monotonic()
        with patch("risk_check.fetch_trace_ip", side_effect=trace):
            ok, reason = monitor.check_remote_ip(deadline=start + .15)
        self.assertFalse(ok)
        self.assertIn("超时", reason)
        self.assertGreaterEqual(time.monotonic() - start, .14)

    @patch("risk_check.load_settings", return_value={"staticIp": "8.8.8.8"})
    def test_real_loopback_proxy_parallel_endpoints_survive_service_failure(
            self, _settings):
        arrived = threading.Barrier(2)
        errors = queue.Queue()
        requests = queue.Queue()

        class Handler(socketserver.BaseRequestHandler):

            def handle(self):
                self.request.settimeout(1)
                data = self.request.recv(4096)
                requests.put(data)
                arrived.wait(1)
                if b"primary.invalid" in data:
                    body = b"unavailable"
                    status = b"403 Unavailable"
                else:
                    body = b"ip=8.8.8.8\n"
                    status = b"200 OK"
                self.request.sendall(
                    b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                    + str(len(body)).encode() + b"\r\n\r\n" + body)

        class Server(socketserver.ThreadingTCPServer):

            def handle_error(self, request, client_address):
                errors.put(sys.exc_info()[1])

        with Server(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": .01},
                daemon=True)
            worker.start()
            try:
                monitor = claude_desktop.EnvironmentMonitor(
                    proxy_port=server.server_address[1])
                with patch("risk_check.CLAUDE_TRACE_URL",
                           "http://primary.invalid/trace"), patch(
                               "risk_check.CLOUDFLARE_TRACE_URL",
                               "http://secondary.invalid/trace"):
                    self.assertTrue(monitor.check_remote_ip()[0])
            finally:
                server.shutdown()
                worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors.empty(), list(errors.queue))
        self.assertEqual(requests.qsize(), 2)

    @patch("risk_check.load_settings", return_value={"staticIpMode": "auto"})
    def test_auto_requires_explicit_baseline_and_rejects_new_exit(self, _settings):
        monitor = claude_desktop.EnvironmentMonitor(proxy_port=18080)
        with patch("risk_check.resolve_node_ip", return_value="9.9.9.9") as node, \
                patch("risk_check.fetch_trace_ip", return_value="8.8.8.8") as trace:
            self.assertFalse(monitor.check_remote_ip()[0])
            trace.assert_not_called()
            monitor.set_baseline_ip("8.8.8.8")
            self.assertTrue(monitor.check_remote_ip()[0])
            trace.return_value = "9.9.9.9"
            self.assertFalse(monitor.check_remote_ip()[0])
            self.assertEqual(monitor.baseline_ip, "8.8.8.8")
            node.assert_not_called()

    @patch("claude_desktop.is_traffic_blocked", return_value=True)
    @patch("claude_desktop.is_cowork_service_running", return_value=False)
    @patch("claude_desktop.list_claude_processes")
    def test_inspect_claude_runtime_lists_processes(
        self, mock_list_procs, _mock_svc, _mock_fw
    ):
        from contextlib import nullcontext

        class FakeProc:
            def __init__(self, pid, name, rss, cmdline=None):
                self.pid = pid
                self._name = name
                self._rss = rss
                self._cmdline = cmdline or [name]

            def oneshot(self):
                return nullcontext()

            def name(self):
                return self._name

            def exe(self):
                return "C:\\Apps\\" + self._name

            def memory_info(self):
                return type("M", (), {"rss": self._rss})()

            def cmdline(self):
                return self._cmdline

        mock_list_procs.return_value = [
            FakeProc(1001, "claude.exe", 120 * 1024 * 1024),
            FakeProc(1003, "cowork-vm-service.exe", 40 * 1024 * 1024),
        ]
        state = claude_desktop.inspect_claude_runtime()
        self.assertFalse(state["service_running"])
        self.assertTrue(state["firewall_blocked"])
        names = [p["name"] for p in state["processes"]]
        self.assertEqual(names, ["claude.exe", "cowork-vm-service.exe"])
        self.assertEqual(state["processes"][0]["pid"], 1001)
        self.assertIn("role", state["processes"][0])

    def test_list_claude_processes_uses_fast_win32_snapshot_without_process_iter(self):
        with patch("win32util.snapshot_processes", return_value=[
                (10, "System", 0),
                (500, "claude.exe", 400),
                (501, "node.exe", 500),
                (600, "chrome.exe", 1),
             ]), \
             patch("win32util.current_sid", return_value="S-1-5-21-test"), \
             patch("win32util.process_sid", return_value="S-1-5-21-test"), \
             patch("win32util.process_image_path", side_effect=lambda pid: (
                 r"C:\Program Files\WindowsApps\Claude_6.0_x64__pzs8sxrjxfjjc\app\claude.exe"
                 if pid == 500 else r"C:\Windows\System32\other.exe")), \
             patch("psutil.Process", side_effect=lambda pid: SimpleNamespace(
                 pid=pid, create_time=lambda: 100.0 + pid)), \
             patch("psutil.process_iter", side_effect=AssertionError("must not call psutil.process_iter")):
            procs = claude_desktop.list_claude_processes(include_children=True)
        self.assertEqual([p.pid for p in procs], [500, 501])

    def test_is_cowork_service_running_queries_scm_directly(self):
        with patch("win32util.is_service_running", return_value=True) as svc, \
             patch.object(claude_desktop, "_run_system", side_effect=AssertionError("must not spawn sc.exe")):
            self.assertTrue(claude_desktop.is_cowork_service_running())
        svc.assert_called_once_with(claude_desktop.COWORK_SERVICE_NAME)


if __name__ == "__main__":
    unittest.main()
