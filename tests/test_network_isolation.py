"""Test planning and WFP launch gating without changing system policy."""

import base64
import ipaddress
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import network_isolation


BINARY = r'C:\Program Files\Claude\Claude.exe'


class RulePlanTests(unittest.TestCase):

    def test_nonloopback_ranges_have_exact_numeric_coverage(self):
        ranges = [tuple(ipaddress.ip_address(part) for part in value.split('-'))
                  for value in network_isolation.NON_LOOPBACK_RANGES]
        for version, loopback in ((4, '127.0.0.0/8'), (6, '::1/128')):
            with self.subTest(version=version):
                selected = [(int(start), int(end)) for start, end in ranges
                            if start.version == version]
                network = ipaddress.ip_network(loopback)
                excluded_start = int(network.network_address)
                excluded_end = int(network.broadcast_address)
                maximum = (1 << network.max_prefixlen) - 1
                self.assertEqual(selected, [
                    (0, excluded_start - 1), (excluded_end + 1, maximum)])

    def test_plan_is_stable_deduplicated_and_separate_from_kill_switch(self):
        rules = network_isolation.plan_nonloopback_blocks([
            BINARY, BINARY.upper(), r'C:\Claude\helper.exe'])
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules, network_isolation.plan_nonloopback_blocks([
            r'C:\Claude\helper.exe', BINARY]))
        for rule in rules:
            self.assertTrue(rule.name.startswith(
                network_isolation.PROXY_RULE_PREFIX))
            self.assertFalse(rule.name.startswith('ClaudeGuard_Block'))

    def test_upgrade_gets_additional_identity(self):
        old = network_isolation.plan_nonloopback_blocks([
            r'C:\Claude\v1\Claude.exe'])[0]
        new = network_isolation.plan_nonloopback_blocks([
            r'C:\Claude\v2\Claude.exe'])[0]
        self.assertNotEqual(old.name, new.name)

    def test_rejects_incomplete_or_ambiguous_plans(self):
        cases = [[], BINARY, ['claude.exe'], [r'C:claude.exe'],
                 [r'\\server\share\claude.exe'], [r'C:\Claude\*.exe'],
                 [r'C:\%APP%\claude.exe'], [r'C:\Claude\app.exe:stream.exe'],
                 ['C:\\Claude\\bad\n.exe'], [None], [r'C:\Claude\file.dll']]
        for binaries in cases:
            with self.subTest(binaries=binaries):
                with self.assertRaises(network_isolation.IsolationError):
                    network_isolation.plan_nonloopback_blocks(binaries)


class LaunchGateTests(unittest.TestCase):

    def test_launch_authorization_returns_verified_backend_result(self):
        backend = Mock()
        backend.ensure.return_value = ('verified-key',)
        with patch.object(network_isolation, '_backend', backend):
            self.assertEqual(network_isolation.ensure_proxy_isolation(
                [BINARY], 54321), ('verified-key',))
        backend.ensure.assert_called_once_with((BINARY.lower(),), 54321)

    def test_lockdown_verification_does_not_run_system_commands(self):
        backend = Mock()
        with patch.object(network_isolation, '_backend', backend), patch.object(
                network_isolation.subprocess, 'run') as run:
            network_isolation.remove_lockdown_preserving_proxy_isolation(
                [BINARY], 7890)
            backend.ensure.assert_called_once()
            run.assert_not_called()

    def test_backend_error_or_timeout_revokes_and_refuses_launch(self):
        for error in (OSError('denied'), TimeoutError('timed out')):
            backend = Mock()
            backend.ensure.side_effect = error
            with self.subTest(error=error), patch.object(
                    network_isolation, '_backend', backend):
                with self.assertRaises(network_isolation.IsolationError):
                    network_isolation.ensure_proxy_isolation([BINARY], 7890)
                backend.revoke_proxy_access.assert_called_once_with()

    def test_invalid_input_revokes_existing_permits(self):
        backend = Mock()
        with patch.object(network_isolation, '_backend', backend):
            with self.assertRaises(network_isolation.IsolationError):
                network_isolation.ensure_proxy_isolation([BINARY], True)
            backend.ensure.assert_not_called()
            backend.revoke_proxy_access.assert_called_once_with()

    def test_revoke_without_session_is_noop(self):
        with patch.object(network_isolation, '_backend', None):
            network_isolation.revoke_proxy_access()
            network_isolation.revoke_proxy_access()

    def test_revoke_failure_is_reported(self):
        backend = Mock()
        backend.revoke_proxy_access.side_effect = OSError('close failed')
        with patch.object(network_isolation, '_backend', backend):
            with self.assertRaises(network_isolation.IsolationError):
                network_isolation.revoke_proxy_access()

    def test_invalid_ports_are_rejected(self):
        for port in (0, -1, 65536, True, '7890', None, 7890.0):
            with self.subTest(port=port):
                with self.assertRaises(network_isolation.IsolationError):
                    network_isolation.build_launch_args(port)

    def test_launch_args_pin_loopback_and_disable_implicit_bypass(self):
        self.assertEqual(network_isolation.build_launch_args(7890), [
            '--proxy-server=http://127.0.0.1:7890',
            '--proxy-bypass-list=<-loopback>'])


class InstallationTests(unittest.TestCase):

    def setUp(self):
        self.rules = network_isolation.plan_nonloopback_blocks([BINARY])
        self.patches = [
            patch.object(network_isolation.os, 'name', 'nt'),
            patch.object(network_isolation.os.path, 'isfile', return_value=True),
            patch.object(network_isolation.subprocess, 'run'),
        ]
        for item in self.patches:
            self.addCleanup(item.stop)
        self.patches[0].start()
        self.isfile = self.patches[1].start()
        self.run = self.patches[2].start()
        self.run.return_value = Mock(returncode=0, stdout=json.dumps({
            'verified': [rule.name for rule in self.rules]}))

    def test_success_returns_diagnostic_plan_only(self):
        self.assertEqual(network_isolation.install_nonloopback_blocks([BINARY]),
                         self.rules)
        self.run.assert_called_once()
        command = self.run.call_args.args[0]
        script = base64.b64decode(command[-1]).decode('utf-16-le')
        self.assertIn('-PolicyStore ActiveStore', script)
        self.assertIn('-PolicyStore PersistentStore', script)
        self.assertIn('$rule.EnforcementStatus', script)
        self.assertEqual(script.count('\nCheck-Environment\n'), 2)
        self.assertNotIn('Remove-NetFirewallRule', script)
        self.assertNotIn('Set-NetFirewallProfile', script)
        self.assertNotIn('ClaudeGuard_Block', script)

    def test_nonzero_status_never_counts_as_success(self):
        self.run.return_value.returncode = 5
        with self.assertRaisesRegex(network_isolation.IsolationError, '5'):
            network_isolation.install_nonloopback_blocks([BINARY])

    def test_bad_or_partial_readback_is_rejected(self):
        for output in ('', 'not json', '{}', '{"verified":[]}',
                       '{"verified":["wrong"]}', 'null'):
            with self.subTest(output=output):
                self.run.return_value.stdout = output
                with self.assertRaises(network_isolation.IsolationError):
                    network_isolation.install_nonloopback_blocks([BINARY])

    def test_timeout_and_execution_error_are_rejected(self):
        for error in (OSError('denied'), subprocess.TimeoutExpired('ps', 60)):
            with self.subTest(error=error):
                self.run.side_effect = error
                with self.assertRaises(network_isolation.IsolationError):
                    network_isolation.install_nonloopback_blocks([BINARY])

    def test_missing_binary_does_not_run_commands(self):
        self.isfile.return_value = False
        with self.assertRaises(network_isolation.IsolationError):
            network_isolation.install_nonloopback_blocks([BINARY])
        self.run.assert_not_called()

    def test_unsupported_os_does_not_run_commands(self):
        with patch.object(network_isolation.os, 'name', 'posix'):
            with self.assertRaises(network_isolation.IsolationError):
                network_isolation.install_nonloopback_blocks([BINARY])
        self.run.assert_not_called()

    def test_encoded_payload_preserves_path_without_shell_interpolation(self):
        binary = r"C:\Claude's $app\Claude.exe"
        rules = network_isolation.plan_nonloopback_blocks([binary])
        self.run.return_value.stdout = json.dumps({
            'verified': [rule.name for rule in rules]})
        network_isolation.install_nonloopback_blocks([binary])
        script = base64.b64decode(
            self.run.call_args.args[0][-1]).decode('utf-16-le')
        self.assertNotIn(binary, script)
        payload = script.split("FromBase64String('")[1].split("')")[0]
        self.assertEqual(json.loads(base64.b64decode(payload))[0]['program'],
                         binary.lower())


if __name__ == '__main__':
    unittest.main()
