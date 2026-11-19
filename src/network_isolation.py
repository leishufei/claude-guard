"""Proxy isolation for explicitly discovered Windows executable paths.

The native WFP backend keeps persistent IPv4/IPv6 ALE connect/receive denies and
permits only TCP to 127.0.0.1 at the caller's dedicated gateway port. Permits
live in this process's dynamic WFP session; an independent guardian must own
that process/session if enforcement should outlive the launcher UI.

The caller must verify the gateway listener, stop protected processes before
policy transitions, and kill them on errors or gateway failure. Loopback
forwarding, port takeover, other executables, cross-account brokers, and Cowork
VM traffic are not covered by this path-scoped boundary. Persistent filters
also deny inbound accepts without exceptions, including local Claude bridges.
Failures must be recorded by the caller; no inbound bypass is installed.
Persistent filters are not boot-time filters. API readback does not prove
zero-packet revocation of established flows; packet-level validation is needed.

The legacy nonloopback Firewall helper is optional defense in depth. Its rules
are independent of the WFP baseline and are never launch authorization.
"""

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import ntpath
import os
import subprocess
import threading

import wfp_native


PROXY_RULE_PREFIX = "ClaudeGuard_ProxyIsolation_v1_"
NON_LOOPBACK_RANGES = (
    "0.0.0.0-126.255.255.255",
    "128.0.0.0-255.255.255.255",
    "::-::",
    "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
)
_backend = None
_backend_lock = threading.RLock()


class IsolationError(RuntimeError):
    """Isolation is unavailable, incomplete, or could not be verified."""


@dataclass(frozen=True)
class BlockRule:
    """One persistent outbound block, not launch authorization."""

    name: str
    program: str
    remote_addresses: tuple = NON_LOOPBACK_RANGES


def _validate_port(proxy_port):
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        raise IsolationError("代理网关 HTTP 端口必须为 1–65535 的整数。")


def build_launch_args(proxy_port):
    """Return Electron routing hints for an explicit IPv4 loopback proxy.

    The caller must independently verify the gateway HTTP listener and owner.
    A SOCKS-only port is not a suitable endpoint.
    Do not append conflicting proxy switches, PAC, or a DIRECT fallback.
    """
    _validate_port(proxy_port)
    return [
        f"--proxy-server=http://127.0.0.1:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
    ]


def plan_nonloopback_blocks(binaries):
    """Return deterministic rules for explicit local Windows executable paths.

    No file discovery is performed. The caller owns complete binary discovery;
    an alias, helper omission, or new install path cannot be repaired by this
    plan. Existing version rules must remain installed during upgrades.
    """
    if isinstance(binaries, (str, bytes)):
        raise IsolationError("必须提供 Claude 二进制路径列表。")
    programs = set()
    for binary in binaries:
        if not isinstance(binary, str) or any(
                char in binary for char in ('\x00', '\r', '\n', '*', '?', '%')):
            raise IsolationError("Claude 二进制路径无效。")
        drive, tail = ntpath.splitdrive(binary)
        if (len(drive) != 2 or drive[1] != ':' or not drive[0].isalpha()
                or not tail.startswith(('\\', '/')) or ':' in tail):
            raise IsolationError("Claude 二进制必须使用本地完整路径。")
        program = ntpath.normpath(binary).lower()
        if not program.endswith('.exe'):
            raise IsolationError("Claude 二进制必须为 exe 文件。")
        programs.add(program)
    if not programs:
        raise IsolationError("未识别到 Claude 二进制，拒绝空隔离计划。")
    return tuple(BlockRule(
        PROXY_RULE_PREFIX + hashlib.sha256(
            program.encode('utf-8')).hexdigest(), program)
                 for program in sorted(programs))


def ensure_proxy_isolation(binaries, proxy_port):
    """Install and verify path-scoped WFP isolation; return verified rule keys.

    The supplied port belongs to the dedicated gateway, not necessarily Clash.
    The caller must keep this process alive to retain the dynamic permits.
    Any failure revokes current permits and raises IsolationError. Previously
    committed baseline rules are retained, including older executable paths.
    """
    global _backend
    with _backend_lock:
        try:
            rules = plan_nonloopback_blocks(binaries)
            _validate_port(proxy_port)
            if _backend is None:
                _backend = wfp_native.WfpBackend()
            return _backend.ensure(tuple(rule.program for rule in rules),
                                   proxy_port)
        except Exception as error:
            revoke_proxy_access()
            if isinstance(error, IsolationError):
                raise
            raise IsolationError(
                "WFP 隔离安装或回读失败；禁止启动并终止受保护进程：" + str(error)
            ) from error


def revoke_proxy_access():
    """Idempotently revoke all dynamic permits owned by this process.

    A close failure raises IsolationError and retains the handle for retry.
    No persistent filters are deleted. The caller must terminate protected
    processes immediately; this API is not a flow-teardown acknowledgement.
    """
    with _backend_lock:
        if _backend is not None:
            try:
                _backend.revoke_proxy_access()
            except Exception as error:
                raise IsolationError(
                    "WFP 动态许可撤销失败；必须终止受保护进程：" + str(error)
                ) from error


def remove_lockdown_preserving_proxy_isolation(binaries, proxy_port):
    """Verify the WFP baseline and permit, without deleting permanent rules.

    This function does not remove legacy emergency firewall rules. The caller
    may remove its separate emergency lockdown only after this call succeeds.
    """
    return ensure_proxy_isolation(binaries, proxy_port)


def install_nonloopback_blocks(binaries):
    """Install defense-in-depth blocks; never treat return as launch approval.

    Requires Windows and administrative privileges. Partial installation on
    error is deliberately retained. No rules are removed or weakened. Profiles
    are checked before/after, but subsequent disable remains an explicit gap.

    Returns:
        The installed plan, solely for diagnostics.

    Raises:
        IsolationError: Any installation, policy, or readback check fails.
    """
    rules = plan_nonloopback_blocks(binaries)
    if os.name != 'nt':
        raise IsolationError("仅支持 Windows Firewall。")
    for rule in rules:
        if not os.path.isfile(rule.program):
            raise IsolationError("Claude 二进制不存在或无法读取。")
    payload = base64.b64encode(json.dumps(
        [asdict(rule) for rule in rules]).encode('utf-8')).decode('ascii')
    script = _INSTALL_SCRIPT.replace('__PAYLOAD__', payload)
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    executable = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                              'System32', 'WindowsPowerShell', 'v1.0',
                              'powershell.exe')
    try:
        result = subprocess.run(
            [executable, '-NoLogo', '-NoProfile', '-NonInteractive',
             '-EncodedCommand', encoded], capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=60,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.SubprocessError) as error:
        raise IsolationError("安装隔离规则失败；保留已安装规则及紧急封锁。") from error
    if result.returncode != 0:
        raise IsolationError("防火墙命令失败（返回码 {}）；禁止启动。".format(
            result.returncode))
    try:
        evidence = json.loads(result.stdout)
    except (ValueError, TypeError) as error:
        raise IsolationError("防火墙规则回读结果无效。") from error
    if evidence != {'verified': [rule.name for rule in rules]}:
        raise IsolationError("防火墙规则回读不完整；禁止启动。")
    return rules


_INSTALL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Check-Environment {
    foreach ($service in @('BFE', 'MpsSvc')) {
        if ((Get-Service -Name $service).Status -ne 'Running') {
            throw 'Firewall service is not running'
        }
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3) { throw 'Incomplete firewall profiles' }
    foreach ($profile in $profiles) {
        if ($profile.Enabled -ne 'True' -or
            $profile.AllowLocalFirewallRules -eq 'False') {
            throw 'Firewall profile disabled or local policy suppressed'
        }
    }
}
Check-Environment
$plans = @([Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json)
$existing = @(Get-NetFirewallRule -PolicyStore PersistentStore)
foreach ($plan in $plans) {
    if (@($existing | Where-Object Name -EQ $plan.name).Count -eq 0) {
        New-NetFirewallRule -PolicyStore PersistentStore -Name $plan.name `
            -DisplayName $plan.name -Program $plan.program -Direction Outbound `
            -Action Block -Enabled True -Profile Any -Protocol Any `
            -RemoteAddress $plan.remote_addresses -ErrorAction Stop | Out-Null
    }
}
$verified = @()
foreach ($plan in $plans) {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $plan.name)
    if ($rules.Count -ne 1) { throw 'Missing or duplicate effective rule' }
    $rule = $rules[0]
    if ($rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or
        $rule.Action -ne 'Block' -or $rule.Profile -ne 'Any' -or
        $rule.PrimaryStatus -ne 'OK' -or $rule.EnforcementStatus -ne 'Full') {
        throw 'Rule is not fully enforced'
    }
    $app = $rule | Get-NetFirewallApplicationFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    $interface = $rule | Get-NetFirewallInterfaceFilter
    $type = $rule | Get-NetFirewallInterfaceTypeFilter
    $service = $rule | Get-NetFirewallServiceFilter
    if ($app.Program -ne $plan.program -or $app.Package -ne 'Any' -or
        $port.Protocol -ne 'Any' -or $port.LocalPort -ne 'Any' -or
        $port.RemotePort -ne 'Any' -or $address.LocalAddress -ne 'Any' -or
        $interface.InterfaceAlias -ne 'Any' -or $type.InterfaceType -ne 'Any' -or
        $service.Service -ne 'Any') { throw 'Rule scope mismatch' }
    $actual = @($address.RemoteAddress | Sort-Object)
    $expected = @($plan.remote_addresses | Sort-Object)
    if (@(Compare-Object $actual $expected).Count -ne 0) {
        throw 'Remote address mismatch'
    }
    $verified += $plan.name
}
Check-Environment
@{verified = @($verified)} | ConvertTo-Json -Compress
"""
