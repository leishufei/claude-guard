"""Claude Desktop lifecycle, firewall traffic cut-off, and environment guard."""

import ctypes
import os
import queue
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

import psutil

import network_isolation
import risk_check
import win32util
from clash_proxy import ClashProxySwitch
from region_core import RegionProfile, RegionService, USA_TZ

FIREWALL_RULE_PREFIX = "ClaudeGuard_Block"
COWORK_SERVICE_NAME = "CoworkVMService"
_FIREWALL_LOCK = threading.RLock()
_EMERGENCY_CUTOFF = threading.Event()

CLAUDE_EXE_NAMES = {
    "claude.exe",
    "claude-desktop.exe",
    "claude-ssh-askpass.exe",
    "claude-ssh-broker.exe",
    "claude-ssh-proxy.exe",
    "chrome-native-host.exe",
    "claude-make-data-folder.exe",
    "cowork-svc.exe",
}

WM_MOUSEMOVE = 0x0200


@dataclass
class ClaudeStatus:
    running: bool = False
    process_count: int = 0
    pids: list = field(default_factory=list)
    service_running: bool = False
    firewall_blocked: bool = False


def find_claude_launch_target():
    """Return (executable, working_directory) for launching Claude Desktop."""
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    alias = os.path.join(
        local_app_data, "Microsoft", "WindowsApps", "claude-desktop.exe")
    packages = _find_registered_claude_packages()
    if packages:
        msix_exes = _find_msix_executables(packages)
        if len(packages) != 1 or not local_app_data or not os.path.isfile(alias):
            raise RuntimeError("Claude 应用执行别名缺失或包注册不唯一，已拒绝启动。")
        working_dir = _verify_msix_launch_alias(packages[0], msix_exes)
        return alias, working_dir

    candidates = [
        os.path.join(local_app_data, "AnthropicClaude", "claude.exe"),
        os.path.join(local_app_data, "Programs", "Claude", "Claude.exe"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate, os.path.dirname(candidate)

    if os.path.isfile(alias):
        raise RuntimeError("仅找到应用执行别名，无法确认实际二进制与代理参数，已拒绝启动。")

    raise RuntimeError("未找到 Claude Desktop 安装路径，请确认已安装 Claude Desktop。")


def _find_registered_claude_packages():
    """Read and validate registered Claude package identities and directories."""
    import json
    import re

    powershell = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32",
        "WindowsPowerShell", "v1.0", "powershell.exe")
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "ConvertTo-Json -Compress -InputObject @(Get-AppxPackage -Name Claude "
        "-ErrorAction Stop | Select-Object Name,PackageFullName,"
        "PackageFamilyName,InstallLocation)")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError("Claude Appx 注册信息查询失败。")
        packages = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise RuntimeError("无法读取 Claude Appx 注册信息。") from error
    if not isinstance(packages, list):
        raise RuntimeError("Claude Appx 注册信息格式无效。")

    for package in packages:
        if not isinstance(package, dict):
            raise RuntimeError("Claude Appx 注册信息格式无效。")
        location = package.get("InstallLocation")
        full_name = package.get("PackageFullName")
        if (package.get("Name") != "Claude"
                or package.get("PackageFamilyName") != "Claude_pzs8sxrjxfjjc"
                or not isinstance(full_name, str)
                or not re.fullmatch(
                    r"Claude_\d+\.\d+\.\d+\.\d+_(x64|x86|arm64|neutral)_"
                    r"[^_]*_pzs8sxrjxfjjc", full_name)
                or not isinstance(location, str)
                or not re.match(r"^[a-zA-Z]:[\\/]", location)
                or ".." in location.replace("/", "\\").split("\\")
                or os.path.basename(location).lower() != full_name.lower()
                or not os.path.isdir(location)):
            raise RuntimeError("Claude Appx 安装目录或包身份无效。")
    return packages


def _verify_msix_launch_alias(package, executables):
    """Verify the alias maps to the discovered package's actual main binary."""
    location = package["InstallLocation"]
    manifest = os.path.join(location, "AppxManifest.xml")
    root = os.path.realpath(location)
    if os.path.commonpath([root, os.path.realpath(manifest)]) != root:
        raise RuntimeError("Claude manifest 指向安装目录之外，已拒绝启动。")
    try:
        document = ET.parse(manifest).getroot()
    except (OSError, ET.ParseError) as error:
        raise RuntimeError("无法验证 Claude 应用执行别名 manifest。") from error
    ns = {
        "f": "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
        "uap5": "http://schemas.microsoft.com/appx/manifest/uap/windows10/5",
    }
    identity = document.find("f:Identity", ns)
    parts = package["PackageFullName"].split("_")
    if (identity is None or identity.get("Name") != package["Name"]
            or identity.get("Version") != parts[1]
            or identity.get("ProcessorArchitecture") != parts[2]):
        raise RuntimeError("Claude manifest 与已验证包身份不符。")
    known = {os.path.normcase(os.path.realpath(path)) for path in executables}
    for application in document.findall("f:Applications/f:Application", ns):
        if application.get("Id") != "Claude":
            continue
        for extension in application.findall("f:Extensions/uap5:Extension", ns):
            if extension.get("Category") != "windows.appExecutionAlias":
                continue
            aliases = extension.findall(
                "uap5:AppExecutionAlias/uap5:ExecutionAlias", ns)
            if not any(item.get("Alias") == "claude-desktop.exe" for item in aliases):
                continue
            executable = extension.get("Executable", application.get("Executable", ""))
            path = os.path.realpath(os.path.join(location, executable))
            app_path = os.path.realpath(os.path.join(
                location, application.get("Executable", "")))
            if (os.path.normcase(path) not in known
                    or os.path.normcase(path) != os.path.normcase(app_path)
                    or os.path.basename(path).lower() != "claude.exe"):
                raise RuntimeError("Claude 应用执行别名未映射到已发现的主程序。")
            return os.path.dirname(path)
    raise RuntimeError("Claude manifest 未注册预期应用执行别名，已拒绝启动。")


def _find_msix_executables(packages=None):
    """Discover registered Claude packages without listing WindowsApps itself."""
    if packages is None:
        packages = _find_registered_claude_packages()

    def raise_walk_error(error):
        raise error

    found = []
    for package in packages:
        location = package["InstallLocation"]
        root = os.path.realpath(location)
        package_exes = []
        try:
            for directory, subdirs, filenames in os.walk(
                    location, onerror=raise_walk_error):
                for name in subdirs + filenames:
                    path = os.path.join(directory, name)
                    resolved = os.path.realpath(path)
                    if os.path.commonpath([root, resolved]) != root:
                        raise RuntimeError("Claude 包内路径指向安装目录之外。")
                    if name in subdirs and os.path.islink(path):
                        raise RuntimeError("Claude 包含无法完整枚举的链接目录。")
                for name in filenames:
                    if name.lower().endswith(".exe"):
                        path = os.path.abspath(os.path.join(directory, name))
                        if not os.path.isfile(path):
                            raise RuntimeError("Claude 二进制文件不存在。")
                        package_exes.append(path)
        except OSError as error:
            raise RuntimeError("无法完整枚举 Claude 安装目录。") from error
        if not any(os.path.basename(path).lower() == "claude.exe"
                   for path in package_exes):
            raise RuntimeError("Claude 包缺少实际主程序。")
        found.extend(package_exes)
    return sorted(set(found), key=str.lower)


def find_all_claude_binaries():
    """Return all Claude Desktop binary paths for firewall rules."""
    binaries = []
    for path in _find_msix_executables():
        if path not in binaries:
            binaries.append(path)
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    for sub in (
        os.path.join(local_app_data, "AnthropicClaude", "claude.exe"),
        os.path.join(local_app_data, "Programs", "Claude", "Claude.exe"),
    ):
        if os.path.isfile(sub):
            abspath = os.path.abspath(sub)
            if abspath not in binaries:
                binaries.append(abspath)
    return binaries


def _is_claude_desktop_process(proc_info, current_pid):
    pid = proc_info.get("pid")
    if not pid or pid == current_pid:
        return False
    name = (proc_info.get("name") or "").lower()
    exe = (proc_info.get("exe") or "").lower()
    if "claudeguard" in name or "claudeguard" in exe:
        return False
    if "anthropic.claudecode" in exe or "claude-code" in exe:
        return False
    if name in CLAUDE_EXE_NAMES:
        if name == "claude.exe":
            if (not exe
                    or "windowsapps\\claude_" in exe
                    or "anthropicclaude" in exe
                    or "programs\\claude" in exe):
                return True
            return False
        return True
    if "windowsapps\\claude_" in exe:
        return True
    return False


def list_claude_processes(include_children=True):
    """Return list of psutil.Process objects belonging to Claude Desktop."""
    current_pid = os.getpid()
    try:
        sid = win32util.current_sid()
    except Exception:
        sid = None

    snapshot = win32util.snapshot_processes()
    children_by_ppid = {}
    if include_children:
        for pid, _name, ppid in snapshot:
            if pid and pid != current_pid:
                children_by_ppid.setdefault(ppid, []).append(pid)

    roots = {}
    for pid, name, _ppid in snapshot:
        if pid <= 4 or pid == current_pid:
            continue
        name_lower = (name or "").lower()
        if "claudeguard" in name_lower:
            continue
        try:
            exe = win32util.process_image_path(pid)
        except OSError:
            exe = ""
        if not _is_claude_desktop_process(
                {"pid": pid, "name": name, "exe": exe}, current_pid):
            continue
        if name_lower != "cowork-svc.exe" and sid is not None:
            try:
                if win32util.process_sid(pid) != sid:
                    continue
            except OSError:
                pass
        try:
            roots[pid] = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue

    if not include_children or not roots:
        return list(roots.values())

    collected = dict(roots)
    for root_pid, root_proc in list(roots.items()):
        try:
            root_created = root_proc.create_time()
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            root_created = None
        pending = list(children_by_ppid.get(root_pid, ()))
        while pending:
            child_pid = pending.pop()
            if child_pid == current_pid or child_pid in collected:
                continue
            try:
                child = psutil.Process(child_pid)
                if root_created is not None and child.create_time() < root_created:
                    continue
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                continue
            collected[child_pid] = child
            pending.extend(children_by_ppid.get(child_pid, ()))
    return list(collected.values())


def _run_system(arguments, timeout=4.0):
    return subprocess.run(
        arguments, capture_output=True, text=True, errors="replace",
        timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)


def is_cowork_service_running():
    try:
        return bool(win32util.is_service_running(COWORK_SERVICE_NAME))
    except Exception:
        return False


def stop_cowork_service():
    try:
        if not is_cowork_service_running():
            return
        _run_system(["sc.exe", "stop", COWORK_SERVICE_NAME], timeout=5.0)
    except Exception:
        pass


def is_traffic_blocked():
    try:
        result = _run_system(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={FIREWALL_RULE_PREFIX}"],
            timeout=3.0)
        output = result.stdout or ""
        return result.returncode == 0 and FIREWALL_RULE_PREFIX in output
    except Exception:
        return False


def block_claude_traffic():
    """Add Windows Firewall outbound block rules for all Claude Desktop binaries."""
    with _FIREWALL_LOCK:
        try:
            binaries = find_all_claude_binaries()
        except Exception:
            return False
        if not binaries:
            return False
        succeeded = True
        for binary in binaries:
            try:
                result = _run_system(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={FIREWALL_RULE_PREFIX}",
                     "dir=out", "action=block",
                     f"program={binary}", "enable=yes", "profile=any"],
                    timeout=4.0)
                if result.returncode != 0:
                    succeeded = False
            except Exception:
                succeeded = False
        return succeeded


def allow_claude_traffic():
    """Remove Windows Firewall outbound block rules for Claude Desktop."""
    # Never queue an unlock behind an in-flight block operation.
    if not _FIREWALL_LOCK.acquire(blocking=False):
        return False
    try:
        if _EMERGENCY_CUTOFF.is_set():
            return False
        result = _run_system(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={FIREWALL_RULE_PREFIX}"],
            timeout=4.0)
        return result.returncode == 0
    except Exception:
        return False
    finally:
        _FIREWALL_LOCK.release()


def _refresh_tray_icons():
    """Sweep mouse move events across notification area to purge ghost icons."""
    try:
        for class_name in ("Shell_TrayWnd", "NotifyIconOverflowWindow"):
            hwnd = win32util.user32.FindWindowW(class_name, None)
            if not hwnd:
                continue
            win32util.user32.PostMessageW(hwnd, WM_MOUSEMOVE, 0, 0)
    except Exception:
        pass


def close_claude_desktop(graceful=True, block_network=True, progress=None):
    """Thoroughly close Claude Desktop, its child processes, and service."""
    import protected_session
    protected_session.close_gate("正在关闭 Claude")
    firewall_ok = block_claude_traffic() if block_network else True
    if not firewall_ok:
        graceful = False
    if progress:
        try:
            progress("正在关闭 Claude Desktop 进程与后台服务…")
        except Exception:
            pass

    procs = list_claude_processes(include_children=True)
    if graceful and procs:
        pids = {p.pid for p in procs}
        try:
            for handle, pid in win32util.enum_visible_windows():
                if pid in pids:
                    win32util.post_close(handle)
        except Exception:
            pass
        deadline = time.monotonic() + 1.2
        while time.monotonic() < deadline:
            if not list_claude_processes(include_children=False):
                break
            time.sleep(0.15)

    procs = list_claude_processes(include_children=True)
    if graceful and procs:
        for proc in procs:
            try:
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            if not list_claude_processes(include_children=True):
                break
            time.sleep(0.1)

    survivors = list_claude_processes(include_children=True)
    for proc in survivors:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    stop_cowork_service()

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        remaining = list_claude_processes(include_children=False)
        if not remaining:
            break
        for proc in remaining:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        time.sleep(0.1)

    _refresh_tray_icons()
    remaining = list_claude_processes(include_children=False)
    if remaining:
        raise RuntimeError(
            "仍有 {} 个 Claude 进程未能结束，请检查权限后重试。".format(
                len(remaining)))
    protected_session.stop()
    if not firewall_ok:
        raise RuntimeError("未能完整添加 Claude 防火墙阻止规则，已尝试终止进程。")
    return True


def cut_off_claude_traffic(reason=""):
    """Emergency kill switch: immediately kill Claude and block outbound traffic."""
    # Signal an in-flight launch before waiting for its final critical section.
    _EMERGENCY_CUTOFF.set()
    import protected_session
    gate_error = None
    try:
        protected_session.close_gate(reason)
    except Exception as error:
        gate_error = error
    procs = list_claude_processes(include_children=True)
    for proc in procs:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    revocation_error = None
    try:
        network_isolation.revoke_proxy_access()
    except Exception as error:
        revocation_error = error
    with _FIREWALL_LOCK:
        _EMERGENCY_CUTOFF.set()
        firewall_ok = block_claude_traffic()
        for proc in list_claude_processes(include_children=True):
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        stop_cowork_service()
        _refresh_tray_icons()
        if revocation_error is not None:
            raise RuntimeError("代理放行撤销未确认，已执行后备封锁与进程终止。") from revocation_error
        if gate_error is not None:
            raise RuntimeError("代理网关关闭未确认，已执行后备封锁与进程终止。") from gate_error
        if not firewall_ok:
            raise RuntimeError("紧急封锁规则添加失败，已尝试终止 Claude 进程与服务。")
        remaining = list_claude_processes(include_children=True)
        if remaining:
            psutil.wait_procs(remaining, timeout=0.3)
            if list_claude_processes(include_children=True):
                raise RuntimeError("仍有 Claude 进程未退出，网关保持关闭，请检查进程权限。")
        return len(procs)


def get_claude_status(check_firewall=False):
    procs = list_claude_processes(include_children=False)
    svc = is_cowork_service_running()
    blocked = is_traffic_blocked() if check_firewall else False
    return ClaudeStatus(
        running=bool(procs),
        process_count=len(procs),
        pids=[p.pid for p in procs],
        service_running=svc,
        firewall_blocked=blocked,
    )


def _classify_process_role(name, cmdline_text):
    lower = name.lower()
    if lower in ("claude.exe", "claude-desktop.exe"):
        if "--type=renderer" in cmdline_text:
            return "渲染进程"
        if "--type=gpu-process" in cmdline_text:
            return "GPU 进程"
        if "--type=" in cmdline_text:
            return "工作子进程"
        return "主进程"
    if lower in ("claude-ssh-proxy.exe", "claude-ssh-broker.exe",
                 "claude-ssh-askpass.exe"):
        return "SSH 辅助"
    if lower == "chrome-native-host.exe":
        return "浏览器桥接"
    if lower == "cowork-svc.exe":
        return "VM 后台服务"
    return "MCP / 子进程"


def inspect_claude_runtime(processes=None):
    """Return detailed snapshot of running Claude processes and services."""
    procs = (list(processes) if processes is not None
             else list_claude_processes(include_children=True))
    details = []
    for proc in procs:
        try:
            with proc.oneshot():
                name = proc.name()
                exe = ""
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                mem_mb = 0.0
                try:
                    mem_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                cmdline = ""
                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                role = _classify_process_role(name, cmdline)
                details.append({
                    "pid": proc.pid,
                    "name": name,
                    "role": role,
                    "memory_mb": mem_mb,
                    "exe": exe,
                })
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue
    details.sort(key=lambda item: (0 if item["role"] == "主进程" else 1,
                                   item["name"].lower(), item["pid"]))
    return {
        "processes": details,
        "service_running": is_cowork_service_running(),
        "firewall_blocked": is_traffic_blocked(),
    }


def validate_prelaunch_report(report):
    """Validate that pre-launch checks passed (IP, region, timezone/language)."""
    if (not isinstance(report, dict)
            or not isinstance(report.get("items"), list)
            or not report["items"]
            or not all(isinstance(entry, dict) for entry in report["items"])):
        return False, "安全检测报告无效，已拦截启动。"
    failed = []
    stun_pending = False
    for entry in report["items"]:
        if (entry.get("name") == risk_check.ITEM_NAMES[7]
                and entry.get("status") == "unknown"):
            stun_pending = True
            continue
        if entry.get("status") != "pass":
            failed.append("{}（{}）".format(
                entry.get("name", "未知项"), entry.get("detail", "未通过")))
    if failed:
        return False, "启动前检查未通过：" + "；".join(failed[:3])
    if stun_pending:
        if not any(entry.get("status") == "pass" for entry in report["items"]):
            return False, "安全检测报告缺少已通过的检查，已拦截启动。"
        return True, "启动前必要检查通过；STUN 出口待确认，仅作提示"
    return True, "启动前安全检查全部通过"


def begin_safe_launch():
    """Clear an old emergency latch for an explicitly requested new launch."""
    if not _FIREWALL_LOCK.acquire(blocking=False):
        raise RuntimeError("紧急保护或防火墙操作正在执行，已取消启动。")
    try:
        _EMERGENCY_CUTOFF.clear()
    finally:
        _FIREWALL_LOCK.release()


def launch_claude_desktop(binaries=None):
    """Unblock firewall and launch Claude Desktop at standard user integrity."""
    executable, working_dir = find_claude_launch_target()
    with _FIREWALL_LOCK:
        if _EMERGENCY_CUTOFF.is_set():
            raise RuntimeError("紧急保护已锁存，请重新发起安全启动。")
        import protected_session
        proxy_port = protected_session.active_port()
        resolved_binaries = (find_all_claude_binaries()
                             if binaries is None else binaries)
        network_isolation.ensure_proxy_isolation(resolved_binaries, proxy_port)
        if not allow_claude_traffic():
            raise RuntimeError("无法安全解除 Claude 防火墙封锁，已取消启动。")
        if _EMERGENCY_CUTOFF.is_set():
            raise RuntimeError("启动期间触发紧急保护，已取消启动。")
        win32util.start_process_with_explorer_token(
            executable, network_isolation.build_launch_args(proxy_port),
            working_dir)
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if list_claude_processes(include_children=False):
            return True
        time.sleep(0.2)
    return True


class EnvironmentMonitor:
    """Monitors local environment (timezone, language, Clash) and exit IP."""

    def __init__(self, region_service=None, clash_switch=None, proxy_port=None):
        self.region_service = region_service or RegionService()
        self.clash_switch = clash_switch or ClashProxySwitch()
        self.proxy_port = (risk_check._clash_mixed_port()
                           if proxy_port is None else proxy_port)
        self.baseline_ip = ""
        self._session_pool = risk_check.ProxyConnectionPool()

    def set_baseline_ip(self, ip):
        self.baseline_ip = risk_check.public_ipv4(ip) if ip else ""
        if not self.baseline_ip:
            self._session_pool.close_all()

    def check_local(self):
        """Check timezone, Edge web language, and Clash TUN locally."""
        try:
            state = self.region_service.read()
        except Exception as error:
            return False, "读取系统时区/Edge 网页语言状态失败：{}".format(error)

        if state.timezone_id.lower() != USA_TZ.lower():
            return False, "系统时区已变为 {}".format(state.timezone_id)

        effective_lang = (state.languages or state.browser_languages or "").lower()
        if not effective_lang.startswith("en"):
            return False, "Edge 网页首选语言已变为 {}".format(
                state.languages or state.browser_languages or "未知")

        ok, reason = self.clash_switch.verify_usa_active()
        if not ok:
            return False, reason

        return True, "洛杉矶时区 · 英语网页语言 · {}".format(reason)

    def check_remote_ip(self, deadline=None):
        """Compare the same explicit proxy route with the launch baseline."""
        deadline = min(deadline or float("inf"), time.monotonic() + 8.0)
        settings = risk_check.load_settings()
        mode = str(settings.get("staticIpMode") or "").lower()
        _china_expected, claude_expected = risk_check.static_targets(settings)
        expected = (self.baseline_ip if mode == "auto"
                    else claude_expected or self.baseline_ip)
        if not expected:
            return False, "无法确认启动基准 IP（{}）".format(
                settings.get("targetNode") or "未指定")

        # Finish endpoint timeouts before the supervisor's outer deadline.
        # A healthy peer must still be collected when one endpoint stalls.
        now = time.monotonic()
        endpoint_deadline = now + max(0.0, deadline - now) * .9
        client = risk_check.HttpClient(
            total_timeout=8.0, proxy_port=self.proxy_port,
            deadline=endpoint_deadline, session_pool=self._session_pool)
        results = queue.Queue()

        def probe(url):
            try:
                results.put(risk_check.fetch_trace_ip(client, url))
            except Exception:
                results.put("")

        for url in (risk_check.CLAUDE_TRACE_URL,
                    risk_check.CLOUDFLARE_TRACE_URL):
            threading.Thread(target=probe, args=(url,), daemon=True).start()
        confirmed = False
        for _ in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, "无法确认出口 IP：远端检查超时"
            try:
                observed = results.get(timeout=remaining)
            except queue.Empty:
                return False, "无法确认出口 IP：远端检查超时"
            if observed:
                if observed != expected:
                    return False, "出口 IP 异常变化：当前 {}（期望 {}）".format(
                        observed, expected)
                confirmed = True
        if time.monotonic() >= deadline:
            return False, "无法确认出口 IP：远端检查超时"
        if confirmed:
            return True, "出口 IP 正常（{}）".format(expected)
        return False, "无法确认出口 IP，疑似代理断流"
