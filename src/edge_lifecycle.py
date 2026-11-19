"""Edge process lifecycle and the full region switch workflow."""

import json
import os
import re
import time
import winreg
from dataclasses import dataclass, field

import psutil

import win32util
from region_core import (
    APPLY_MUTEX_NAME, EDGE_ROOT, PROFILE_PATTERN, RegionService,
)

EDGE_PROCESS = "msedge.exe"
EDGE_PREFERENCES = "Preferences"


@dataclass
class BrowserSession:
    was_running: bool = False
    profiles: list = field(default_factory=list)


@dataclass
class BrowserProcessInfo:
    pid: int
    create_time: float
    executable: str


def find_edge():
    candidates = []
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(
                    root,
                    r"Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe") as key:
                value, _kind = winreg.QueryValueEx(key, "")
                if isinstance(value, str) and value:
                    candidates.append(value.strip('"'))
        except OSError:
            pass
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get(
        "ProgramFiles(x86)", r"C:\Program Files (x86)")
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates.extend([
        os.path.join(program_files_x86, "Microsoft", "Edge", "Application",
                     EDGE_PROCESS),
        os.path.join(program_files, "Microsoft", "Edge", "Application",
                     EDGE_PROCESS),
        os.path.join(local_app_data, "Microsoft", "Edge", "Application",
                     EDGE_PROCESS),
    ])
    for candidate in candidates:
        if (os.path.isfile(candidate)
                and os.path.basename(candidate).lower() == EDGE_PROCESS):
            return os.path.abspath(candidate)
    raise RuntimeError("未找到可验证的 Microsoft Edge 安装，请先安装或修复 Edge。")


def is_edge_running():
    sid = win32util.current_sid()
    session = win32util.current_session_id()
    for pid, name, _ppid in win32util.snapshot_processes():
        if (name or "").lower() != EDGE_PROCESS:
            continue
        try:
            if (win32util.process_session_id(pid) == session
                    and win32util.process_sid(pid) == sid):
                return True
        except OSError:
            if psutil.pid_exists(pid):
                raise
    return False


class WindowsBrowserLifecycle:
    def __init__(self):
        self.sid = win32util.current_sid()
        self.session_id = win32util.current_session_id()
        self.executable = find_edge()
        self.user_data_root = os.path.abspath(EDGE_ROOT)
        self.checked_arguments = {}

    def processes(self):
        result = []
        for process in psutil.process_iter():
            try:
                info = process.as_dict(attrs=["pid", "name"])
                if (info["name"] or "").lower() != EDGE_PROCESS:
                    continue
                if "exe" not in info or "create_time" not in info:
                    info.update(process.as_dict(attrs=["exe", "create_time"]))
                pid = info["pid"]
                if (win32util.process_session_id(pid) != self.session_id
                        or win32util.process_sid(pid) != self.sid):
                    continue
                executable = info["exe"] or win32util.process_image_path(pid)
                if executable.lower() != self.executable.lower():
                    raise RuntimeError(
                        "检测到当前用户运行了其他路径的 Edge，请手动退出该浏览器后重试。")
                create_time = info["create_time"]
                self._check_arguments(process, pid, create_time)
                result.append(BrowserProcessInfo(pid, create_time, executable))
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied as error:
                if psutil.pid_exists(process.pid):
                    raise RuntimeError(
                        "无法核对 Edge 进程身份，请手动完全退出 Edge 后重试。") from error
            except (FileNotFoundError, ProcessLookupError):
                continue
        return result

    def windows(self, processes):
        identifiers = {process.pid: process for process in processes}
        result = []
        for handle, pid in win32util.enum_visible_windows():
            process = identifiers.get(pid)
            if process is not None:
                result.append((handle, process))
        return result

    def active_profiles(self):
        return read_active_profiles(self.user_data_root)

    def close_for_switch(self, progress=None):
        initial = self.processes()
        session = BrowserSession(bool(initial), [])
        if not session.was_running:
            return session
        session.profiles = self.active_profiles()
        original_windows = self.windows(initial)
        stopped_background = False
        deadline = time.monotonic() + 19.0
        try:
            _notify(progress,
                    "正在关闭 Edge，请处理浏览器中尚未保存的页面或退出提示…")
            for window in original_windows:
                self._request_close(window)
            while self.windows(self.processes()):
                if time.monotonic() >= deadline - 3.0:
                    raise RuntimeError(
                        "Edge 仍有窗口或退出提示，请先处理后重试。")
                time.sleep(0.2)
            grace = min(deadline - 2.0, time.monotonic() + 1.5)
            while self.processes() and time.monotonic() < grace:
                time.sleep(0.15)
            remaining = self.processes()
            if self.windows(remaining):
                raise RuntimeError(
                    "Edge 在退出过程中重新打开了窗口，请先处理后重试。")
            for process in remaining:
                stopped_background = True
                self._stop_background(process)
            while self.processes():
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Edge 后台进程未能在限定时间内退出，请完全退出 Edge 后重试。")
                time.sleep(0.1)
            return session
        except Exception as error:
            try:
                current = self.windows(self.processes())
            except Exception:
                current = []
            current_keys = {(handle, process.pid, process.create_time)
                            for handle, process in current}
            closed_window = any(
                (handle, process.pid, process.create_time) not in current_keys
                for handle, process in original_windows)
            if closed_window or stopped_background:
                try:
                    self.restore(session)
                except Exception as restore_error:
                    raise RuntimeError(
                        "Edge 退出未完成：{} 已关闭窗口的恢复也未完成：{}".format(
                            error, restore_error)) from error
            raise RuntimeError(
                "Edge 退出未完成，尚未修改环境配置：" + str(error)) from error

    def restore(self, session):
        if session is None or not session.was_running:
            return
        failures = []
        directory = os.path.dirname(self.executable)
        for profile in session.profiles:
            try:
                win32util.start_process_with_explorer_token(
                    self.executable,
                    ["--restore-last-session",
                     "--profile-directory=" + profile],
                    directory)
            except Exception as error:
                failures.append(profile + "：" + str(error))
        if failures:
            raise RuntimeError(
                "部分 Edge 配置恢复失败：" + "；".join(failures))
        deadline = time.monotonic() + 10.0
        while not self.windows(self.processes()):
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "已请求恢复 Edge，但未检测到浏览器启动窗口。请从桌面手动打开 Edge 并恢复上次会话。")
            time.sleep(0.1)

    def _request_close(self, window):
        handle, expected = window
        current = next(
            (process for process in self.processes()
             if process.pid == expected.pid), None)
        if not _same_process(current, expected):
            return
        owner = win32util.wintypes.DWORD()
        win32util.user32.GetWindowThreadProcessId(
            handle, win32util.ctypes.byref(owner))
        if (owner.value == current.pid
                and win32util.user32.IsWindowVisible(handle)
                and not win32util.post_close(handle)):
            raise RuntimeError(
                "无法向 Edge 窗口发送正常退出请求，请手动关闭浏览器后重试。")

    def _stop_background(self, expected):
        try:
            process = psutil.Process(expected.pid)
        except psutil.NoSuchProcess:
            return
        try:
            if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                return
            if abs(process.create_time() - expected.create_time) > 0.01:
                raise RuntimeError("Edge 后台进程身份发生变化，已停止清理。")
            if (win32util.process_session_id(expected.pid) != self.session_id
                    or win32util.process_sid(expected.pid) != self.sid
                    or win32util.process_image_path(expected.pid).lower()
                    != expected.executable.lower()):
                raise RuntimeError("Edge 后台进程身份发生变化，已停止清理。")
            if self.windows(self.processes()):
                raise RuntimeError("Edge 仍有可见窗口，已停止清理后台进程。")
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except psutil.TimeoutExpired:
                raise RuntimeError("Edge 后台进程未能退出，请手动退出后重试。")
        except psutil.NoSuchProcess:
            return

    def _check_arguments(self, process, pid, create_time):
        key = (pid, round(create_time, 3))
        if key in self.checked_arguments:
            return
        try:
            command_line = process.cmdline()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return
        self._validate_user_data_directory(command_line)
        self.checked_arguments[key] = True

    def _validate_user_data_directory(self, arguments):
        option = "--user-data-dir"
        index = 1
        while index < len(arguments):
            argument = arguments[index]
            directory = None
            if argument.lower().startswith(option + "="):
                directory = argument[len(option) + 1:]
            elif argument.lower() == option:
                if (index + 1 >= len(arguments)
                        or arguments[index + 1].startswith("--")):
                    raise RuntimeError(
                        "Edge 用户数据目录参数缺少有效路径，已停止自动退出。")
                index += 1
                directory = arguments[index]
            if directory is not None:
                if not directory.strip():
                    raise RuntimeError(
                        "Edge 用户数据目录参数缺少有效路径，已停止自动退出。")
                path = os.path.abspath(directory).rstrip("\\")
                expected = os.path.abspath(self.user_data_root).rstrip("\\")
                if os.path.normcase(path) != os.path.normcase(expected):
                    raise RuntimeError(
                        "检测到使用独立用户数据目录的 Edge，请先手动退出该浏览器再切换。")
            index += 1


def _same_process(first, second):
    return (first is not None
            and first.pid == second.pid
            and abs(first.create_time - second.create_time) <= 0.01
            and os.path.normcase(first.executable)
            == os.path.normcase(second.executable))


def _notify(progress, message):
    if progress:
        try:
            progress(message)
        except Exception:
            pass


def read_active_profiles(user_data_root):
    path = os.path.join(user_data_root, "Local State")
    try:
        with open(path, "rb") as file:
            state = json.loads(file.read().decode("utf-8-sig"))
    except (OSError, ValueError, RecursionError) as error:
        raise RuntimeError(
            "Edge 会话配置无法读取，已停止自动退出。请先用 Edge 修复配置。") from error
    if not isinstance(state, dict):
        raise RuntimeError("Edge 会话配置无法读取，已停止自动退出。请先用 Edge 修复配置。")
    profiles = state.get("profile")
    if not isinstance(profiles, dict):
        raise RuntimeError("无法识别 Edge 会话配置，已停止自动退出。")
    result = []
    active = profiles.get("last_active_profiles")
    if active is not None:
        if not isinstance(active, list):
            raise RuntimeError("Edge 活跃配置列表格式无效，已停止自动退出。")
        for name in active:
            _add_profile(result, name, user_data_root)
    last_used = profiles.get("last_used")
    _add_profile(result, last_used, user_data_root)
    if last_used in result:
        result.remove(last_used)
    result.append(last_used)
    return result


def _add_profile(result, name, user_data_root):
    if (not isinstance(name, str)
            or not PROFILE_PATTERN.fullmatch(name)
            or not os.path.isfile(
                os.path.join(user_data_root, name, EDGE_PREFERENCES))):
        raise RuntimeError(
            "Edge 会话包含无法识别的配置，已停止自动退出。请手动保存会话后重试。")
    if name not in result:
        result.append(name)


class ClaudeGuardWorkflow:
    def __init__(self, service=None, browser=None, proxy=None):
        self.service = service or RegionService()
        self.browser = browser or WindowsBrowserLifecycle()
        self.proxy = proxy

    def apply(self, mode, progress=None):
        handle = win32util.create_mutex(APPLY_MUTEX_NAME)
        try:
            if not win32util.acquire_mutex(handle, 0):
                raise RuntimeError("另一个环境切换正在进行，请稍后重试。")
            try:
                return self._apply_locked(mode, progress)
            finally:
                win32util.release_mutex(handle)
        finally:
            win32util.close_handle(handle)

    def _apply_locked(self, mode, progress):
        proxy_snapshot = None
        if mode == "usa" and self.proxy is not None:
            _notify(progress, "正在检查 Clash 与目标节点…")
            proxy_snapshot = self.proxy.prepare_usa()
        elif mode == "china" and self.proxy is not None:
            try:
                _notify(progress, "正在检查 Clash 状态以恢复规则模式…")
                proxy_snapshot = self.proxy.prepare_china()
            except Exception:
                proxy_snapshot = None
        browser_session = self.browser.close_for_switch(progress)
        failure = None
        proxy_applied = False
        try:
            if proxy_snapshot is not None:
                if mode == "usa":
                    _notify(progress, "正在设置 Clash 全局目标节点、关闭系统代理并开启 TUN…")
                    self.proxy.apply_usa(proxy_snapshot)
                else:
                    _notify(progress, "正在恢复 Clash 规则模式、开启系统代理并关闭 TUN…")
                    self.proxy.apply_china(proxy_snapshot)
                proxy_applied = True
            _notify(progress, "正在保存时区与 Edge 网页语言…")
            self.service.apply(mode)
        except Exception as error:
            failure = error
            if proxy_applied:
                try:
                    self.proxy.restore(proxy_snapshot)
                except Exception as rollback:
                    failure = RuntimeError(
                        "{} Clash 恢复失败：{}".format(error, rollback))
        try:
            if browser_session.was_running:
                _notify(progress, "正在以普通用户权限恢复 Edge 会话…")
            self.browser.restore(browser_session)
        except Exception as restore_error:
            if failure is None:
                prefix = "配置已保存，但 Edge 恢复未完成："
            else:
                prefix = "切换未完成：{} Edge 恢复也未完成：".format(failure)
            raise RuntimeError(prefix + str(restore_error)) from restore_error
        if failure is not None:
            raise RuntimeError(str(failure)) from failure
        return browser_session.was_running
