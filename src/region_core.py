"""Timezone, Edge language policy, and Edge preferences for the region switch."""

import json
import os
import re
import subprocess
import time
import uuid
import winreg
from dataclasses import dataclass, field

import win32util

POLICY_PATH = r"Software\Policies\Microsoft\Edge"
POLICY_NAME = "DefinePreferredLanguages"
CHINA_TZ = "China Standard Time"
USA_TZ = "Pacific Standard Time"
APPLY_MUTEX_NAME = r"Local\ClaudeGuard.Apply"
EDGE_ROOT = os.path.join(
    os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data")
PROFILE_PATTERN = re.compile(r"^(?:Default|Profile [0-9]+)$")


@dataclass(frozen=True)
class RegionProfile:
    mode: str
    name: str
    timezone_id: str
    languages: str

    @staticmethod
    def for_mode(mode):
        if mode == "china":
            return RegionProfile("china", "中国", CHINA_TZ, "zh-CN,zh")
        if mode == "usa":
            return RegionProfile("usa", "美国", USA_TZ, "en-US,en")
        raise ValueError("无效的切换模式。")


@dataclass
class RegionState:
    timezone_id: str
    languages: str
    machine_languages: str
    browser_languages: str
    browser_profile: str
    browser_is_running: bool


@dataclass
class PolicyValue:
    exists: bool
    value: object = None
    kind: int = 0


@dataclass
class BrowserSnapshot:
    profile_name: str
    languages: str
    selected_languages: str
    preferences_path: str
    original_bytes: bytes
    local_state_bytes: bytes
    written_bytes: bytes = None
    recovery_bytes: bytes = None


def _default_is_running():
    from edge_lifecycle import is_edge_running
    return is_edge_running()


def _parse_json(data):
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise RuntimeError(
            "Edge 配置 JSON 无效或超出读取限制，已停止操作。"
            "请先用 Edge 修复配置后重试。") from error
    if not isinstance(value, dict):
        raise RuntimeError(
            "Edge 配置 JSON 无效或超出读取限制，已停止操作。"
            "请先用 Edge 修复配置后重试。")
    return value


def _object_member(parent, name, create=False):
    value = parent.get(name)
    if value is not None:
        if not isinstance(value, dict):
            raise RuntimeError("Edge 配置中的 " + name + " 不是对象。")
        return value
    if not create:
        return None
    value = {}
    parent[name] = value
    return value


def _language_member(intl, name):
    if not isinstance(intl, dict) or name not in intl:
        return ""
    value = intl[name]
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RuntimeError("Edge 语言首选项 " + name + " 不是字符串。")
    return value


def _same_bytes(first, second):
    return first == second


class EdgePreferences:
    def __init__(self, user_data_root=None, is_running=None):
        self.root = os.path.abspath(user_data_root or EDGE_ROOT)
        self.is_running = is_running or _default_is_running

    def read(self):
        local_state_path = os.path.join(self.root, "Local State")
        _reject_link(local_state_path)
        with open(local_state_path, "rb") as file:
            local_state_bytes = file.read()
        state = _parse_json(local_state_bytes)
        profile = _object_member(state, "profile", False)
        last_used = profile.get("last_used") if profile else None
        if (not isinstance(last_used, str)
                or not PROFILE_PATTERN.fullmatch(last_used)):
            raise RuntimeError(
                "无法识别 Edge 上次使用的普通配置，请先打开目标 Edge 配置并完全退出后重试。")
        directory = os.path.abspath(os.path.join(self.root, last_used))
        path = os.path.abspath(os.path.join(directory, "Preferences"))
        if (os.path.normcase(os.path.dirname(directory))
                != os.path.normcase(self.root)
                or os.path.normcase(os.path.dirname(path))
                != os.path.normcase(directory)):
            raise RuntimeError("Edge 配置路径不在预期用户数据目录中，已停止操作。")
        _reject_link(directory)
        _reject_link(path)
        with open(path, "rb") as file:
            original = file.read()
        preferences = _parse_json(original)
        intl = _object_member(preferences, "intl", False)
        return BrowserSnapshot(
            profile_name=last_used,
            preferences_path=path,
            languages=_language_member(intl, "accept_languages"),
            selected_languages=_language_member(intl, "selected_languages"),
            original_bytes=original,
            local_state_bytes=local_state_bytes,
        )

    def read_language_state(self):
        snapshot = self.read()
        preferences = _parse_json(snapshot.original_bytes)
        profile = preferences.get("profile")
        profile = profile if isinstance(profile, dict) else {}
        settings = profile.get("default_content_setting_values")
        settings = settings if isinstance(settings, dict) else {}
        cookie_behavior = profile.get("cookie_behavior")
        cookies = settings.get("cookies")
        cookie_enabled = not (cookies == 2 or cookie_behavior == 3)
        return {
            "languages": _effective_languages(snapshot.languages),
            "selected_languages": snapshot.selected_languages,
            "cookie_enabled": cookie_enabled,
        }

    def write(self, snapshot, languages):
        self._ensure_unchanged(snapshot, snapshot.original_bytes)
        preferences = _parse_json(snapshot.original_bytes)
        intl = _object_member(preferences, "intl", True)
        intl["accept_languages"] = languages
        intl["selected_languages"] = languages
        updated = json.dumps(
            preferences, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if _same_bytes(updated, snapshot.original_bytes):
            return
        staging = _stage(snapshot.preferences_path, updated)
        try:
            self._ensure_unchanged(snapshot, snapshot.original_bytes)
            snapshot.written_bytes = updated
            backup = snapshot.preferences_path + ".claudeguard.bak"
            win32util.replace_file(
                snapshot.preferences_path, staging, backup)
            staging = None
            with open(backup, "rb") as file:
                replaced = file.read()
            if not _same_bytes(replaced, snapshot.original_bytes):
                snapshot.recovery_bytes = replaced
                raise RuntimeError(
                    "Edge 配置在保存时被其他程序修改，已停止并保留并发版本以供恢复。")
            if self.is_running():
                raise RuntimeError(
                    "Edge 在切换过程中启动，请完全退出 Edge 后核对配置并重试。")
            with open(snapshot.preferences_path, "rb") as file:
                if not _same_bytes(file.read(), updated):
                    raise RuntimeError(
                        "Edge 配置在保存后被其他程序修改，请完全退出 Edge 后核对配置。")
        finally:
            if staging and os.path.exists(staging):
                os.remove(staging)

    def restore(self, snapshot):
        with open(snapshot.preferences_path, "rb") as file:
            current = file.read()
        original = snapshot.recovery_bytes or snapshot.original_bytes
        if _same_bytes(current, original):
            return
        if (snapshot.written_bytes is None
                or not _same_bytes(current, snapshot.written_bytes)):
            raise RuntimeError(
                "Edge 配置已被其他程序修改，恢复操作已停止以保留其更新。原文件备份位于配置目录。")
        self._ensure_unchanged(snapshot, snapshot.written_bytes)
        staging = _stage(snapshot.preferences_path, original)
        try:
            self._ensure_unchanged(snapshot, snapshot.written_bytes)
            backup = (snapshot.preferences_path + ".claudeguard.rollback-"
                      + uuid.uuid4().hex + ".bak")
            win32util.replace_file(
                snapshot.preferences_path, staging, backup)
            staging = None
            with open(backup, "rb") as file:
                if not _same_bytes(file.read(), snapshot.written_bytes):
                    raise RuntimeError(
                        "恢复时检测到 Edge 配置并发更新，相关版本已保留在恢复备份中，请人工核对。")
        finally:
            if staging and os.path.exists(staging):
                os.remove(staging)

    def _ensure_unchanged(self, snapshot, expected):
        if self.is_running():
            raise RuntimeError(
                "请完全退出 Edge（包括后台进程）后重试，切换时需要保存浏览器首选语言。")
        current = self.read()
        if (os.path.normcase(current.preferences_path)
                != os.path.normcase(snapshot.preferences_path)
                or not _same_bytes(
                    current.local_state_bytes, snapshot.local_state_bytes)
                or not _same_bytes(current.original_bytes, expected)):
            raise RuntimeError(
                "Edge 的当前配置或首选项已变化，已停止操作以保留其他程序的更新。请刷新状态后重试。")


def _effective_languages(preferences):
    """Prefer the Edge policy; it drives navigator.languages at startup."""
    for hive, view in (
            (winreg.HKEY_CURRENT_USER, winreg.KEY_READ),
            (winreg.HKEY_LOCAL_MACHINE,
             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)):
        try:
            with winreg.OpenKey(hive, POLICY_PATH, 0, view) as key:
                value, _kind = winreg.QueryValueEx(key, POLICY_NAME)
            if isinstance(value, str) and value.strip():
                return value.strip()
        except OSError:
            pass
    return preferences


def _reject_link(path):
    if win32util.is_reparse_point(path):
        raise RuntimeError(
            "Edge 配置使用了重解析路径，已停止操作以确保只修改目标配置。")


def _stage(destination, value):
    path = destination + ".claudeguard-" + uuid.uuid4().hex + ".tmp"
    with open(path, "xb") as file:
        file.write(value)
        file.flush()
        os.fsync(file.fileno())
    return path


class WindowsRegionSystem:
    def __init__(self):
        self.browser = EdgePreferences()

    def get_timezone_id(self):
        try:
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation") as key:
                value, _kind = winreg.QueryValueEx(key, "TimeZoneKeyName")
                if isinstance(value, str) and value:
                    return value.rstrip("\x00")
        except OSError:
            pass
        result = subprocess.run(
            ["tzutil.exe", "/g"], capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        raise RuntimeError("无法读取当前时区。")

    def set_timezone_id(self, identifier):
        result = subprocess.run(
            ["tzutil.exe", "/s", identifier], capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                "Windows 无法设置时区（退出码 {}）：{}".format(
                    result.returncode, detail))
        if self.get_timezone_id().lower() != identifier.lower():
            raise RuntimeError("时区设置后核对不一致，请检查自动时区或系统策略。")

    def is_browser_running(self):
        return self.browser.is_running()

    def read_browser(self):
        return self.browser.read()

    def write_browser_languages(self, snapshot, languages):
        self.browser.write(snapshot, languages)

    def restore_browser(self, snapshot):
        self.browser.restore(snapshot)

    def read_user_policy(self):
        return _read_policy(winreg.HKEY_CURRENT_USER, winreg.KEY_READ)

    def read_machine_policy(self):
        value = _read_policy(
            winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        if value.exists:
            return value
        return _read_policy(
            winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY)

    def write_user_policy(self, value):
        with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, POLICY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, POLICY_NAME, 0, winreg.REG_SZ, value.value)

    def remove_user_policy(self):
        try:
            with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, POLICY_PATH, 0,
                    winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, POLICY_NAME)
        except FileNotFoundError:
            pass


def _read_policy(root, access):
    try:
        with winreg.OpenKey(root, POLICY_PATH, 0, access) as key:
            try:
                value, kind = winreg.QueryValueEx(key, POLICY_NAME)
            except FileNotFoundError:
                return PolicyValue(False)
            return PolicyValue(True, value, kind)
    except FileNotFoundError:
        return PolicyValue(False)


def _same_policy(first, second):
    if first.exists != second.exists:
        return False
    if not first.exists:
        return True
    if first.kind != second.kind:
        return False
    return first.value == second.value


class RegionService:
    def __init__(self, system=None):
        self.system = system or WindowsRegionSystem()

    def read(self):
        try:
            user = self.system.read_user_policy()
            machine = self.system.read_machine_policy()
            browser = self.system.read_browser()
            return RegionState(
                timezone_id=self.system.get_timezone_id(),
                languages=str(user.value) if user.exists else "",
                machine_languages=str(machine.value) if machine.exists else "",
                browser_languages=browser.languages,
                browser_profile=browser.profile_name,
                browser_is_running=self.system.is_browser_running(),
            )
        except Exception as error:
            raise RuntimeError(
                "读取时区与 Edge 语言配置失败：" + str(error)) from error

    def apply(self, mode):
        handle = win32util.create_mutex(APPLY_MUTEX_NAME)
        try:
            if not win32util.acquire_mutex(handle, 0):
                raise RuntimeError(
                    "另一个环境切换操作正在进行，请等待完成后重试。")
            try:
                self._apply_exclusive(mode)
            finally:
                win32util.release_mutex(handle)
        finally:
            win32util.close_handle(handle)

    def _apply_exclusive(self, mode):
        profile = RegionProfile.for_mode(mode)
        try:
            if self.system.is_browser_running():
                raise RuntimeError(
                    "请完全退出 Edge（包括后台进程）后重试，当前未修改任何设置。")
            machine = self.system.read_machine_policy()
            if (machine.exists
                    and str(machine.value).lower()
                    != profile.languages.lower()):
                raise RuntimeError(
                    "计算机级 Edge 语言策略与目标冲突，已停止切换且未修改任何设置。请联系管理该策略的人员。")
            original_policy = self.system.read_user_policy()
            original_timezone = self.system.get_timezone_id()
            original_browser = self.system.read_browser()
        except Exception as error:
            raise RuntimeError("切换前检查失败：" + str(error)) from error

        target_policy = PolicyValue(True, profile.languages, winreg.REG_SZ)
        attempted_timezone = False
        attempted_policy = False
        attempted_browser = False
        try:
            if original_timezone.lower() != profile.timezone_id.lower():
                attempted_timezone = True
                self.system.set_timezone_id(profile.timezone_id)
            if not _same_policy(original_policy, target_policy):
                attempted_policy = True
                self.system.write_user_policy(target_policy)
            if (original_browser.languages != profile.languages
                    or original_browser.selected_languages
                    != profile.languages):
                attempted_browser = True
                self.system.write_browser_languages(
                    original_browser, profile.languages)
        except Exception as error:
            rollback_errors = []
            if attempted_browser:
                try:
                    self.system.restore_browser(original_browser)
                except Exception as rollback:
                    rollback_errors.append(
                        "Edge 首选项文件：" + str(rollback))
            if attempted_policy:
                try:
                    if not _same_policy(
                            self.system.read_user_policy(), original_policy):
                        if original_policy.exists:
                            self.system.write_user_policy(original_policy)
                        else:
                            self.system.remove_user_policy()
                except Exception as rollback:
                    rollback_errors.append("Edge 语言：" + str(rollback))
            if attempted_timezone:
                try:
                    if (self.system.get_timezone_id().lower()
                            != original_timezone.lower()):
                        self.system.set_timezone_id(original_timezone)
                except Exception as rollback:
                    rollback_errors.append("时区：" + str(rollback))
            if rollback_errors:
                result = ("以下设置恢复失败，请核对当前状态："
                          + "；".join(rollback_errors) + "。")
            else:
                result = "已恢复本次操作前的设置。"
            raise RuntimeError(
                "切换失败：{}。{}如权限不足，请使用当前账户的管理员权限运行。".format(
                    error, result)) from error
