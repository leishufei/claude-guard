"""Clash Verge proxy discovery, validation, switching, and rollback."""

import ctypes
import http.client
import json
import os
import queue
import re
import threading
import time
import urllib.parse
import winreg
from ctypes import wintypes
from dataclasses import dataclass

import win32util

PIPE_PREFIX = "\\\\.\\pipe\\"
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
ERROR_PIPE_BUSY = 231
ERROR_BROKEN_PIPE = 109
MAX_BODY = 4 * 1024 * 1024
REQUEST_TIMEOUT = 3.5
HOTKEY_MESSAGE = 0x0312
WM_HOTKEY = 0x0312

kernel32 = win32util.kernel32

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.WaitNamedPipeW.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
kernel32.WriteFile.restype = wintypes.BOOL


class INTERNET_PER_CONN_OPTIONW(ctypes.Structure):
    _fields_ = [("dwOption", wintypes.DWORD), ("dwValue", ctypes.c_ulonglong)]


class INTERNET_PER_CONN_OPTION_LISTW(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("pszConnection", wintypes.LPWSTR),
        ("dwOptionCount", wintypes.DWORD),
        ("dwOptionError", wintypes.DWORD),
        ("pOptions", ctypes.POINTER(INTERNET_PER_CONN_OPTIONW)),
    ]


wininet = ctypes.WinDLL("wininet", use_last_error=True)
wininet.InternetQueryOptionW.argtypes = [
    wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD)]
wininet.InternetQueryOptionW.restype = wintypes.BOOL


@dataclass
class VergeProxyState:
    system_proxy: bool
    tun: bool
    windows_proxy: bool
    windows_pac: bool


@dataclass
class ProxySnapshot:
    mode: str
    selection: str
    system_proxy: bool
    tun: bool
    core_tun: bool
    windows_proxy: bool
    windows_pac: bool
    api: object
    client: object
    tun_written: bool = False
    system_proxy_written: bool = False
    selection_written: bool = False
    mode_written: bool = False


class _HandleBox:
    def __init__(self):
        self.handle = None
        self.closed = False
        self.lock = threading.Lock()

    def set(self, handle):
        with self.lock:
            self.handle = handle

    def close(self):
        with self.lock:
            if self.handle and not self.closed:
                self.closed = True
                kernel32.CloseHandle(self.handle)
                self.handle = None


class LocalClashApi:
    def __init__(self, pipe=None, address=None, secret=""):
        self.pipe = pipe
        self.address = address
        self.secret = secret or ""
        if any(character in self.secret for character in "\r\n"):
            raise RuntimeError("Clash 控制凭据格式无效。")
        if pipe:
            if (not pipe or any(character in pipe for character in "\\/\r\n")):
                raise RuntimeError("Clash 控制接口配置无效。")
        if address is not None:
            parsed = urllib.parse.urlparse(address)
            if (parsed.scheme != "http"
                    or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
                    or parsed.path not in ("", "/")
                    or parsed.query or parsed.fragment or parsed.username
                    or parsed.password):
                raise RuntimeError("Clash 控制接口必须位于本机。")

    @staticmethod
    def discover():
        path = os.path.join(
            os.environ.get("APPDATA", ""),
            "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml")
        if not os.path.isfile(path):
            raise RuntimeError("未找到 Clash Verge 配置，请先启动 Clash Verge。")
        try:
            values = read_settings(path)
            pipe = values.get("external-controller-pipe", "")
            if pipe.lower().startswith(PIPE_PREFIX.lower()):
                name = pipe[len(PIPE_PREFIX):]
                if not name or any(
                        character in name for character in "\\/\r\n"):
                    raise ValueError()
                if not os.path.exists(PIPE_PREFIX + name):
                    marker = "verge-mihomo-sidecar-release-"
                    if name.startswith(marker):
                        candidate = ("verge-mihomo-production-"
                                     + name[len(marker):])
                        if os.path.exists(PIPE_PREFIX + candidate):
                            name = candidate
                return LocalClashApi(
                    pipe=name, secret=values.get("secret", ""))
            controller = values.get("external-controller", "")
            if not controller:
                raise ValueError()
            address = "http://" + controller + "/"
            parsed = urllib.parse.urlparse(address)
            if not parsed.hostname or not parsed.port:
                raise ValueError()
            return LocalClashApi(
                address=address, secret=values.get("secret", ""))
        except Exception as error:
            raise RuntimeError(
                "无法读取 Clash 本机控制接口配置，请先启动 Clash Verge。") from error

    def request(self, method, path, body=None):
        payload = (json.dumps(body, ensure_ascii=False, separators=(",", ":"))
                   .encode("utf-8") if body is not None else b"")
        try:
            if self.pipe is not None:
                response = self._pipe_request(method, path, payload)
            else:
                response = self._http_request(method, path, payload)
            if not response:
                return {}
            value = json.loads(response.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except Exception as error:
            raise RuntimeError(
                "Clash 本机控制请求失败或超时，请确认 Clash Verge 正在运行。") from error

    def _http_request(self, method, path, payload):
        parsed = urllib.parse.urlparse(self.address)
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port, timeout=REQUEST_TIMEOUT)
        headers = {}
        if self.secret:
            headers["Authorization"] = "Bearer " + self.secret
        if payload:
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=payload or None,
                               headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise ValueError()
            return response.read(MAX_BODY + 1)
        finally:
            connection.close()

    def _pipe_request(self, method, path, payload):
        result = queue.Queue(maxsize=1)
        box = _HandleBox()

        def worker():
            try:
                handle = _create_pipe(PIPE_PREFIX + self.pipe)
                box.set(handle)
                header = (method + " " + path
                          + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
                if self.secret:
                    header += "Authorization: Bearer " + self.secret + "\r\n"
                header += "Content-Type: application/json\r\n"
                header += "Content-Length: " + str(len(payload)) + "\r\n\r\n"
                _write_all(handle, header.encode("utf-8") + payload)
                result.put((True, _read_all(handle)))
            except Exception as error:
                result.put((False, error))
            finally:
                box.close()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            succeeded, value = result.get(timeout=REQUEST_TIMEOUT)
        except queue.Empty:
            box.close()
            raise TimeoutError("Clash 请求超时。")
        if not succeeded:
            raise value
        return _parse_response(value)


def _create_pipe(path):
    deadline = time.monotonic() + REQUEST_TIMEOUT
    while True:
        handle = kernel32.CreateFileW(
            path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, None)
        if handle != win32util.INVALID_HANDLE_VALUE:
            return handle
        error = ctypes.get_last_error()
        remaining = deadline - time.monotonic()
        if error == ERROR_PIPE_BUSY and remaining > 0:
            kernel32.WaitNamedPipeW(
                path, min(500, int(remaining * 1000)))
            continue
        raise OSError(error, "无法连接 Clash 本机控制管道。")


def _write_all(handle, data):
    written = wintypes.DWORD()
    buffer = ctypes.create_string_buffer(data, len(data))
    if not kernel32.WriteFile(
            handle, buffer, len(data), ctypes.byref(written), None):
        raise OSError(ctypes.get_last_error(), "无法写入 Clash 控制请求。")
    if written.value != len(data):
        raise OSError("Clash 控制请求未完整写入。")


def _read_all(handle):
    output = bytearray()
    buffer = ctypes.create_string_buffer(65536)
    while True:
        count = wintypes.DWORD()
        if not kernel32.ReadFile(
                handle, buffer, len(buffer), ctypes.byref(count), None):
            error = ctypes.get_last_error()
            if error == ERROR_BROKEN_PIPE:
                break
            raise OSError(error, "无法读取 Clash 控制响应。")
        if count.value == 0:
            break
        output.extend(buffer.raw[:count.value])
        if len(output) > MAX_BODY:
            raise RuntimeError("Clash 响应超过读取限制。")
    return bytes(output)


def _parse_response(data):
    if not data:
        return b""
    separator = data.find(b"\r\n\r\n")
    if separator < 0:
        raise ValueError("Clash 响应格式无效。")
    header_bytes = data[:separator]
    body = data[separator + 4:]
    lines = header_bytes.decode("ascii", errors="replace").split("\r\n")
    status = lines[0].split(" ")
    if len(status) < 2 or not 200 <= int(status[1]) < 300:
        raise ValueError("Clash 请求未成功。")
    code = int(status[1])
    length = None
    chunked = False
    for line in lines[1:]:
        name, _sep, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "content-length":
            length = int(value)
        elif name == "transfer-encoding" and value.lower() == "chunked":
            chunked = True
    if code == 204:
        return b""
    if chunked:
        return _decode_chunked(body)
    if length is not None:
        if len(body) < length:
            raise ValueError("Clash 响应不完整。")
        return body[:length]
    return body


def _decode_chunked(data):
    output = bytearray()
    position = 0
    while True:
        end = data.find(b"\r\n", position)
        if end < 0:
            raise ValueError("Clash 分块响应格式无效。")
        size_text = data[position:end].split(b";")[0].strip()
        size = int(size_text, 16)
        position = end + 2
        if size == 0:
            return bytes(output)
        if position + size > len(data):
            raise ValueError("Clash 分块响应不完整。")
        output.extend(data[position:position + size])
        position += size
        if data[position:position + 2] != b"\r\n":
            raise ValueError("Clash 分块响应格式无效。")
        position += 2
        if len(output) > MAX_BODY:
            raise ValueError("Clash 响应超过读取限制。")


def read_settings(path):
    values = {}
    with open(path, encoding="utf-8") as file:
        for line in file:
            key, separator, value = line.partition(":")
            if key not in ("external-controller", "external-controller-pipe",
                           "secret"):
                continue
            value = value.strip()
            if value.startswith("'"):
                if len(value) < 2 or not value.endswith("'"):
                    raise ValueError()
                value = value[1:-1].replace("''", "'")
            elif value.startswith('"'):
                value = json.loads(value)
            else:
                comment = value.find(" #")
                if comment >= 0:
                    value = value[:comment].rstrip()
            values[key] = value
    return values


class VergeHotkeySettings:
    def __init__(self, path=None):
        self.path = path or os.path.join(
            os.environ.get("APPDATA", ""),
            "io.github.clash-verge-rev.clash-verge-rev", "verge.yaml")
        self.pending_function = None
        self.pending_value = None

    def read(self):
        settings = self._read_config()
        flags = _read_windows_flags()
        try:
            with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                registry_enabled = int(winreg.QueryValueEx(
                    key, "ProxyEnable")[0]) != 0
        except OSError:
            registry_enabled = False
        return VergeProxyState(
            system_proxy=_flag(settings, "enable_system_proxy", False),
            tun=_flag(settings, "enable_tun_mode", False),
            windows_proxy=bool(flags & 14) or registry_enabled,
            windows_pac=bool(flags & 4),
        )

    def validate(self):
        settings = self._read_config()
        _require_hotkey(settings, "toggle_system_proxy")
        _require_hotkey(settings, "toggle_tun_mode")
        _find_hotkey_window()

    def set_system_proxy(self, enabled):
        self._set("toggle_system_proxy", enabled)

    def set_tun(self, enabled):
        self._set("toggle_tun_mode", enabled)

    def _set(self, function, desired):
        self._wait_pending()
        state = self.read()
        current = state.tun if function == "toggle_tun_mode" else state.system_proxy
        if current == desired:
            return
        settings = self._read_config()
        hotkey = _require_hotkey(settings, function)
        window = _find_hotkey_window()
        self.pending_function = function
        self.pending_value = desired
        parameter = (hotkey["virtual_key"] << 16) | hotkey["windows_modifiers"]
        if not win32util.user32.PostMessageW(
                window, WM_HOTKEY, hotkey["id"], parameter):
            self.pending_function = None
            self.pending_value = None
            raise RuntimeError("无法将代理切换请求发送到 Clash Verge。")
        self._wait_pending()

    def _wait_pending(self):
        if self.pending_function is None:
            return
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            try:
                state = self.read()
                if self.pending_function == "toggle_tun_mode":
                    done = state.tun == self.pending_value
                else:
                    done = (state.system_proxy == self.pending_value
                            and state.windows_proxy == self.pending_value)
                if done:
                    self.pending_function = None
                    self.pending_value = None
                    return
            except Exception:
                pass
            time.sleep(0.2)
        raise RuntimeError(
            "Clash Verge 尚未确认代理切换请求，请稍后核对客户端状态。")

    def _read_config(self):
        try:
            settings = {}
            hotkeys = False
            with open(self.path, encoding="utf-8") as file:
                for line in file:
                    item = line.strip()
                    if not item or item.startswith("#"):
                        continue
                    if line.strip() == "hotkeys:":
                        hotkeys = True
                        continue
                    if hotkeys and item.startswith("- "):
                        hotkey = item[2:].strip().strip("'\"")
                        comma = hotkey.find(",")
                        if comma > 0:
                            settings[hotkey[:comma].strip()] = (
                                hotkey[comma + 1:].strip())
                        continue
                    if line and not line[0].isspace():
                        hotkeys = False
                    colon = line.find(":")
                    if colon > 0 and not line[0].isspace():
                        name = line[:colon]
                        if name in ("enable_system_proxy",
                                    "enable_tun_mode",
                                    "enable_global_hotkey"):
                            settings[name] = (
                                line[colon + 1:].split("#")[0].strip())
            return settings
        except OSError as error:
            raise RuntimeError("无法读取 Clash Verge 代理设置。") from error


def _flag(settings, name, fallback):
    if name not in settings:
        return fallback
    value = settings[name].strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise RuntimeError("Clash Verge 代理开关格式无效。")


def _require_hotkey(settings, function):
    if (not _flag(settings, "enable_global_hotkey", True)
            or function not in settings):
        raise RuntimeError(
            "请在 Clash Verge 中启用并配置系统代理和 TUN 的全局快捷键。")
    return parse_hotkey(settings[function])


def parse_hotkey(text):
    rust_modifiers = 0
    windows_modifiers = 0
    parts = text.upper().split("+")
    for part in parts[:-1]:
        part = part.strip()
        if part == "SHIFT":
            rust_modifiers |= 0x200
            windows_modifiers |= 4
        elif part in ("CTRL", "CONTROL", "CMDORCTRL", "COMMANDORCONTROL"):
            rust_modifiers |= 8
            windows_modifiers |= 2
        elif part == "ALT":
            rust_modifiers |= 1
            windows_modifiers |= 1
        elif part in ("WIN", "SUPER", "META"):
            rust_modifiers |= 0x40
            windows_modifiers |= 8
        else:
            raise RuntimeError(
                "Clash Verge 快捷键格式不受支持，请使用修饰键加字母或数字。")
    key = parts[-1].strip()
    if key.startswith("KEY"):
        key = key[3:]
    if key.startswith("DIGIT"):
        key = key[5:]
    if (len(key) != 1
            or not ("A" <= key <= "Z" or "0" <= key <= "9")):
        raise RuntimeError(
            "Clash Verge 快捷键格式不受支持，请使用修饰键加字母或数字。")
    code = 19 + ord(key) - ord("A") if "A" <= key <= "Z" else 5 + ord(key) - ord("0")
    return {
        "id": (rust_modifiers << 16) | code,
        "windows_modifiers": windows_modifiers,
        "virtual_key": ord(key),
    }


def _find_hotkey_window():
    expected, version = _installed_executable()
    sid = win32util.current_sid()
    session = win32util.current_session_id()
    found = []
    for handle, pid in win32util.enum_top_level_windows():
        if win32util.window_class_name(handle) != "global_hotkey_app":
            continue
        try:
            if (win32util.process_session_id(pid) == session
                    and win32util.process_sid(pid) == sid
                    and os.path.normcase(win32util.process_image_path(pid))
                    == os.path.normcase(expected)):
                found.append(handle)
        except OSError:
            continue
    if len(found) != 1:
        raise RuntimeError(
            "未找到当前账户唯一的 Clash Verge 快捷键窗口，请先启动 Clash Verge。")
    if version != "2.5.10":
        raise RuntimeError(
            "当前快捷键联动仅支持 Clash Verge 2.5.10，请更新环境工具后重试。")
    return found[0]


def _installed_executable():
    paths = []
    version = ""
    for hive, view in (
            (winreg.HKEY_CURRENT_USER, winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_CURRENT_USER, winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)):
        try:
            with winreg.OpenKey(
                    hive,
                    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    0, winreg.KEY_READ | view) as uninstall:
                for index in range(winreg.QueryInfoKey(uninstall)[0]):
                    try:
                        name = winreg.EnumKey(uninstall, index)
                        with winreg.OpenKey(uninstall, name) as entry:
                            display, _kind = winreg.QueryValueEx(
                                entry, "DisplayName")
                            if display != "Clash Verge":
                                continue
                            try:
                                publisher = winreg.QueryValueEx(
                                    entry, "Publisher")[0]
                            except OSError:
                                publisher = ""
                            if publisher != "Clash Verge Rev":
                                continue
                            try:
                                location = winreg.QueryValueEx(
                                    entry, "InstallLocation")[0]
                            except OSError:
                                location = ""
                            try:
                                version = winreg.QueryValueEx(
                                    entry, "DisplayVersion")[0]
                            except OSError:
                                version = ""
                            location = location.strip('"')
                            executable = os.path.abspath(
                                os.path.join(location, "clash-verge.exe"))
                            if (os.path.isabs(location)
                                    and os.path.isfile(executable)
                                    and executable not in paths):
                                paths.append(executable)
                    except OSError:
                        continue
        except OSError:
            continue
    if len(paths) != 1:
        raise RuntimeError(
            "无法核对 Clash Verge 安装路径，请保留单个已安装版本。")
    return paths[0], version


def _read_windows_flags():
    option = INTERNET_PER_CONN_OPTIONW()
    option.dwOption = 1
    option.dwValue = 0
    options = (INTERNET_PER_CONN_OPTIONW * 1)(option)
    listing = INTERNET_PER_CONN_OPTION_LISTW()
    listing.dwSize = ctypes.sizeof(listing)
    listing.pszConnection = None
    listing.dwOptionCount = 1
    listing.dwOptionError = 0
    listing.pOptions = options
    length = wintypes.DWORD(ctypes.sizeof(listing))
    if not wininet.InternetQueryOptionW(
            None, 75, ctypes.byref(listing), ctypes.byref(length)):
        raise RuntimeError("无法读取 Windows 实际代理状态。")
    return int(options[0].dwValue)


def _unquote_yaml(value):
    value = value.strip()
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1].replace("''", "'")
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        try:
            return json.loads(value)
        except ValueError:
            return value[1:-1]
    comment = value.find(" #")
    if comment >= 0:
        value = value[:comment].rstrip()
    return value


def _iter_yaml_kv_pairs(text):
    """Yield (key, unquoted_value) pairs from a YAML mapping line or flow dict."""
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1]
        quote = None
        start = 0
        fields = []
        for idx, ch in enumerate(inner):
            if ch in ("'", '"'):
                if quote is None:
                    quote = ch
                elif quote == ch:
                    quote = None
            elif ch == "," and quote is None:
                fields.append(inner[start:idx])
                start = idx + 1
        fields.append(inner[start:])
    else:
        fields = [text]
    for field in fields:
        key, sep, val = field.partition(":")
        if sep:
            yield key.strip(), _unquote_yaml(val)


def read_proxy_server(node_name, path=None):
    """Read the server host/IP of a named proxy node from clash-verge.yaml."""
    if not node_name:
        return ""
    path = path or os.path.join(
        os.environ.get("APPDATA", ""),
        "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml")
    try:
        with open(path, encoding="utf-8", errors="replace") as file:
            in_proxies = False
            current_name = None
            current_server = ""
            for raw in file:
                line = raw.rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not line[0].isspace() and not stripped.startswith("-"):
                    if in_proxies and current_name == node_name:
                        return current_server
                    in_proxies = (stripped == "proxies:")
                    current_name = None
                    current_server = ""
                    continue
                if not in_proxies:
                    continue
                fragment = stripped
                if stripped.startswith("- "):
                    if current_name == node_name:
                        return current_server
                    current_name = None
                    current_server = ""
                    fragment = stripped[2:].strip()
                for key, val in _iter_yaml_kv_pairs(fragment):
                    if key == "name":
                        current_name = val
                    elif key == "server":
                        current_server = val
            if in_proxies and current_name == node_name:
                return current_server
    except OSError:
        return ""
    return ""


class ClashProxySwitch:
    def __init__(self, connect=None, connect_client=None, target_node=None):
        self.connect = connect or LocalClashApi.discover
        self.connect_client = connect_client or VergeHotkeySettings
        self._explicit_target = target_node

    def get_target_node(self):
        if self._explicit_target:
            return str(self._explicit_target).strip()
        try:
            import risk_check
            node = risk_check.load_settings().get("targetNode")
            if isinstance(node, str) and node.strip():
                return node.strip()
        except Exception:
            pass
        return ""

    def list_global_nodes(self):
        """Return selectable proxy node names in Clash GLOBAL."""
        api = self.connect()
        proxies = _object(api.request("GET", "/proxies"), "proxies")
        global_group = _object(proxies, "GLOBAL")
        bad_types = {
            "direct", "reject", "selector", "urltest", "fallback",
            "loadbalance", "relay", "rejectdrop", "compatible", "pass",
        }
        nodes = []
        for name in global_group.get("all") or []:
            node = proxies.get(name)
            if not isinstance(node, dict) or "all" in node:
                continue
            node_type = _text(node, "type").lower()
            if node_type and node_type not in bad_types:
                nodes.append(name)
        return nodes

    def prepare_usa(self):
        target = self.get_target_node()
        if not target:
            raise RuntimeError("请先在“节点与 IP 设置”中选择 Clash 目标节点。")
        api = self.connect()
        mode, tun = _read_configs(api)
        client = self.connect_client()
        state = client.read()
        if state.system_proxy != state.windows_proxy or state.tun != tun:
            raise RuntimeError(
                "Clash Verge 与 Windows 或 TUN 实际状态不一致，请先在 Clash Verge 中同步后重试。")
        client.validate()
        proxies = _object(api.request("GET", "/proxies"), "proxies")
        global_group = _object(proxies, "GLOBAL")
        node = _object(proxies, target)
        node_type = _text(node, "type").lower()
        bad_types = {
            "direct", "reject", "selector", "urltest", "fallback",
            "loadbalance", "relay", "rejectdrop",
        }
        if (_text(global_group, "type") != "Selector"
                or "all" in node
                or not node_type
                or node_type in bad_types
                or not _contains(global_group, "all", target)):
            raise RuntimeError(
                "Clash 的 GLOBAL 中没有可直接选择的“{}”节点。".format(target))
        selection = _text(global_group, "now")
        if not selection:
            raise RuntimeError("无法读取 Clash 当前节点。")
        return ProxySnapshot(
            mode=mode, selection=selection, api=api, client=client,
            system_proxy=state.system_proxy, tun=state.tun, core_tun=tun,
            windows_proxy=state.windows_proxy,
            windows_pac=state.windows_pac)

    def apply_usa(self, snapshot):
        _check(snapshot)
        target = self.get_target_node()
        if not target:
            raise RuntimeError("请先在“节点与 IP 设置”中选择 Clash 目标节点。")
        state = snapshot.client.read()
        current_mode, current_tun = _read_configs(snapshot.api)
        if (current_mode != snapshot.mode
                or _read_selection(snapshot.api) != snapshot.selection
                or state.system_proxy != snapshot.system_proxy
                or state.windows_proxy != snapshot.windows_proxy
                or state.windows_pac != snapshot.windows_pac
                or state.tun != snapshot.tun
                or current_tun != snapshot.core_tun):
            raise RuntimeError("Clash 配置已被其他操作更改，请重新切换。")
        try:
            if not snapshot.tun:
                snapshot.tun_written = True
                snapshot.mode_written = True
                snapshot.selection_written = True
                snapshot.client.set_tun(True)
                _wait_tun(snapshot.api, True)
            if snapshot.system_proxy:
                snapshot.system_proxy_written = True
                snapshot.client.set_system_proxy(False)
            if _read_selection(snapshot.api) != target:
                snapshot.selection_written = True
                snapshot.api.request(
                    "PUT", "/proxies/GLOBAL", {"name": target})
            if _read_selection(snapshot.api) != target:
                raise RuntimeError("Clash 目标节点“{}”未生效。".format(target))
            if _read_mode(snapshot.api) != "global":
                snapshot.mode_written = True
                snapshot.api.request(
                    "PATCH", "/configs", {"mode": "global"})
            final = snapshot.client.read()
            final_mode, final_tun = _read_configs(snapshot.api)
            if (final_mode != "global"
                    or _read_selection(snapshot.api) != target
                    or not final_tun
                    or not final.tun or final.system_proxy
                    or final.windows_proxy or final.windows_pac):
                raise RuntimeError("Clash 全局目标节点配置未生效。")
        except Exception as error:
            try:
                self.restore(snapshot)
            except Exception as rollback:
                raise RuntimeError(
                    "Clash 切换失败，代理回滚也未完成。" + str(rollback)) from error
            raise RuntimeError("Clash 切换失败，已恢复原代理配置。") from error

    def restore(self, snapshot):
        _check(snapshot)
        target = self.get_target_node()
        failures = []
        mode_conflict = False
        selection_conflict = False
        restored_tun = False
        try:
            mode = _read_mode(snapshot.api)
            selection = _read_selection(snapshot.api)
            mode_conflict = (mode != snapshot.mode
                             and mode not in ("global", "rule"))
            selection_conflict = (selection != snapshot.selection
                                  and (not target or selection != target))
        except Exception:
            mode_conflict = True
            selection_conflict = True
        if snapshot.system_proxy_written:
            try:
                snapshot.client.set_system_proxy(snapshot.system_proxy)
                state = snapshot.client.read()
                if (state.system_proxy != snapshot.system_proxy
                        or state.windows_proxy != snapshot.windows_proxy
                        or state.windows_pac != snapshot.windows_pac):
                    raise RuntimeError()
                snapshot.system_proxy_written = False
            except Exception:
                failures.append("原系统代理恢复失败，或客户端切换请求尚未完成。")
        if snapshot.tun_written:
            try:
                snapshot.client.set_tun(snapshot.tun)
                _wait_tun(snapshot.api, snapshot.core_tun)
                snapshot.tun_written = False
                restored_tun = True
            except Exception:
                failures.append("原 TUN 状态恢复失败，或客户端切换请求尚未完成。")
        if snapshot.mode_written:
            try:
                if mode_conflict:
                    raise RuntimeError()
                current = _read_mode(snapshot.api)
                if current != snapshot.mode:
                    if current not in ("global", "rule") and not restored_tun:
                        raise RuntimeError()
                    snapshot.api.request(
                        "PATCH", "/configs", {"mode": snapshot.mode})
                    if _read_mode(snapshot.api) != snapshot.mode:
                        raise RuntimeError()
                snapshot.mode_written = False
            except Exception:
                failures.append("原代理模式恢复失败，或已被其他操作更改。")
        if snapshot.selection_written:
            try:
                if selection_conflict:
                    raise RuntimeError()
                current = _read_selection(snapshot.api)
                if current != snapshot.selection:
                    if (not target or current != target) and not restored_tun:
                        raise RuntimeError()
                    snapshot.api.request(
                        "PUT", "/proxies/GLOBAL",
                        {"name": snapshot.selection})
                    if _read_selection(snapshot.api) != snapshot.selection:
                        raise RuntimeError()
                snapshot.selection_written = False
            except Exception:
                failures.append("原代理节点恢复失败，或已被其他操作更改。")
        if failures:
            raise RuntimeError(" ".join(failures))

    def prepare_china(self):
        api = self.connect()
        mode, tun = _read_configs(api)
        client = self.connect_client()
        state = client.read()
        client.validate()
        selection = _read_selection(api) or ""
        return ProxySnapshot(
            mode=mode, selection=selection, api=api, client=client,
            system_proxy=state.system_proxy, tun=state.tun, core_tun=tun,
            windows_proxy=state.windows_proxy,
            windows_pac=state.windows_pac)

    def apply_china(self, snapshot):
        _check(snapshot)
        try:
            if _read_mode(snapshot.api) != "rule":
                snapshot.mode_written = True
                snapshot.api.request("PATCH", "/configs", {"mode": "rule"})
            if snapshot.tun or _read_tun(snapshot.api):
                snapshot.tun_written = True
                snapshot.client.set_tun(False)
                _wait_tun(snapshot.api, False)
            if not snapshot.system_proxy or not snapshot.windows_proxy:
                snapshot.system_proxy_written = True
                snapshot.client.set_system_proxy(True)
            final = snapshot.client.read()
            final_mode, final_tun = _read_configs(snapshot.api)
            if (final_mode != "rule"
                    or final_tun
                    or final.tun
                    or not final.system_proxy
                    or not final.windows_proxy):
                raise RuntimeError("Clash 规则模式或系统代理配置未生效。")
        except Exception as error:
            try:
                self.restore(snapshot)
            except Exception as rollback:
                raise RuntimeError(
                    "Clash 切换失败，代理回滚也未完成。" + str(rollback)) from error
            raise RuntimeError("Clash 切换中国模式失败，已恢复原代理配置。") from error

    def verify_usa_active(self):
        target = self.get_target_node()
        if not target:
            return False, "未配置 Clash 目标节点"
        try:
            api = self.connect()
            mode, tun_enabled = _read_configs(api)
            if mode != "global":
                return False, "Clash 代理模式已变更为 {}".format(mode)
            selection = _read_selection(api)
            if selection != target:
                return False, "Clash 节点已变更为 {}".format(selection or "未知")
            if not tun_enabled:
                return False, "Clash TUN 内核已关闭"
            client = self.connect_client()
            state = client.read()
            if not state.tun:
                return False, "Clash Verge TUN 开关已关闭"
            if state.system_proxy or state.windows_proxy:
                return False, "检测到系统代理被开启"
            return True, "Clash 全局（{}）+ TUN 正常".format(target)
        except Exception as error:
            return False, "Clash 状态异常：{}".format(error)


def _check(snapshot):
    if snapshot is None or snapshot.api is None or snapshot.client is None:
        raise ValueError("无效的代理快照。")


def _read_configs(api):
    configs = api.request("GET", "/configs")
    mode = _text(configs, "mode").lower()
    if mode not in ("global", "rule", "direct"):
        raise RuntimeError("无法读取 Clash 当前代理模式。")
    tun = _object(configs, "tun")
    enabled = tun.get("enable")
    if not isinstance(enabled, bool):
        raise RuntimeError("无法读取 Clash TUN 实际状态。")
    return mode, enabled


def _read_tun(api):
    tun = _object(api.request("GET", "/configs"), "tun")
    enabled = tun.get("enable")
    if not isinstance(enabled, bool):
        raise RuntimeError("无法读取 Clash TUN 实际状态。")
    return enabled


def _wait_tun(api, desired):
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            if _read_tun(api) == desired:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("Clash TUN 内核状态未能在限定时间内生效。")


def _read_mode(api):
    mode = _text(api.request("GET", "/configs"), "mode").lower()
    if mode not in ("global", "rule", "direct"):
        raise RuntimeError("无法读取 Clash 当前代理模式。")
    return mode


def _read_selection(api):
    return _text(api.request("GET", "/proxies/GLOBAL"), "now")


def _contains(value, key, target):
    items = value.get(key)
    if not isinstance(items, list):
        return False
    return target in items


def _object(value, key):
    item = value.get(key) if isinstance(value, dict) else None
    if not isinstance(item, dict):
        raise RuntimeError("Clash 代理配置不完整，未更改代理。")
    return item


def _text(value, key):
    item = value.get(key) if isinstance(value, dict) else None
    return item if isinstance(item, str) else ""
