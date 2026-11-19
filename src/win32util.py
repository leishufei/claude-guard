"""Small Win32 helpers used by the region switch application."""

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes

import psutil

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
ULONG_PTR = ctypes.c_size_t
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
SMTO_ABORTIFHUNG = 0x0002
MSGFLT_ALLOW = 1
WM_CLOSE = 0x0010
SW_SHOWNORMAL = 1
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_PRIVILEGES = 0x0020
MAXIMUM_ALLOWED = 0x02000000
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1
LOGON_WITH_PROFILE = 1
CREATE_UNICODE_ENVIRONMENT = 0x00000400
TH32CS_SNAPPROCESS = 0x00000002
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_RUNNING = 4
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
kernel32.ReleaseMutex.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.ProcessIdToSessionId.argtypes = [
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype = wintypes.DWORD
kernel32.ReplaceFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
kernel32.ReplaceFileW.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
advapi32.OpenSCManagerW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenSCManagerW.restype = wintypes.HANDLE
advapi32.OpenServiceW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenServiceW.restype = wintypes.HANDLE
advapi32.QueryServiceStatus.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
advapi32.QueryServiceStatus.restype = wintypes.BOOL
advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
advapi32.CloseServiceHandle.restype = wintypes.BOOL
advapi32.CreateProcessWithTokenW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
    wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes = [
    wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
advapi32.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, ctypes.c_int,
    ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
advapi32.DuplicateTokenEx.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
    wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD)]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = [
    wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int
user32.PostMessageW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
user32.RegisterWindowMessageW.restype = wintypes.UINT
user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ULONG_PTR)]
user32.SendMessageTimeoutW.restype = LRESULT
user32.ChangeWindowMessageFilterEx.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.DWORD, wintypes.LPVOID]
user32.ChangeWindowMessageFilterEx.restype = wintypes.BOOL
user32.MessageBoxW.argtypes = [
    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
user32.MessageBoxW.restype = ctypes.c_int

shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = wintypes.BOOL
shell32.ShellExecuteW.argtypes = [
    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.LPCWSTR, ctypes.c_int]
shell32.ShellExecuteW.restype = wintypes.HINSTANCE


def _last_error(message):
    return OSError(ctypes.get_last_error(), message)


def is_admin():
    return bool(shell32.IsUserAnAdmin())


def current_process():
    return kernel32.GetCurrentProcess()


def current_session_id():
    session = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        raise _last_error("无法读取当前会话。")
    return session.value


def process_session_id(pid):
    session = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(pid, ctypes.byref(session)):
        raise _last_error("无法读取进程会话。")
    return session.value


def _sid_from_token(token):
    needed = wintypes.DWORD()
    advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
    buffer = ctypes.create_string_buffer(needed.value)
    returned = wintypes.DWORD()
    if not advapi32.GetTokenInformation(
            token, 1, buffer, needed, ctypes.byref(returned)):
        raise _last_error("无法读取账户标识。")
    user = ctypes.cast(buffer, ctypes.POINTER(SID_AND_ATTRIBUTES)).contents
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(user.Sid, ctypes.byref(text)):
        raise _last_error("无法转换账户标识。")
    try:
        return text.value
    finally:
        kernel32.LocalFree(text)


def current_sid():
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            current_process(), TOKEN_QUERY, ctypes.byref(token)):
        raise _last_error("无法读取当前账户令牌。")
    try:
        return _sid_from_token(token)
    finally:
        kernel32.CloseHandle(token)


def process_sid(pid):
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise _last_error("无法打开进程 " + str(pid) + "。")
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
                process, TOKEN_QUERY, ctypes.byref(token)):
            raise _last_error("无法读取进程账户令牌。")
        return _sid_from_token(token)
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def process_image_path(pid):
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise _last_error("无法打开进程 " + str(pid) + "。")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(
                process, 0, buffer, ctypes.byref(size)):
            raise _last_error("无法读取进程路径。")
        return buffer.value
    finally:
        kernel32.CloseHandle(process)


def is_process_elevated(pid):
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise _last_error("无法打开进程 " + str(pid) + "。")
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
                process, TOKEN_QUERY, ctypes.byref(token)):
            raise _last_error("无法读取进程令牌。")
        elevated = wintypes.DWORD()
        returned = wintypes.DWORD()
        if not advapi32.GetTokenInformation(
                token, 20, ctypes.byref(elevated), ctypes.sizeof(elevated),
                ctypes.byref(returned)):
            raise _last_error("无法读取进程权限。")
        return elevated.value != 0
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def is_reparse_point(path):
    attributes = kernel32.GetFileAttributesW(str(path))
    return (attributes != 0xFFFFFFFF
            and bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT))


def replace_file(destination, replacement, backup):
    if not kernel32.ReplaceFileW(
            str(destination), str(replacement),
            str(backup) if backup else None, 0, None, None):
        raise _last_error("无法原子替换文件。")


def enum_top_level_windows():
    windows = []

    def callback(hwnd, _parameter):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        windows.append((int(hwnd), pid.value))
        return True

    if not user32.EnumWindows(WNDENUMPROC(callback), 0):
        raise _last_error("无法枚举窗口。")
    return windows


def enum_visible_windows():
    windows = []

    def callback(hwnd, _parameter):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            windows.append((int(hwnd), pid.value))
        return True

    if not user32.EnumWindows(WNDENUMPROC(callback), 0):
        raise _last_error("无法枚举窗口。")
    return windows


def window_class_name(hwnd):
    buffer = ctypes.create_unicode_buffer(256)
    count = user32.GetClassNameW(hwnd, buffer, len(buffer))
    return buffer.value[:count] if count else ""


def post_close(hwnd):
    return bool(user32.PostMessageW(hwnd, WM_CLOSE, 0, 0))


def find_window(title):
    return int(user32.FindWindowW(None, title) or 0)


def register_window_message(name):
    return int(user32.RegisterWindowMessageW(name))


def send_window_message(hwnd, message, parameter, timeout_ms=3000):
    result = ULONG_PTR()
    sent = user32.SendMessageTimeoutW(
        hwnd, message, parameter, 0, SMTO_ABORTIFHUNG, timeout_ms,
        ctypes.byref(result))
    return bool(sent) and result.value == 1


def allow_window_message(hwnd, message):
    return bool(user32.ChangeWindowMessageFilterEx(
        hwnd, message, MSGFLT_ALLOW, None))


def message_box(text, title, warning=True):
    flags = 0x00000030 if warning else 0x00000040
    user32.MessageBoxW(None, text, title, flags | 0x00000000)


def enable_privilege(name):
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            current_process(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token)):
        raise _last_error("无法调整进程权限。")
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(
                None, name, ctypes.byref(luid)):
            raise _last_error("无法查找进程权限。")
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = 0x00000002
        if not advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(privileges), 0, None, None):
            raise _last_error("无法启用进程权限。")
        if ctypes.get_last_error() == 1300:
            raise _last_error("当前账户不具备所需权限。")
    finally:
        kernel32.CloseHandle(token)


def _duplicate_explorer_token(pid):
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise _last_error("无法打开 Explorer 进程。")
    token = wintypes.HANDLE()
    duplicate = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
                process,
                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                ctypes.byref(token)):
            raise _last_error("无法读取 Explorer 令牌。")
        if not advapi32.DuplicateTokenEx(
                token, MAXIMUM_ALLOWED, None, SECURITY_IMPERSONATION,
                TOKEN_PRIMARY, ctypes.byref(duplicate)):
            raise _last_error("无法复制 Explorer 令牌。")
        return duplicate
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def start_process_with_explorer_token(executable, arguments, working_directory):
    """Start a process at the desktop user's integrity level."""
    sid = current_sid()
    session = current_session_id()
    explorer = None
    for process in psutil.process_iter(["pid", "name"]):
        try:
            if (process.info["name"] or "").lower() != "explorer.exe":
                continue
            pid = process.info["pid"]
            if process_session_id(pid) != session or process_sid(pid) != sid:
                continue
            if is_process_elevated(pid):
                continue
            explorer = pid
            break
        except (psutil.Error, OSError):
            continue
    if explorer is None:
        raise RuntimeError(
            "未找到当前账户的普通权限桌面 Explorer，无法启动目标程序。")
    try:
        enable_privilege("SeImpersonatePrivilege")
    except OSError:
        pass
    token = _duplicate_explorer_token(explorer)
    try:
        command_line = subprocess.list2cmdline([str(executable)] + list(arguments))
        startup = STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        startup.lpDesktop = "winsta0\\default"
        info = PROCESS_INFORMATION()
        if not advapi32.CreateProcessWithTokenW(
                token, LOGON_WITH_PROFILE, None,
                ctypes.create_unicode_buffer(command_line),
                CREATE_UNICODE_ENVIRONMENT, None,
                str(working_directory),
                ctypes.byref(startup), ctypes.byref(info)):
            raise _last_error(
                "无法以普通权限启动目标程序。")
        try:
            return info.dwProcessId
        finally:
            kernel32.CloseHandle(info.hThread)
            kernel32.CloseHandle(info.hProcess)
    finally:
        kernel32.CloseHandle(token)


def notify_existing_instance(instance_name, message, request_exit):
    hwnd = find_window(instance_name)
    if not hwnd:
        return False
    return send_window_message(hwnd, message, 2 if request_exit else 1)


def run_elevated(arguments):
    if getattr(sys, "frozen", False):
        executable = sys.executable
        parameters = subprocess.list2cmdline(arguments)
        working_directory = os.path.dirname(sys.executable)
    else:
        script = os.path.abspath(sys.argv[0])
        executable = pythonw_executable()
        parameters = subprocess.list2cmdline([script] + arguments)
        working_directory = os.path.dirname(script)
    result = shell32.ShellExecuteW(
        None, "runas", executable, parameters, working_directory,
        SW_SHOWNORMAL)
    return int(result) > 32


def pythonw_executable():
    if getattr(sys, "frozen", False):
        return sys.executable
    directory, name = os.path.split(sys.executable)
    candidate = os.path.join(directory, "pythonw.exe")
    if os.path.isfile(candidate):
        return candidate
    return sys.executable


def create_mutex(name):
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        raise _last_error("无法创建互斥量。")
    return handle


def acquire_mutex(handle, timeout_ms=0):
    result = kernel32.WaitForSingleObject(handle, timeout_ms)
    if result in (WAIT_OBJECT_0, WAIT_ABANDONED):
        return True
    if result == WAIT_TIMEOUT:
        return False
    raise _last_error("无法等待互斥量。")


def release_mutex(handle):
    kernel32.ReleaseMutex(handle)


def close_handle(handle):
    if handle:
        kernel32.CloseHandle(handle)


def snapshot_processes():
    """Return a list of (pid, exe_name, ppid) via a fast Win32 snapshot."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        raise _last_error("无法读取系统进程快照。")
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    processes = []
    try:
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                processes.append((
                    int(entry.th32ProcessID),
                    entry.szExeFile,
                    int(entry.th32ParentProcessID),
                ))
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    return processes


def is_service_running(service_name):
    """Query Windows Service Control Manager directly without spawning sc.exe."""
    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return False
    try:
        service = advapi32.OpenServiceW(scm, service_name, SERVICE_QUERY_STATUS)
        if not service:
            return False
        try:
            status = SERVICE_STATUS()
            if not advapi32.QueryServiceStatus(service, ctypes.byref(status)):
                return False
            return status.dwCurrentState == SERVICE_RUNNING
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(scm)
