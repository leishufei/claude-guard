"""Per-user logon task that starts the tool silently."""

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
from xml.sax.saxutils import escape

import win32util

SOURCE = "ClaudeGuard"
LEGACY_SOURCES = (SOURCE, "SmallTools.ClaudeGuard")
LEGACY_TASK_PREFIX = "claude环境工具-"
NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def task_name(sid):
    return "ClaudeGuard-" + sid


def _command_spec():
    if getattr(sys, "frozen", False):
        executable = sys.executable
        arguments = "--tray-startup"
        working_directory = os.path.dirname(sys.executable)
    else:
        script = os.path.abspath(sys.argv[0])
        executable = win32util.pythonw_executable()
        arguments = '"{}" --tray-startup'.format(script)
        working_directory = os.path.dirname(script)
    return executable, arguments, working_directory


def build_task_xml(sid, executable=None, arguments=None,
                   working_directory=None):
    if executable is None:
        executable, arguments, working_directory = _command_spec()
    arguments = arguments + " --expected-sid " + sid
    return (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.2" xmlns="' + NAMESPACE + '">'
        "<RegistrationInfo><Description>登录后静默启动 Claude Guard 并应用中国模式。"
        "</Description><Source>" + SOURCE + "</Source></RegistrationInfo>"
        "<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>"
        + escape(sid) + "</UserId><Delay>PT10S</Delay></LogonTrigger></Triggers>"
        '<Principals><Principal id="CurrentUser"><UserId>' + escape(sid)
        + "</UserId><LogonType>InteractiveToken</LogonType>"
        "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<AllowHardTerminate>false</AllowHardTerminate>"
        "<StartWhenAvailable>true</StartWhenAvailable>"
        "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        "<Enabled>true</Enabled><Hidden>false</Hidden>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
        "<Priority>7</Priority></Settings>"
        '<Actions Context="CurrentUser"><Exec><Command>'
        + escape(executable) + "</Command><Arguments>"
        + escape(arguments) + "</Arguments><WorkingDirectory>"
        + escape(working_directory) + "</WorkingDirectory></Exec></Actions>"
        "</Task>")


def _run(arguments):
    return subprocess.run(
        ["schtasks.exe"] + arguments, capture_output=True, text=True,
        errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)


def _existing_xml(name):
    result = _run(["/Query", "/TN", name, "/XML"])
    if result.returncode != 0:
        return None
    text = result.stdout
    if text.startswith("﻿"):
        text = text[1:]
    try:
        ElementTree.fromstring(text)
        return text
    except ElementTree.ParseError:
        try:
            text = result.stdout.encode("utf-8", errors="ignore").decode(
                "utf-16")
            ElementTree.fromstring(text)
            return text
        except (UnicodeError, ElementTree.ParseError):
            raise RuntimeError("无法读取现有开机任务，已停止以避免覆盖。") from None


def _find(element, path):
    return element.find(path, {"t": NAMESPACE})


def _validate_existing(xml, name):
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as error:
        raise RuntimeError("现有开机任务格式无效，已停止以避免覆盖。") from error
    source = _find(root, "t:RegistrationInfo/t:Source")
    if source is None or (source.text or "") not in LEGACY_SOURCES:
        raise RuntimeError(
            "同名开机任务不属于当前工具，已停止以避免覆盖。请检查任务计划程序中的“"
            + name + "”。")
    return root


def _matches(root, executable, arguments, sid):
    command = _find(root, "t:Actions/t:Exec/t:Command")
    action_arguments = _find(root, "t:Actions/t:Exec/t:Arguments")
    user = _find(root, "t:Principals/t:Principal/t:UserId")
    if command is None or action_arguments is None or user is None:
        return False
    return (os.path.normcase(os.path.abspath(command.text or ""))
            == os.path.normcase(os.path.abspath(executable))
            and (action_arguments.text or "").strip()
            == (arguments + " --expected-sid " + sid).strip()
            and (user.text or "") == sid)


def ensure_registered():
    if not win32util.is_admin():
        raise RuntimeError("设置开机启动需要当前账户的管理员权限。")
    sid = win32util.current_sid()
    legacy = LEGACY_TASK_PREFIX + sid
    if _existing_xml(legacy):
        _run(["/Delete", "/TN", legacy, "/F"])
    name = task_name(sid)
    executable, arguments, working_directory = _command_spec()
    existing = _existing_xml(name)
    if existing:
        root = _validate_existing(existing, name)
        if _matches(root, executable, arguments, sid):
            return
    xml = build_task_xml(
        sid, executable, arguments, working_directory)
    directory = tempfile.gettempdir()
    path = os.path.join(directory, "claudeguard-task-{}.xml".format(os.getpid()))
    try:
        with open(path, "w", encoding="utf-16") as file:
            file.write(xml)
        result = _run(["/Create", "/TN", name, "/XML", path, "/F"])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                "无法设置开机启动任务：" + (detail or "任务计划程序拒绝请求。"))
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
