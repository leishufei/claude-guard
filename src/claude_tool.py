"""PySide6 desktop UI for Claude Guard."""

import ctypes
import os
import sys
import threading
import traceback
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import (
    QAbstractNativeEventFilter, QByteArray, QObject, QPointF, QRectF, QSize, Qt, QThread, QTimer, Signal,
)
from PySide6.QtGui import (
    QAction, QBrush, QColor, QFont, QFontDatabase, QFontMetrics, QIcon,
    QPainter, QPainterPath, QPen, QPixmap,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMenu, QProxyStyle, QPushButton, QScrollArea, QSizePolicy, QStyle,
    QStyleOptionComboBox, QSystemTrayIcon, QVBoxLayout, QWidget,
)
from zoneinfo import ZoneInfo

import claude_desktop
import risk_check
import startup as startup_tasks
import win32util
from clash_proxy import ClashProxySwitch, read_proxy_server
from edge_lifecycle import WindowsBrowserLifecycle
from region_core import (
    CHINA_TZ, USA_TZ, RegionProfile, RegionService,
)

APP_TITLE = "Claude Guard"
APP_USER_MODEL_ID = "ClaudeGuard.App"
APP_DIR = Path(__file__).resolve().parent
ASSETS_DIR = (
    Path(sys._MEIPASS)
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")
    else APP_DIR.parent / "assets"
)
ICON_PATH = ASSETS_DIR / "App.ico"
FONTS_DIR = ASSETS_DIR / "fonts"
LOCAL_DIR = Path(os.environ.get("LOCALAPPDATA", "")) / "ClaudeGuard"
ERROR_LOG = LOCAL_DIR / "error.log"
INSTANCE_PREFIX = "ClaudeGuard.Instance."
_FONTS_LOADED = False


def _ensure_app_fonts():
    """Load bundled Inter, Noto Sans SC, and JetBrains Mono fonts into Qt."""
    global _FONTS_LOADED
    if _FONTS_LOADED or QApplication.instance() is None:
        return
    _FONTS_LOADED = True
    if FONTS_DIR.is_dir():
        for font_file in sorted(FONTS_DIR.glob("*.ttf")):
            QFontDatabase.addApplicationFont(str(font_file))
    QFont.insertSubstitutions(
        "Inter", ["Noto Sans SC", "Microsoft YaHei UI", "Segoe UI"])


FONT_UI = '"Inter", "Noto Sans SC", "Microsoft YaHei UI", "Segoe UI"'
FONT_MONO = '"JetBrains Mono", "Cascadia Mono", "Consolas", "Noto Sans SC", "Microsoft YaHei UI"'

PALETTE = {
    "canvas": "#edf1f6",
    "surface": "#ffffff",
    "surface_subtle": "#f8fafc",
    "surface_muted": "#f1f5f9",
    "surface_quiet": "#fafbfd",
    "border": "#dce3ec",
    "border_strong": "#cbd5e1",
    "border_primary_card": "#b8c4d4",
    "divider": "#eef2f6",
    "ink": "#0f172a",
    "ink_hover": "#1e293b",
    "text_secondary": "#334155",
    "text_muted": "#475569",
    "text_subtle": "#526075",
    "text_disabled": "#64748b",
    "icon_muted": "#475569",
    "icon_subtle": "#64748b",
    "icon_disabled": "#94a3b8",
    "accent": "#2563eb",
    "accent_deep": "#1d4ed8",
    "accent_ink": "#1e3a8a",
    "accent_ink_soft": "#1e40af",
    "accent_bg": "#eff6ff",
    "accent_bg_strong": "#dbeafe",
    "accent_border": "#93c5fd",
    "accent_border_soft": "#bfdbfe",
    "focus": "#2563eb",
    "focus_on_dark": "#60a5fa",
    "success_bg": "#ecfdf5",
    "success_bg_hover": "#d1fae5",
    "success_border": "#86efac",
    "success_text": "#065f46",
    "success_subtext": "#047857",
    "success_dot": "#059669",
    "warning_bg": "#fffbeb",
    "warning_border": "#fcd34d",
    "warning_text": "#92400e",
    "warning_dot": "#d97706",
    "danger_bg": "#fff1f2",
    "danger_bg_soft": "#fff5f6",
    "danger_bg_hover": "#ffe4e6",
    "danger_border": "#fda4af",
    "danger_border_soft": "#fecdd3",
    "danger_text": "#9f1239",
    "danger_subtext": "#881337",
    "danger_accent": "#be123c",
    "danger_dot": "#e11d48",
}


QSS = f"""
QWidget {{ font-family: {FONT_UI}; font-size: 12px; color: {PALETTE["ink"]}; }}
QMainWindow, QScrollArea, QWidget#Root {{ background: {PALETTE["canvas"]}; }}
QScrollArea {{ border: none; }}
QFrame#TopBar {{ background: {PALETTE["surface"]}; border-bottom: 1px solid {PALETTE["border"]}; }}
QLabel#BrandTitle {{ font-size: 16px; font-weight: 700; color: {PALETTE["ink"]}; }}
QFrame#OutboundPill {{ border-radius: 13px; border: 1px solid {PALETTE["border"]}; background: {PALETTE["surface_subtle"]}; }}
QFrame#OutboundPill[locked="true"] {{ border: 1px solid {PALETTE["success_border"]}; background: {PALETTE["success_bg"]}; }}
QFrame#OutboundPill[locked="false"] {{ border: 1px solid {PALETTE["warning_border"]}; background: {PALETTE["warning_bg"]}; }}
QLabel#OutboundText {{ font-size: 12px; font-weight: 600; color: {PALETTE["text_secondary"]}; }}
QFrame#OutboundPill[locked="true"] QLabel#OutboundText {{ color: {PALETTE["success_text"]}; }}
QFrame#OutboundPill[locked="false"] QLabel#OutboundText {{ color: {PALETTE["warning_text"]}; }}
QPushButton#EndpointPill {{ background: {PALETTE["surface_subtle"]}; border: 1px solid {PALETTE["border"]}; border-radius: 13px; padding: 0 10px; min-height: 26px; max-height: 26px; color: {PALETTE["text_secondary"]}; font-family: {FONT_MONO}; font-size: 11px; font-weight: 500; }}
QPushButton#EndpointPill:hover {{ background: {PALETTE["surface_muted"]}; border-color: {PALETTE["border_strong"]}; color: {PALETTE["ink"]}; }}
QWidget#Card {{ background: {PALETTE["surface"]}; border: 1px solid {PALETTE["border"]}; border-bottom: 1px solid {PALETTE["border_strong"]}; border-radius: 12px; }}
QWidget#Card[role="primary"] {{ border: 1px solid {PALETTE["border_strong"]}; border-bottom: 1px solid {PALETTE["border_primary_card"]}; }}
QWidget#Card[tone="cutoff"] {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {PALETTE["danger_bg_soft"]}, stop:0.28 {PALETTE["surface"]}, stop:1 {PALETTE["surface"]}); border: 1px solid {PALETTE["danger_border"]}; border-bottom: 1px solid {PALETTE["danger_border"]}; }}
QWidget#Card[tone="running"] {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {PALETTE["success_bg"]}, stop:0.26 {PALETTE["surface"]}, stop:1 {PALETTE["surface"]}); border: 1px solid {PALETTE["success_border"]}; border-bottom: 1px solid {PALETTE["success_border"]}; }}
QWidget#ProfileCard {{ background: {PALETTE["surface_quiet"]}; border: 1px solid {PALETTE["border"]}; border-radius: 12px; padding: 1px; }}
QWidget#ProfileCard:hover {{ border: 1px solid {PALETTE["accent_border"]}; background: {PALETTE["surface"]}; padding: 1px; }}
QWidget#ProfileCard:focus {{ border: 2px solid {PALETTE["focus"]}; background: {PALETTE["surface"]}; padding: 0px; }}
QWidget#ProfileCard[active="true"] {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #eaf2ff, stop:0.48 #f6faff, stop:1 {PALETTE["surface"]}); border: 2px solid {PALETTE["accent"]}; padding: 0px; }}
QWidget#ProfileCard[active="true"]:hover {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e3eeff, stop:0.48 #f3f8ff, stop:1 {PALETTE["surface"]}); border: 2px solid {PALETTE["accent_deep"]}; padding: 0px; }}
QWidget#ProfileCard[active="true"]:focus {{ border: 2px solid {PALETTE["accent_ink"]}; padding: 0px; }}
QWidget#ProfileCard[pending="true"] {{ border: 2px dashed {PALETTE["accent"]}; padding: 0px; background: {PALETTE["surface"]}; }}
QWidget#ProfileCard[pending="true"][pulse="true"] {{ border: 2px solid {PALETTE["accent_deep"]}; padding: 0px; }}
QFrame#ModeGuidePanel {{ background: {PALETTE["surface_subtle"]}; border: 1px solid {PALETTE["border"]}; border-radius: 8px; }}
QFrame#AuditListBox {{ background: {PALETTE["surface_subtle"]}; border: 1px solid {PALETTE["border"]}; border-radius: 8px; }}
QWidget#AuditRowRisk {{ background: {PALETTE["danger_bg_soft"]}; }}
QWidget#AuditRowUnknown {{ background: {PALETTE["warning_bg"]}; }}
QWidget#AuditRowPass {{ background: transparent; }}
QWidget#StatusBanner {{ background: transparent; border: none; }}
QWidget#SubPanel {{ background: {PALETTE["surface_subtle"]}; border: 1px solid {PALETTE["border"]}; border-radius: 8px; }}
QWidget#ActionBar {{ background: {PALETTE["surface_subtle"]}; border: none; border-top: 1px solid {PALETTE["divider"]}; border-bottom-left-radius: 11px; border-bottom-right-radius: 11px; }}
QLabel#CardTitle {{ font-size: 14px; font-weight: 600; color: {PALETTE["ink"]}; }}
QLabel#ProfileTitle {{ font-size: 14px; font-weight: 600; color: {PALETTE["text_muted"]}; }}
QWidget#ProfileCard[active="true"] QLabel#ProfileTitle {{ color: {PALETTE["ink"]}; }}
QLabel#SettingsTitle {{ font-size: 14px; font-weight: 600; color: {PALETTE["ink"]}; }}
QLabel#ClaudeTitle {{ font-size: 15.5px; font-weight: 700; color: {PALETTE["ink"]}; }}
QLabel#Muted, QLabel#RiskDetail {{ font-size: 12px; color: {PALETTE["text_subtle"]}; }}
QLabel#MutedSep {{ font-size: 12px; color: {PALETTE["border_strong"]}; }}
QWidget#ProfileCard[active="true"] QLabel#MutedSep {{ color: {PALETTE["accent_border"]}; }}
QLabel#MetaLang {{ font-size: 12px; color: {PALETTE["text_muted"]}; }}
QLabel#MetaLangMono {{ font-family: {FONT_MONO}; font-size: 11.5px; color: {PALETTE["text_muted"]}; }}
QLabel#MetaProxy {{ font-size: 12px; color: {PALETTE["text_muted"]}; }}
QWidget#ProfileCard[active="true"] QLabel#MetaLang, QWidget#ProfileCard[active="true"] QLabel#MetaLangMono, QWidget#ProfileCard[active="true"] QLabel#MetaProxy, QWidget#ProfileCard[active="true"] QLabel#Muted {{ color: {PALETTE["accent_ink_soft"]}; }}
QLabel#AuditDetail {{ font-size: 11.5px; color: {PALETTE["text_muted"]}; }}
QWidget#AuditRowRisk QLabel#AuditDetail {{ color: {PALETTE["danger_subtext"]}; }}
QWidget#AuditRowUnknown QLabel#AuditDetail {{ color: {PALETTE["warning_text"]}; }}
QLabel#GuideTitle {{ font-size: 12px; font-weight: 600; color: {PALETTE["ink"]}; }}
QLabel#GuideBody {{ font-size: 11.5px; color: {PALETTE["text_muted"]}; }}
QLabel#Clock {{ font-family: {FONT_MONO}; font-size: 26px; font-weight: 600; color: {PALETTE["text_secondary"]}; }}
QWidget#ProfileCard[active="true"] QLabel#Clock {{ color: {PALETTE["ink"]}; }}
QLabel#OffsetChip {{ font-family: {FONT_MONO}; font-size: 11px; font-weight: 500; color: {PALETTE["text_muted"]}; background: {PALETTE["surface_muted"]}; border-radius: 4px; padding: 2px 6px; }}
QWidget#ProfileCard[active="true"] QLabel#OffsetChip {{ background: {PALETTE["accent_bg_strong"]}; color: {PALETTE["accent_ink"]}; font-weight: 600; }}
QLabel#Endpoint {{ color: {PALETTE["text_subtle"]}; font-size: 11px; }}
QLabel#EndpointFooter {{ font-family: {FONT_UI}; color: {PALETTE["text_muted"]}; font-size: 11.5px; font-weight: 500; }}
QLabel#ScrollHint {{ font-family: {FONT_UI}; color: {PALETTE["accent_deep"]}; font-size: 11px; font-weight: 600; }}
QFrame#Footer {{ background: {PALETTE["surface"]}; border-top: 1px solid {PALETTE["border"]}; }}
QLabel#StatusTitle {{ font-size: 13px; font-weight: 700; color: {PALETTE["ink"]}; }}
QWidget#StatusBanner[running="true"] QLabel#StatusTitle {{ color: {PALETTE["success_text"]}; }}
QWidget#StatusBanner[error="true"] QLabel#StatusTitle {{ color: {PALETTE["danger_text"]}; }}
QWidget#StatusBanner[china="true"] QLabel#StatusTitle {{ color: {PALETTE["accent_ink"]}; }}
QLabel#StatusDetail {{ font-size: 12px; color: {PALETTE["text_secondary"]}; }}
QWidget#StatusBanner[running="true"] QLabel#StatusDetail {{ color: {PALETTE["success_subtext"]}; }}
QWidget#StatusBanner[error="true"] QLabel#StatusDetail {{ color: {PALETTE["danger_subtext"]}; }}
QWidget#StatusBanner[china="true"] QLabel#StatusDetail {{ color: {PALETTE["accent_ink_soft"]}; }}
QLabel#RiskName {{ font-size: 12px; font-weight: 600; color: {PALETTE["ink"]}; }}
QWidget#AuditRowRisk QLabel#RiskName {{ color: {PALETTE["danger_text"]}; }}
QLabel#ProcName {{ font-family: {FONT_MONO}; font-size: 12px; font-weight: 600; color: {PALETTE["ink"]}; }}
QLabel#ProcRole {{ font-family: {FONT_UI}; font-size: 11.5px; font-weight: 500; color: {PALETTE["text_muted"]}; }}
QLabel#ProcRow {{ font-family: {FONT_MONO}; font-size: 11px; color: {PALETTE["text_muted"]}; }}
QLabel#ProcPidTag {{ font-family: {FONT_UI}; font-size: 11px; font-weight: 600; background: {PALETTE["success_bg_hover"]}; color: {PALETTE["success_text"]}; border-radius: 5px; padding: 2px 7px; }}
QLabel#ProcZeroTag {{ font-family: {FONT_UI}; font-size: 11px; font-weight: 600; background: #e2e8f0; color: {PALETTE["text_secondary"]}; border-radius: 5px; padding: 2px 7px; }}
QLabel#FieldLabel {{ font-size: 12px; font-weight: 600; color: {PALETTE["text_secondary"]}; }}
QLabel#DriftTag {{ font-family: {FONT_UI}; font-size: 11.5px; font-weight: 600; color: {PALETTE["danger_accent"]}; }}
QLabel#HoverHint {{ font-size: 11px; font-weight: 600; color: {PALETTE["accent_deep"]}; background: {PALETTE["accent_bg"]}; border: 1px solid {PALETTE["accent_border_soft"]}; border-radius: 10px; padding: 2px 8px; }}
QFrame#IpBadgeAuto {{ background: #e2e8f0; border-radius: 4px; }}
QFrame#IpBadgeAuto QLabel {{ font-size: 10.5px; font-weight: 600; color: {PALETTE["text_muted"]}; background: transparent; }}
QFrame#IpBadgeManual {{ background: {PALETTE["accent_bg_strong"]}; border-radius: 4px; }}
QFrame#IpBadgeManual QLabel {{ font-size: 10.5px; font-weight: 600; color: {PALETTE["accent_deep"]}; background: transparent; }}
QLabel#PillPass, QPushButton#PillPass {{ background: {PALETTE["success_bg"]}; color: {PALETTE["success_text"]}; border: 1px solid {PALETTE["success_border"]}; border-radius: 12px; min-height: 16px; padding: 3px 10px; font-size: 11.5px; font-weight: 600; }}
QPushButton#PillPass:hover {{ background: {PALETTE["success_bg_hover"]}; border-color: #34d399; }}
QLabel#PillRisk, QPushButton#PillRisk {{ background: {PALETTE["danger_bg"]}; color: {PALETTE["danger_accent"]}; border: 1px solid {PALETTE["danger_border_soft"]}; border-radius: 12px; min-height: 16px; padding: 3px 10px; font-size: 11.5px; font-weight: 600; }}
QPushButton#PillRisk:hover {{ background: {PALETTE["danger_bg_hover"]}; border-color: {PALETTE["danger_border"]}; }}
QLabel#PillWarn {{ background: {PALETTE["warning_bg"]}; color: {PALETTE["warning_text"]}; border: 1px solid {PALETTE["warning_border"]}; border-radius: 10px; padding: 2px 8px; font-size: 11px; font-weight: 600; }}
QLabel#PillNeutral, QPushButton#PillNeutral {{ background: {PALETTE["surface_muted"]}; color: {PALETTE["text_secondary"]}; border: 1px solid {PALETTE["border"]}; border-radius: 12px; min-height: 16px; padding: 3px 10px; font-size: 11.5px; font-weight: 600; }}
QPushButton#PillNeutral:hover {{ background: #e2e8f0; border-color: {PALETTE["border_strong"]}; }}
QLabel#PillChecking {{ background: {PALETTE["accent_bg"]}; color: {PALETTE["accent_deep"]}; border: 1px solid {PALETTE["accent_border_soft"]}; border-radius: 12px; min-height: 16px; padding: 3px 10px; font-size: 11.5px; font-weight: 600; }}
QLabel#PillActive {{ background: {PALETTE["accent_bg_strong"]}; color: {PALETTE["accent_ink_soft"]}; border: 1px solid {PALETTE["accent_border"]}; border-radius: 10px; padding: 2px 9px; font-size: 11px; font-weight: 600; }}
QLabel#AuditBadgePass {{ font-family: {FONT_UI}; font-size: 11px; font-weight: 600; background: {PALETTE["success_bg_hover"]}; color: {PALETTE["success_text"]}; border-radius: 6px; padding: 2px 8px; }}
QLabel#AuditBadgeRisk {{ font-family: {FONT_UI}; font-size: 11px; font-weight: 600; background: {PALETTE["danger_bg_hover"]}; color: {PALETTE["danger_text"]}; border-radius: 6px; padding: 2px 8px; }}
QLabel#AuditBadgeUnknown {{ font-family: {FONT_UI}; font-size: 11px; font-weight: 600; background: #fef3c7; color: {PALETTE["warning_text"]}; border-radius: 6px; padding: 2px 8px; }}
QPushButton {{ border-radius: 8px; padding: 0 10px; }}
QPushButton#PrimaryBtn, QPushButton#CompactPrimaryBtn {{ background: {PALETTE["ink"]}; color: {PALETTE["surface"]}; border: 1px solid {PALETTE["ink"]}; font-weight: 600; }}
QPushButton#PrimaryBtn {{ font-size: 13px; }}
QPushButton#PrimaryBtn:hover, QPushButton#CompactPrimaryBtn:hover {{ background: {PALETTE["ink_hover"]}; border-color: {PALETTE["ink_hover"]}; }}
QPushButton#DangerBtn {{ background: {PALETTE["danger_bg"]}; color: {PALETTE["danger_accent"]}; border: 1px solid {PALETTE["danger_border_soft"]}; font-size: 13px; font-weight: 600; }}
QPushButton#DangerBtn:hover {{ background: {PALETTE["danger_bg_hover"]}; border-color: {PALETTE["danger_border"]}; }}
QPushButton#DangerIdleBtn {{ background: {PALETTE["surface"]}; color: {PALETTE["text_secondary"]}; border: 1px solid {PALETTE["border"]}; font-size: 13px; font-weight: 600; }}
QPushButton#DangerIdleBtn:hover {{ background: {PALETTE["danger_bg_soft"]}; color: {PALETTE["danger_accent"]}; border-color: {PALETTE["danger_border_soft"]}; }}
QPushButton#SecondaryBtn, QPushButton#GhostBtn, QPushButton#CompactOutlineBtn {{ background: {PALETTE["surface"]}; color: {PALETTE["text_secondary"]}; border: 1px solid {PALETTE["border"]}; }}
QPushButton#SecondaryBtn {{ font-size: 13px; font-weight: 600; }}
QPushButton#CompactActiveBtn {{ background: {PALETTE["accent_bg"]}; color: {PALETTE["accent_deep"]}; border: 1px solid {PALETTE["accent_border"]}; min-height: 32px; font-size: 12px; font-weight: 600; padding: 0 12px; }}
QPushButton#CompactActiveBtn:hover {{ background: {PALETTE["accent_bg_strong"]}; border-color: {PALETTE["accent"]}; }}
QPushButton#BlueSecondaryBtn {{ background: {PALETTE["accent_bg"]}; color: {PALETTE["accent_deep"]}; border: 1px solid {PALETTE["accent_border_soft"]}; font-size: 13px; font-weight: 600; }}
QPushButton#BlueSecondaryBtn:hover {{ background: {PALETTE["accent_bg_strong"]}; border-color: {PALETTE["accent_border"]}; }}
QPushButton#GhostBtn:hover, QPushButton#SecondaryBtn:hover, QPushButton#CompactOutlineBtn:hover {{ background: {PALETTE["surface_subtle"]}; border-color: {PALETTE["border_strong"]}; color: {PALETTE["ink"]}; }}
QPushButton#GhostBtn {{ min-height: 36px; max-height: 36px; font-size: 12px; font-weight: 500; padding: 0 10px; }}
QPushButton#SoftBtn {{ background: {PALETTE["surface_subtle"]}; color: {PALETTE["text_secondary"]}; border: 1px solid {PALETTE["border"]}; border-radius: 8px; padding: 0 10px; min-height: 32px; max-height: 32px; font-size: 12px; font-weight: 500; }}
QPushButton#SoftBtn:hover {{ background: {PALETTE["surface_muted"]}; border-color: {PALETTE["border_strong"]}; color: {PALETTE["ink"]}; }}
QPushButton#MiniCollapseBtn {{ background: {PALETTE["surface_subtle"]}; color: {PALETTE["text_muted"]}; border: 1px solid {PALETTE["border"]}; border-radius: 6px; min-height: 26px; max-height: 26px; font-size: 12px; font-weight: 500; }}
QPushButton#MiniCollapseBtn:hover {{ background: {PALETTE["surface_muted"]}; border-color: {PALETTE["border_strong"]}; color: {PALETTE["ink"]}; }}
QPushButton#QuickFixBtn {{ background: {PALETTE["surface"]}; color: {PALETTE["danger_accent"]}; border: 1px solid {PALETTE["danger_border_soft"]}; border-radius: 6px; padding: 0 10px; min-height: 28px; max-height: 28px; font-size: 12px; font-weight: 600; }}
QPushButton#QuickFixBtn:hover {{ background: {PALETTE["danger_bg"]}; border-color: {PALETTE["danger_border"]}; }}
QPushButton#ModeHelpBtn {{ background: transparent; color: {PALETTE["text_muted"]}; border: 1px solid transparent; border-radius: 6px; padding: 0 8px; min-height: 30px; max-height: 30px; font-size: 12px; font-weight: 500; }}
QPushButton#ModeHelpBtn:hover {{ background: {PALETTE["surface_muted"]}; color: {PALETTE["ink"]}; }}
QPushButton#ModeHelpBtn:checked {{ background: {PALETTE["accent_bg"]}; color: {PALETTE["accent_deep"]}; border-color: {PALETTE["accent_border"]}; font-weight: 600; }}
QPushButton#CompactPrimaryBtn {{ min-height: 32px; font-size: 12px; padding: 0 12px; }}
QPushButton#CompactOutlineBtn {{ min-height: 32px; font-size: 12px; font-weight: 500; padding: 0 12px; }}
QPushButton:disabled, QPushButton#PrimaryBtn:disabled, QPushButton#DangerBtn:disabled, QPushButton#DangerIdleBtn:disabled, QPushButton#SecondaryBtn:disabled, QPushButton#BlueSecondaryBtn:disabled, QPushButton#GhostBtn:disabled, QPushButton#SoftBtn:disabled, QPushButton#CompactPrimaryBtn:disabled, QPushButton#CompactOutlineBtn:disabled, QPushButton#CompactActiveBtn:disabled, QPushButton#QuickFixBtn:disabled {{ background: {PALETTE["surface_muted"]}; color: {PALETTE["text_disabled"]}; border: 1px solid {PALETTE["border"]}; }}
QPushButton#Segment {{ background: transparent; border: 1px solid transparent; color: {PALETTE["text_muted"]}; padding: 0 9px; font-size: 12px; font-weight: 500; border-radius: 6px; }}
QPushButton#Segment:hover {{ color: {PALETTE["ink"]}; }}
QPushButton#Segment:checked {{ background: {PALETTE["surface"]}; color: {PALETTE["ink"]}; border: 1px solid {PALETTE["border"]}; font-weight: 600; }}
QFrame#Segments {{ background: {PALETTE["surface_muted"]}; border: 1px solid {PALETTE["border"]}; border-radius: 8px; }}
QPushButton#PrimaryBtn:focus {{ border: 2px solid {PALETTE["focus_on_dark"]}; padding: 0 9px; }}
QPushButton#CompactPrimaryBtn:focus {{ border: 2px solid {PALETTE["focus_on_dark"]}; padding: 0 11px; }}
QPushButton#CompactOutlineBtn:focus, QPushButton#CompactActiveBtn:focus {{ border: 2px solid {PALETTE["focus"]}; padding: 0 11px; }}
QPushButton#EndpointPill:focus, QPushButton#GhostBtn:focus, QPushButton#SoftBtn:focus, QPushButton#QuickFixBtn:focus {{ border: 2px solid {PALETTE["focus"]}; padding: 0 9px; }}
QPushButton#ModeHelpBtn:focus {{ border: 2px solid {PALETTE["focus"]}; padding: 0 7px; }}
QPushButton#Segment:focus {{ border: 2px solid {PALETTE["focus"]}; padding: 0 8px; }}
QPushButton:focus, QPushButton#SecondaryBtn:focus, QPushButton#BlueSecondaryBtn:focus, QPushButton#DangerBtn:focus, QPushButton#DangerIdleBtn:focus, QPushButton#MiniCollapseBtn:focus, QPushButton#PillPass:focus, QPushButton#PillRisk:focus, QPushButton#PillNeutral:focus {{ border: 2px solid {PALETTE["focus"]}; }}
QLineEdit, QComboBox {{ background: {PALETTE["surface"]}; border: 1px solid {PALETTE["border_strong"]}; border-radius: 8px; padding: 0 10px; font-size: 12px; min-height: 36px; max-height: 36px; color: {PALETTE["ink"]}; }}
QComboBox {{ background: {PALETTE["surface_subtle"]}; border: 1px solid {PALETTE["border"]}; color: {PALETTE["ink"]}; font-weight: 500; padding-right: 24px; }}
QLineEdit#IpInput {{ font-family: {FONT_MONO}; padding-right: 64px; }}
QLineEdit:focus, QComboBox:focus {{ border: 2px solid {PALETTE["focus"]}; background: {PALETTE["surface"]}; }}
QLineEdit:disabled {{ background: {PALETTE["surface_muted"]}; border-color: {PALETTE["border"]}; color: {PALETTE["text_muted"]}; }}
QComboBox::drop-down {{ subcontrol-origin: padding; subcontrol-position: top right; width: 22px; border: none; }}
QComboBox::down-arrow {{ image: none; }}
QComboBox QAbstractItemView {{ background: {PALETTE["surface"]}; border: 1px solid {PALETTE["border"]}; selection-background-color: {PALETTE["accent_bg"]}; selection-color: {PALETTE["ink"]}; outline: none; }}
QScrollBar:vertical {{ background: {PALETTE["canvas"]}; width: 8px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {PALETTE["border_strong"]}; min-height: 30px; border-radius: 4px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
"""


def write_error(error):
    try:
        LOCAL_DIR.mkdir(parents=True, exist_ok=True)
        with open(ERROR_LOG, "a", encoding="utf-8") as file:
            file.write(datetime.now().astimezone().isoformat() + "\n")
            file.write("".join(traceback.format_exception(
                type(error), error, error.__traceback__)))
            file.write("\n")
        return str(ERROR_LOG)
    except OSError:
        return "无法写入错误记录"


def _icon(name, color="#64748b", size=18, filled=False):
    """Render the shared Lucide-aligned SVG icon set with Qt's native SVG renderer."""
    paths = {
        "brand_shield": (
            '<path d="M12 2.25 4.5 5.4v6c0 5.05 3.18 9.58 7.5 10.85 '
            '4.32-1.27 7.5-5.8 7.5-10.85v-6L12 2.25Z" fill="' + color + '" '
            'fill-opacity="0.2" stroke="' + color + '" stroke-width="1.75" '
            'stroke-linejoin="round"/>'
            '<path d="M14.2 9.35C13.65 8.82 12.88 8.5 12 8.5c-1.82 0-3.25 '
            '1.46-3.25 3.35S10.18 15.2 12 15.2c.9 0 1.68-.34 2.25-.9" '
            'fill="none" stroke="' + color + '" stroke-width="2.1" '
            'stroke-linecap="round"/>'
        ),
        "shield": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
        "shield_check": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
        "shield_alert": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
        "cpu": '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>',
        "settings": '<path d="M20 7h-9"/><path d="M14 17H5"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/>',
        "sliders": '<line x1="21" x2="14" y1="4" y2="4"/><line x1="10" x2="3" y1="4" y2="4"/><line x1="21" x2="12" y1="12" y2="12"/><line x1="8" x2="3" y1="12" y2="12"/><line x1="21" x2="16" y1="20" y2="20"/><line x1="12" x2="3" y1="20" y2="20"/><line x1="14" x2="14" y1="2" y2="6"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="16" x2="16" y1="18" y2="22"/>',
        "server": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.1M7 17.5h.1"/>',
        "refresh": '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
        "play": '<polygon points="6 3 20 12 6 21 6 3"/>',
        "power": '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>',
        "switch": '<path d="m16 3 4 4-4 4"/><path d="M20 7H4"/><path d="m8 21-4-4 4-4"/><path d="M4 17h16"/>',
        "report": '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/><path d="m16 16-1.9-1.9"/>',
        "target": '<circle cx="12" cy="12" r="10"/><line x1="22" x2="18" y1="12" y2="12"/><line x1="6" x2="2" y1="12" y2="12"/><line x1="12" x2="12" y1="6" y2="2"/><line x1="12" x2="12" y1="22" y2="18"/>',
        "chevron_up": '<path d="m18 15-6-6-6 6"/>',
        "chevron_down": '<path d="m6 9 6 6 6-6"/>',
        "help_circle": '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
        "lock": '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
        "check_circle": '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
        "alert_triangle": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
        "alert_octagon": '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>',
        "circle_dashed": '<path d="M10.1 2.182a10 10 0 0 1 3.8 0"/><path d="M13.9 21.818a10 10 0 0 1-3.8 0"/><path d="M17.609 3.721a10 10 0 0 1 2.69 2.7"/><path d="M2.182 13.9a10 10 0 0 1 0-3.8"/><path d="M20.279 17.609a10 10 0 0 1-2.7 2.69"/><path d="M21.818 10.1a10 10 0 0 1 0 3.8"/><path d="M3.721 6.391a10 10 0 0 1 2.7-2.69"/><path d="M6.391 20.279a10 10 0 0 1-2.69-2.7"/>',
        "activity": '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
        "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
        "globe": '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
        "wrench": '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
        "maximize": '<polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" x2="14" y1="3" y2="10"/><line x1="3" x2="10" y1="21" y2="14"/>',
        "minimize": '<polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" x2="21" y1="10" y2="3"/><line x1="3" x2="10" y1="21" y2="14"/>',
    }
    if name == "brand_shield":
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
               'viewBox="0 0 24 24">' + paths[name] + '</svg>')
    else:
        fill_attr = color if filled else "none"
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
               f'viewBox="0 0 24 24" fill="{fill_attr}" stroke="{color}" '
               'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
               + paths[name] + '</svg>')
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.fill(Qt.transparent)
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(2)
    return QIcon(pixmap)


def _icon_label(name, color="#64748b", size=18):
    label = QLabel()
    label.setFixedSize(size, size)
    label.setPixmap(_icon(name, color, size).pixmap(QSize(size, size)))
    return label


def _set_label_icon(label, name, color="#64748b", size=16):
    label.setFixedSize(size, size)
    label.setPixmap(_icon(name, color, size).pixmap(QSize(size, size)))


def _label(text, name, parent=None):
    value = QLabel(text, parent)
    value.setObjectName(name)
    value.setWordWrap(True)
    value.setMinimumWidth(0)
    return value


def _repolish(widget, obj_name=None):
    if obj_name is not None:
        widget.setObjectName(obj_name)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def _clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            _clear_layout(item.layout())


def _invalidate_layout_tree(root):
    """Invalidate nested child layouts bottom-up so cached heightForWidth resets."""
    for child in reversed(root.findChildren(QWidget)):
        child.updateGeometry()
        layout = child.layout()
        if layout is not None:
            layout.invalidate()
            layout.activate()
    root.updateGeometry()
    layout = root.layout()
    if layout is not None:
        layout.invalidate()
        layout.activate()


class StatusDot(QWidget):
    """Paint a crisp dot with an optional soft outer ring."""

    def __init__(self, core_color="#059669", ring_color="#10b981", size=10,
                 with_ring=True, parent=None):
        super().__init__(parent)
        self._core = QColor(core_color)
        self._ring = QColor(ring_color)
        self._with_ring = with_ring
        self.setFixedSize(size, size)

    def set_colors(self, core_color, ring_color=None):
        self._core = QColor(core_color)
        self._ring = QColor(ring_color or core_color)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        center = QPointF(self.width() / 2.0, self.height() / 2.0)
        if self._with_ring:
            ring = QColor(self._ring)
            ring.setAlpha(60)
            painter.setBrush(QBrush(ring))
            painter.drawEllipse(center, self.width() / 2.0 - 0.5,
                                self.height() / 2.0 - 0.5)
        painter.setBrush(QBrush(self._core))
        radius = 3.0 if self._with_ring else min(self.width(), self.height()) / 2.0 - 0.5
        painter.drawEllipse(center, radius, radius)
        painter.end()


class PillButton(QPushButton):
    """Push button with optional left status dot and right chevron."""

    def __init__(self, text="", parent=None, dot_color=None, chevron="down"):
        super().__init__(text, parent)
        self._dot_color = dot_color
        self._chevron = chevron
        self._chevron_color = "#64748b"
        self._sync_padding()

    def set_dot_color(self, color):
        self._dot_color = color
        self._sync_padding()
        self.update()

    def set_chevron(self, direction, color=None):
        self._chevron = direction
        if color is not None:
            self._chevron_color = color
        self._sync_padding()
        self.update()

    def _sync_padding(self):
        left = 22 if self._dot_color else 11
        right = 24 if self._chevron else 11
        self.setStyleSheet(f"padding-left: {left}px; padding-right: {right}px;")

    def sizeHint(self):
        hint = super().sizeHint()
        extra = (10 if self._dot_color else 0) + (12 if self._chevron else 0)
        return QSize(hint.width() + extra, hint.height())

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        cy = self.height() / 2.0
        if self._dot_color:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor(self._dot_color)))
            painter.drawEllipse(QPointF(12.5, cy), 3.0, 3.0)
        if self._chevron:
            pen = QPen(QColor(self._chevron_color if self.isEnabled() else "#94a3b8"), 1.6)
            pen.setCapStyle(Qt.RoundCap)
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            cx = self.width() - 13.0
            dy = -1.8 if self._chevron == "up" else 1.8
            painter.drawLine(QPointF(cx - 3.5, cy - dy), QPointF(cx, cy + dy))
            painter.drawLine(QPointF(cx, cy + dy), QPointF(cx + 3.5, cy - dy))
        painter.end()


class GuardStyle(QProxyStyle):
    """Keep stylesheet focus borders without native dotted focus rectangles."""

    def drawPrimitive(self, element, option, painter, widget=None):
        if (element == QStyle.PE_FrameFocusRect
                and isinstance(widget, (QPushButton, QComboBox))):
            return
        super().drawPrimitive(element, option, painter, widget)


class SelectComboBox(QComboBox):
    """Non-editable display combo box with pointer cursor."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._placeholder = ""
        self.setEditable(False)
        self.setCursor(Qt.PointingHandCursor)
        self.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.setMinimumContentsLength(8)

    def setPlaceholder(self, text):
        """Store placeholder text drawn when no item is selected."""
        self._placeholder = text or ""
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        option = QStyleOptionComboBox()
        self.initStyleOption(option)
        arrow = self.style().subControlRect(
            QStyle.CC_ComboBox, option, QStyle.SC_ComboBoxArrow, self)
        center = arrow.center()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        if self.currentIndex() < 0 and self._placeholder:
            edit_rect = self.style().subControlRect(
                QStyle.CC_ComboBox, option, QStyle.SC_ComboBoxEditField, self)
            text = QFontMetrics(self.font()).elidedText(
                self._placeholder, Qt.ElideRight, max(0, edit_rect.width() - 4))
            painter.setPen(QColor(PALETTE["text_disabled"]))
            painter.drawText(
                edit_rect.adjusted(2, 0, -2, 0),
                Qt.AlignVCenter | Qt.AlignLeft, text)
        color = "#596579" if self.isEnabled() else "#9CA3AF"
        pen = QPen(QColor(color), 1.5)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawLine(QPointF(center.x() - 3, center.y() - 1),
                         QPointF(center.x(), center.y() + 2))
        painter.drawLine(QPointF(center.x(), center.y() + 2),
                         QPointF(center.x() + 3, center.y() - 1))
        painter.end()


class StatusBannerFrame(QFrame):
    """Rounded semantic status callout with crisp 1px border and tinted fill."""

    _PALETTES = {
        "error": (PALETTE["danger_bg"], PALETTE["danger_border"]),
        "running": (PALETTE["success_bg"], PALETTE["success_border"]),
        "china": (PALETTE["accent_bg"], PALETTE["accent_border"]),
        "neutral": (PALETTE["surface_subtle"], PALETTE["border_strong"]),
    }

    def paintEvent(self, event):
        mode = ("error" if self.property("error") == "true" else
                "running" if self.property("running") == "true" else
                "china" if self.property("china") == "true" else "neutral")
        bg, border = self._PALETTES[mode]
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(rect, 8.0, 8.0)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillPath(path, QColor(bg))
        painter.setPen(QPen(QColor(border), 1.0))
        painter.drawPath(path)
        painter.end()


class ClickableLabel(QLabel):
    """QLabel that emits clicked when pressed with the left mouse button."""

    clicked = Signal()

    def mouseReleaseEvent(self, event):
        if (event.button() == Qt.LeftButton
                and self.rect().contains(event.position().toPoint())):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class ProfileCard(QFrame):
    clicked = Signal()

    def __init__(self, title, place, detail_text, icon_name="clock",
                 region_key="china", parent=None):
        super().__init__(parent)
        self.setObjectName("ProfileCard")
        self.setProperty("active", "false")
        self.setProperty("pending", "false")
        self.setProperty("pulse", "false")
        self._title = title
        self._active = False
        self._drift = False
        self._icon_name = icon_name
        self._daylight = False
        self._drift_label = "→ rule"
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.setMinimumHeight(110)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAccessibleName(f"切换到{title}环境")
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(350)
        self._pulse_timer.timeout.connect(self._toggle_pulse)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(6)
        self.dot = QLabel()
        self.dot.setFixedSize(8, 8)
        self.dot.setStyleSheet(
            f"background: {PALETTE['border_strong']}; border-radius: 4px;")
        top.addWidget(self.dot, 0, Qt.AlignVCenter)
        top.addSpacing(2)
        top.addWidget(_label(f"{title} · {place}", "ProfileTitle"), 1)
        self.drift_badge = QLabel("代理偏离")
        self.drift_badge.setObjectName("PillRisk")
        self.drift_badge.setVisible(False)
        top.addWidget(self.drift_badge, 0, Qt.AlignVCenter)
        self.hover_hint = QLabel("点击切换")
        self.hover_hint.setObjectName("HoverHint")
        self.hover_hint.setVisible(False)
        top.addWidget(self.hover_hint, 0, Qt.AlignVCenter)
        self.badge = QLabel("当前")
        self.badge.setObjectName("PillActive")
        self.badge.setVisible(False)
        top.addWidget(self.badge, 0, Qt.AlignVCenter)
        layout.addLayout(top)

        clock_row = QHBoxLayout()
        clock_row.setContentsMargins(0, 0, 0, 0)
        clock_row.setSpacing(8)
        self.clock = _label("—", "Clock")
        self.clock.setWordWrap(False)
        clock_row.addWidget(self.clock, 0, Qt.AlignBaseline)
        clock_row.addStretch(1)
        layout.addLayout(clock_row)

        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(5)
        self.offset_chip = QLabel("UTC")
        self.offset_chip.setObjectName("OffsetChip")
        self.offset_chip.setProperty("region", region_key)
        meta_row.addWidget(self.offset_chip, 0, Qt.AlignVCenter)

        self._base_detail = detail_text
        if " · " in detail_text:
            lang_text, proxy_text = detail_text.split(" · ", 1)
        else:
            lang_text, proxy_text = "", detail_text

        self.daylight_sep = _label("·", "MutedSep")
        self.daylight_sep.setWordWrap(False)
        self.daylight_sep.setVisible(False)
        self.daylight_label = _label("夏令时", "Muted")
        self.daylight_label.setWordWrap(False)
        self.daylight_label.setVisible(False)
        meta_row.addWidget(self.daylight_sep, 0, Qt.AlignVCenter)
        meta_row.addWidget(self.daylight_label, 0, Qt.AlignVCenter)

        if lang_text:
            lang_sep = _label("·", "MutedSep")
            lang_sep.setWordWrap(False)
            meta_row.addWidget(lang_sep, 0, Qt.AlignVCenter)
            lang_obj = "MetaLangMono" if region_key == "usa" else "MetaLang"
            self.lang_label = _label(lang_text, lang_obj)
            self.lang_label.setWordWrap(False)
            meta_row.addWidget(self.lang_label, 0, Qt.AlignVCenter)
        else:
            self.lang_label = None

        proxy_sep = _label("·", "MutedSep")
        proxy_sep.setWordWrap(False)
        meta_row.addWidget(proxy_sep, 0, Qt.AlignVCenter)
        self.meta = _label(proxy_text, "MetaProxy")
        self.meta.setWordWrap(False)
        self.meta.setToolTip("目标配置（语言与代理），不代表当前检测结果。")
        meta_row.addWidget(self.meta, 0, Qt.AlignVCenter)
        self.drift_tag = _label("→ rule", "DriftTag")
        self.drift_tag.setWordWrap(False)
        self.drift_tag.setVisible(False)
        meta_row.addWidget(self.drift_tag, 0, Qt.AlignVCenter)
        meta_row.addStretch(1)
        layout.addLayout(meta_row)

    def enterEvent(self, event):
        if not self._active and self.isEnabled():
            self.hover_hint.setVisible(True)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hover_hint.setVisible(False)
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event):
        if (not self._active
                and event.button() == Qt.LeftButton
                and self.rect().contains(event.position().toPoint())):
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Space):
            if not self._active:
                self.clicked.emit()
            event.accept()
            return
        super().keyPressEvent(event)

    def set_time(self, clock_text, offset_text, daylight):
        self.clock.setText(clock_text)
        self.offset_chip.setText(offset_text)
        self._daylight = bool(daylight)
        self._refresh_meta_text()

    def _refresh_meta_text(self):
        self.daylight_sep.setVisible(self._daylight)
        self.daylight_label.setVisible(self._daylight)
        drift_visible = self._drift and self._active
        self.drift_tag.setText(self._drift_label)
        self.drift_tag.setVisible(drift_visible)
        self.meta.setStyleSheet(
            f"color: {PALETTE['danger_accent']}; text-decoration: line-through;"
            if drift_visible else "")

    def set_drift(self, drift, drift_label=None):
        self._drift = bool(drift)
        if drift_label:
            self._drift_label = drift_label
        elif not drift:
            self._drift_label = "→ rule"
        self._sync_dot_and_badges()
        self._refresh_meta_text()

    def _sync_dot_and_badges(self):
        show_drift = self._active and self._drift
        self.drift_badge.setVisible(show_drift)
        self.badge.setVisible(self._active)
        if self._active:
            self.hover_hint.setVisible(False)
        self.setCursor(Qt.ArrowCursor if self._active else Qt.PointingHandCursor)
        self.setAccessibleName(
            f"{self._title}（当前模式）" if self._active
            else f"切换到{self._title}环境")
        color = (PALETTE["danger_dot"] if show_drift
                 else PALETTE["accent"] if self._active
                 else PALETTE["border_strong"])
        self.dot.setStyleSheet(f"background: {color}; border-radius: 4px;")

    def set_active(self, active):
        self._active = bool(active)
        value = "true" if self._active else "false"
        self._sync_dot_and_badges()
        if self.property("active") == value:
            return
        self.setProperty("active", value)
        _repolish(self)
        for child in self.findChildren(QLabel):
            _repolish(child)

    def set_pending(self, pending):
        value = "true" if pending else "false"
        if self.property("pending") == value:
            return
        self.setProperty("pending", value)
        if pending:
            self._pulse_timer.start()
            self._set_pulse(True)
        else:
            self._pulse_timer.stop()
            self._set_pulse(False)
        _repolish(self)

    def _toggle_pulse(self):
        self._set_pulse(self.property("pulse") != "true")

    def _set_pulse(self, value):
        self.setProperty("pulse", "true" if value else "false")
        _repolish(self)


class SettingsCard(QFrame):
    saved = Signal(dict)
    guide_toggled = Signal()
    visibility_changed = Signal(bool)

    _MODE_TIPS = {
        "auto": (
            "自动识别：通过指定代理实测多个出口，检查一致后绑定启动基准。\n"
            "• 不使用下方手动 IP（两者严格二选一）\n"
            "• 运行中出口改变或无法确认时触发保护，重新安全启动才会绑定新基准"
        ),
        "manual": (
            "手动指定 IP：严格校验下方填写的固定公网 IPv4。\n"
            "• 适用于独享固定静态出口 IP，定期检查发现异常时触发保护"
        ),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._manual_ip = ""
        self._saved_manual_ip = ""
        self._saved_state = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        header_wrap = QWidget()
        header = QHBoxLayout(header_wrap)
        header.setContentsMargins(16, 10, 16, 10)
        header.setSpacing(8)
        header.addWidget(_icon_label("server", PALETTE["icon_muted"], 16))
        header.addWidget(_label("节点与 IP 设置", "SettingsTitle"))
        self.unsaved_badge = QLabel("未保存")
        self.unsaved_badge.setObjectName("PillWarn")
        self.unsaved_badge.setVisible(False)
        header.addWidget(self.unsaved_badge, 0, Qt.AlignVCenter)
        header.addStretch(1)
        self.close_btn = PillButton("收起", chevron="up")
        self.close_btn.setObjectName("MiniCollapseBtn")
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.clicked.connect(lambda: self.setVisible(False))
        header.addWidget(self.close_btn)
        layout.addWidget(header_wrap)

        header_rule = QFrame()
        header_rule.setFixedHeight(1)
        header_rule.setStyleSheet(f"background: {PALETTE['divider']};")
        layout.addWidget(header_rule)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(16, 12, 16, 14)
        body_layout.setSpacing(10)

        fields = QGridLayout()
        fields.setContentsMargins(0, 0, 0, 0)
        fields.setHorizontalSpacing(6)
        fields.setVerticalSpacing(10)
        fields.setColumnStretch(1, 1)

        self.node_combo = SelectComboBox()
        self.node_combo.setMinimumContentsLength(4)
        self.node_combo.setMinimumWidth(0)
        self.node_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.node_combo.setAccessibleName("目标节点")
        self.node_combo.setPlaceholder("请选择 Clash 目标节点")
        self.refresh_nodes_btn = QPushButton("刷新节点")
        self.refresh_nodes_btn.setObjectName("GhostBtn")
        self.refresh_nodes_btn.setIcon(_icon("refresh", PALETTE["icon_muted"], 14))
        self.refresh_nodes_btn.setCursor(Qt.PointingHandCursor)

        self.mode_combo = SelectComboBox()
        self.mode_combo.setMinimumWidth(0)
        self.mode_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.mode_combo.setAccessibleName("IP 模式")
        self.mode_combo.addItem("自动识别", "auto")
        self.mode_combo.setItemData(0, self._MODE_TIPS["auto"], Qt.ToolTipRole)
        self.mode_combo.addItem("手动指定 IP", "manual")
        self.mode_combo.setItemData(1, self._MODE_TIPS["manual"], Qt.ToolTipRole)
        self.mode_tip = _label("", "Muted")
        self.mode_tip.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)

        self.ip_input = QLineEdit()
        self.ip_input.setObjectName("IpInput")
        self.ip_input.setMinimumWidth(165)
        self.ip_input.setMaximumWidth(230)
        self.ip_input.setAccessibleName("静态 IP")
        self.ip_input.setPlaceholderText("例如 93.184.216.34")
        ip_overlay = QHBoxLayout(self.ip_input)
        ip_overlay.setContentsMargins(0, 0, 8, 0)
        ip_overlay.setSpacing(0)
        ip_overlay.addStretch(1)
        self._ip_mode_badge = QFrame()
        self._ip_mode_badge.setObjectName("IpBadgeAuto")
        self._ip_mode_badge.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        badge_layout = QHBoxLayout(self._ip_mode_badge)
        badge_layout.setContentsMargins(5, 2, 5, 2)
        badge_layout.setSpacing(3)
        self._ip_lock_icon = _icon_label("lock", PALETTE["icon_muted"], 10)
        badge_layout.addWidget(self._ip_lock_icon, 0, Qt.AlignVCenter)
        self._ip_mode_label = QLabel("自动")
        badge_layout.addWidget(self._ip_mode_label, 0, Qt.AlignVCenter)
        ip_overlay.addWidget(self._ip_mode_badge, 0, Qt.AlignVCenter)

        self.detect_ip_btn = QPushButton("填入当前 IP")
        self.detect_ip_btn.setObjectName("GhostBtn")
        self.detect_ip_btn.setIcon(_icon("target", PALETTE["icon_muted"], 14))
        self.detect_ip_btn.setCursor(Qt.PointingHandCursor)

        self.mode_combo.setParent(self)
        self.mode_combo.hide()
        self.mode_tip.setParent(self)
        self.mode_tip.hide()
        self.mode_segments = QFrame()
        self.mode_segments.setObjectName("Segments")
        self.mode_segments.setFixedHeight(36)
        segment_layout = QHBoxLayout(self.mode_segments)
        segment_layout.setContentsMargins(3, 3, 3, 3)
        segment_layout.setSpacing(2)
        self.auto_mode_btn = QPushButton("自动识别")
        self.manual_mode_btn = QPushButton("手动指定")
        for index, button in enumerate((self.auto_mode_btn, self.manual_mode_btn)):
            button.setObjectName("Segment")
            button.setCheckable(True)
            button.setFixedHeight(28)
            button.setCursor(Qt.PointingHandCursor)
            button.setToolTip(self._MODE_TIPS[("auto", "manual")[index]])
            button.clicked.connect(
                lambda _checked=False, value=index: self._select_mode(value))
            segment_layout.addWidget(button)
        self.mode_help = QPushButton("模式说明")
        self.mode_help.setObjectName("ModeHelpBtn")
        self.mode_help.setIcon(_icon("help_circle", PALETTE["icon_muted"], 14))
        self.mode_help.setCheckable(True)
        self.mode_help.setFocusPolicy(Qt.NoFocus)
        self.mode_help.setCursor(Qt.PointingHandCursor)
        self.mode_help.toggled.connect(self._toggle_mode_guide)

        self.save_btn = QPushButton("保存设置")
        self.save_btn.setObjectName("CompactOutlineBtn")
        self.save_btn.setCursor(Qt.PointingHandCursor)
        self.save_btn.setFixedHeight(36)

        node_label = _label("目标节点", "FieldLabel")
        node_label.setFixedWidth(50)
        node_label.setWordWrap(False)
        node_label.setBuddy(self.node_combo)
        mode_label = _label("IP 模式", "FieldLabel")
        mode_label.setContentsMargins(10, 0, 0, 0)
        mode_label.setWordWrap(False)
        mode_label.setBuddy(self.mode_combo)
        ip_label = _label("静态 IP", "FieldLabel")
        ip_label.setFixedWidth(50)
        ip_label.setWordWrap(False)
        ip_label.setBuddy(self.ip_input)

        fields.addWidget(node_label, 0, 0)
        fields.addWidget(self.node_combo, 0, 1)
        fields.addWidget(self.refresh_nodes_btn, 0, 2)
        fields.addWidget(mode_label, 0, 3)
        fields.addWidget(self.mode_segments, 0, 4)
        fields.addWidget(self.mode_help, 0, 5)

        self.mode_guide_panel = QFrame()
        self.mode_guide_panel.setObjectName("ModeGuidePanel")
        self.mode_guide_panel.setVisible(False)
        guide_grid = QGridLayout(self.mode_guide_panel)
        guide_grid.setContentsMargins(12, 10, 12, 10)
        guide_grid.setHorizontalSpacing(14)
        guide_grid.setVerticalSpacing(4)
        guide_grid.setColumnStretch(0, 1)
        guide_grid.setColumnStretch(1, 1)
        guide_grid.addWidget(_label("自动识别（推荐）", "GuideTitle"), 0, 0)
        guide_grid.addWidget(_label("手动指定（严格静态锁）", "GuideTitle"), 0, 1)
        guide_grid.addWidget(_label(
            "启动前通过指定代理实测多个出口，一致后绑定基准，运行期防止节点漂移。",
            "GuideBody"), 1, 0)
        guide_grid.addWidget(_label(
            "强制绑定固定独享公网 IPv4；一旦代理出口与预设不符立即触发断流保护。",
            "GuideBody"), 1, 1)
        fields.addWidget(self.mode_guide_panel, 1, 0, 1, 6)

        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background: {PALETTE['divider']};")
        fields.addWidget(divider, 2, 0, 1, 6)

        fields.addWidget(ip_label, 3, 0)
        ip_row = QHBoxLayout()
        ip_row.setSpacing(8)
        ip_row.addWidget(self.ip_input)
        ip_row.addWidget(self.detect_ip_btn)
        ip_row.addStretch(1)
        fields.addLayout(ip_row, 3, 1, 1, 4)
        fields.addWidget(self.save_btn, 3, 5, Qt.AlignRight)

        body_layout.addLayout(fields)
        layout.addWidget(body)
        self.setMinimumHeight(164)
        controls = (self.close_btn, self.node_combo, self.refresh_nodes_btn,
                    self.auto_mode_btn, self.manual_mode_btn, self.ip_input,
                    self.detect_ip_btn, self.save_btn)
        for previous, following in zip(controls, controls[1:]):
            QWidget.setTabOrder(previous, following)

        self.ip_input.textEdited.connect(self._on_ip_edited)
        self.ip_input.textChanged.connect(lambda _text: self._sync_dirty_state())
        self.node_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.save_btn.clicked.connect(self._emit_save)
        self._on_mode_changed()

    def _toggle_mode_guide(self, checked):
        self.mode_guide_panel.setVisible(bool(checked))
        icon_color = PALETTE["accent_deep"] if checked else PALETTE["icon_muted"]
        self.mode_help.setIcon(_icon("help_circle", icon_color, 14))
        self.guide_toggled.emit()

    def setVisible(self, visible):
        super().setVisible(visible)
        self.visibility_changed.emit(bool(visible))

    def _select_mode(self, index):
        self.mode_combo.setCurrentIndex(index)
        self.auto_mode_btn.setChecked(index == 0)
        self.manual_mode_btn.setChecked(index == 1)

    def _current_state(self):
        mode = self.mode_combo.currentData() or "auto"
        ip_value = (
            self._manual_ip if mode == "auto"
            else self.ip_input.text().strip())
        return (self.node_combo.currentText().strip(), mode, ip_value)

    def _sync_dirty_state(self):
        dirty = self._saved_state is not None and self._current_state() != self._saved_state
        self.unsaved_badge.setVisible(dirty)
        target_name = "CompactPrimaryBtn" if dirty else "CompactOutlineBtn"
        if self.save_btn.objectName() != target_name:
            _repolish(self.save_btn, target_name)
        self.save_btn.setToolTip(
            "有未保存修改，点击应用设置" if dirty else "当前设置已与配置同步")

    def mark_saved(self, settings):
        node = str(settings.get("targetNode") or "").strip()
        mode = str(settings.get("staticIpMode") or "auto")
        if mode not in ("auto", "manual"):
            mode = "auto"
        ip_value = str(settings.get("staticIp") or "").strip()
        self._saved_manual_ip = ip_value
        self._saved_state = (node, mode, ip_value)
        self._sync_dirty_state()

    def load_values(self, settings, nodes=None):
        node = str(settings.get("targetNode") or "").strip()
        self.node_combo.blockSignals(True)
        self.node_combo.clear()
        items = list(nodes or [])
        if node and node not in items:
            items.insert(0, node)
        for entry in items:
            self.node_combo.addItem(entry)
        node_idx = self.node_combo.findText(node) if node else -1
        self.node_combo.setCurrentIndex(node_idx)
        self.node_combo.blockSignals(False)

        self._manual_ip = str(settings.get("staticIp") or "").strip()
        self._saved_manual_ip = self._manual_ip
        mode = str(settings.get("staticIpMode") or "auto")
        if mode not in ("auto", "manual"):
            mode = "auto"
        idx = self.mode_combo.findData(mode)
        self.mode_combo.blockSignals(True)
        self.mode_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.mode_combo.blockSignals(False)
        self._saved_state = (
            self.node_combo.currentText().strip(),
            mode,
            self._saved_manual_ip,
        )
        self._on_mode_changed()

    def set_nodes(self, nodes):
        """Replace selectable node list while keeping current form edits."""
        current_node = self.node_combo.currentText().strip()
        items = list(nodes or [])
        if current_node and current_node not in items:
            items.insert(0, current_node)
        self.node_combo.blockSignals(True)
        self.node_combo.clear()
        for entry in items:
            self.node_combo.addItem(entry)
        node_idx = self.node_combo.findText(current_node) if current_node else -1
        self.node_combo.setCurrentIndex(node_idx)
        self.node_combo.blockSignals(False)
        self._sync_dirty_state()

    def _on_ip_edited(self, text):
        if self.mode_combo.currentData() == "manual":
            self._manual_ip = text.strip()

    def _on_mode_changed(self):
        mode = self.mode_combo.currentData() or "auto"
        tip = self._MODE_TIPS.get(mode, self._MODE_TIPS["auto"])
        self.mode_combo.setToolTip(tip)
        self.mode_tip.setToolTip(tip)
        self.mode_help.setToolTip(tip)
        self.auto_mode_btn.setChecked(mode == "auto")
        self.manual_mode_btn.setChecked(mode == "manual")
        visible_tip = (
            "启动时实测代理出口并绑定基准，不可手动编辑。"
            if mode == "auto"
            else "填写固定公网 IPv4，保存与检测时严格校验。")
        self.mode_tip.setText(visible_tip)
        self.mode_combo.setAccessibleDescription(visible_tip)
        if mode == "manual":
            self.ip_input.setEnabled(True)
            self.detect_ip_btn.setEnabled(True)
            self.ip_input.setText(self._manual_ip)
            self.ip_input.setPlaceholderText("例如 93.184.216.34")
            self.ip_input.setToolTip("请输入期望锁定的固定公网 IPv4 地址")
            self._ip_lock_icon.setVisible(False)
            self._ip_mode_label.setText("固定")
            _repolish(self._ip_mode_badge, "IpBadgeManual")
        else:
            self.ip_input.setEnabled(False)
            self.detect_ip_btn.setEnabled(False)
            self.ip_input.clear()
            self.ip_input.setPlaceholderText("启动前实测出口")
            self.ip_input.setToolTip("检查通过后绑定实测出口，不使用代理入口服务器地址。")
            self._ip_lock_icon.setVisible(True)
            self._ip_mode_label.setText("自动")
            _repolish(self._ip_mode_badge, "IpBadgeAuto")
        _repolish(self._ip_mode_label)
        self._sync_dirty_state()

    def _emit_save(self):
        mode = self.mode_combo.currentData() or "auto"
        ip_value = (
            self._manual_ip if mode == "auto"
            else self.ip_input.text().strip())
        self.saved.emit({
            "targetNode": self.node_combo.currentText().strip(),
            "staticIpMode": mode,
            "staticIp": ip_value,
        })


class ClaudeControlCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setProperty("role", "primary")
        self.setProperty("tone", "normal")
        self._processes_expanded = False
        self._running = False
        self._cutoff_triggered = False
        self._actions_enabled = True
        self._target_mode = "usa"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 16, 1, 1)
        layout.setSpacing(10)

        header_wrap = QWidget()
        header = QHBoxLayout(header_wrap)
        header.setContentsMargins(19, 0, 19, 0)
        header.setSpacing(10)

        left_col = QVBoxLayout()
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(4)
        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)
        self.state_icon_box = QFrame()
        self.state_icon_box.setFixedSize(24, 24)
        self.state_icon_box.setStyleSheet(
            f"background: {PALETTE['surface_subtle']}; "
            f"border: 1px solid {PALETTE['border']}; border-radius: 6px;")
        box_layout = QHBoxLayout(self.state_icon_box)
        box_layout.setContentsMargins(4, 4, 4, 4)
        self.state_icon_label = _icon_label("cpu", PALETTE["icon_muted"], 14)
        box_layout.addWidget(self.state_icon_label)
        title_row.addWidget(self.state_icon_box)
        title_row.addWidget(_label("Claude Desktop", "ClaudeTitle"), 1)
        left_col.addLayout(title_row)

        self.guard_summary = ClickableLabel("待机")
        self.guard_summary.setObjectName("Muted")
        self.guard_summary.setWordWrap(True)
        self.guard_summary.setMinimumWidth(0)
        self.guard_summary.setVisible(False)
        left_col.addWidget(self.guard_summary)
        header.addLayout(left_col, 1)

        self.process_pill = PillButton(
            "未运行 · 0 进程", dot_color=PALETTE["icon_subtle"], chevron="down")
        self.process_pill.setObjectName("PillNeutral")
        self.process_pill.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.process_pill.setMinimumHeight(26)
        self.process_pill.setCursor(Qt.PointingHandCursor)
        self.process_pill.setToolTip("点击查看已识别的 Claude 进程与防火墙核验状态")
        self.process_pill.clicked.connect(self.toggle_processes)
        header.addWidget(self.process_pill, 0, Qt.AlignVCenter)
        layout.addWidget(header_wrap)

        self.process_panel_wrap = QWidget()
        proc_wrap_layout = QHBoxLayout(self.process_panel_wrap)
        proc_wrap_layout.setContentsMargins(19, 2, 19, 2)
        self.process_panel = QFrame()
        self.process_panel.setObjectName("SubPanel")
        proc_layout = QVBoxLayout(self.process_panel)
        proc_layout.setContentsMargins(12, 8, 12, 8)
        proc_layout.setSpacing(6)

        proc_head = QHBoxLayout()
        proc_head.setSpacing(6)
        proc_head.addWidget(_icon_label("activity", PALETTE["icon_muted"], 14))
        proc_title = _label("进程驻留与防火墙过滤实时核验", "FieldLabel")
        proc_title.setWordWrap(False)
        proc_head.addWidget(proc_title)
        proc_head.addStretch(1)
        self.proc_meta_label = _label("残留进程: 0 · 规则未确认", "ProcRow")
        self.proc_meta_label.setWordWrap(False)
        proc_head.addWidget(self.proc_meta_label)
        proc_layout.addLayout(proc_head)

        proc_div = QFrame()
        proc_div.setFixedHeight(1)
        proc_div.setStyleSheet(f"background: {PALETTE['border']};")
        proc_layout.addWidget(proc_div)

        self.proc_rows = QVBoxLayout()
        self.proc_rows.setSpacing(0)
        proc_layout.addLayout(self.proc_rows)
        proc_wrap_layout.addWidget(self.process_panel)
        self.process_panel_wrap.setVisible(False)
        self.process_panel.setVisible(False)
        layout.addWidget(self.process_panel_wrap)

        self.status_panel = StatusBannerFrame()
        self.status_panel.setObjectName("StatusBanner")
        self.status_panel.setProperty("error", "false")
        self.status_panel.setProperty("running", "false")
        self.status_panel.setProperty("china", "false")
        status_grid = QGridLayout(self.status_panel)
        status_grid.setContentsMargins(14, 10, 14, 10)
        status_grid.setHorizontalSpacing(10)
        status_grid.setVerticalSpacing(4)
        status_grid.setColumnStretch(1, 1)
        self.status_icon = _icon_label("shield_check", PALETTE["icon_muted"], 16)
        status_grid.addWidget(self.status_icon, 0, 0, Qt.AlignVCenter)
        self.status_title = _label("", "StatusTitle")
        self.status_detail = _label("", "StatusDetail")
        status_grid.addWidget(self.status_title, 0, 1)
        status_grid.addWidget(self.status_detail, 1, 1)
        self.quick_fix_btn = QPushButton("恢复全局 TUN")
        self.quick_fix_btn.setObjectName("QuickFixBtn")
        self.quick_fix_btn.setIcon(_icon("wrench", PALETTE["danger_accent"], 13))
        self.quick_fix_btn.setCursor(Qt.PointingHandCursor)
        self.quick_fix_btn.setVisible(False)
        status_grid.addWidget(self.quick_fix_btn, 2, 1, Qt.AlignLeft)
        self.status_panel.setVisible(False)
        status_row = QHBoxLayout()
        status_row.setContentsMargins(19, 0, 19, 0)
        status_row.addWidget(self.status_panel)
        layout.addLayout(status_row)

        action_bar = QFrame()
        action_bar.setObjectName("ActionBar")
        actions = QHBoxLayout(action_bar)
        actions.setContentsMargins(19, 13, 19, 13)
        actions.setSpacing(10)

        self.launch_button = QPushButton("安全启动 Claude")
        self.launch_button.setObjectName("PrimaryBtn")
        self.launch_button.setFixedHeight(40)
        self.launch_button.setMinimumWidth(0)
        self.launch_button.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.launch_button.setCursor(Qt.PointingHandCursor)

        self.kill_button = QPushButton("安全关闭 Claude")
        self.kill_button.setObjectName("DangerIdleBtn")
        self.kill_button.setFixedHeight(40)
        self.kill_button.setMinimumWidth(0)
        self.kill_button.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.kill_button.setCursor(Qt.PointingHandCursor)

        self.apply_button = QPushButton("切回中国模式")
        self.apply_button.setObjectName("SecondaryBtn")
        self.apply_button.setFixedHeight(40)
        self.apply_button.setMinimumWidth(0)
        self.apply_button.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.apply_button.setCursor(Qt.PointingHandCursor)

        self.launch_button.setIcon(_icon("play", PALETTE["surface"], 14, filled=True))
        self.kill_button.setIcon(_icon("power", PALETTE["icon_muted"], 14))
        self.apply_button.setIcon(_icon("switch", PALETTE["icon_muted"], 14))
        actions.addWidget(self.launch_button, 1)
        actions.addWidget(self.kill_button, 1)
        actions.addWidget(self.apply_button, 1)
        layout.addWidget(action_bar)

        self.on_toggle_processes = None
        self._sync_pill_arrow()

    def _sync_pill_arrow(self):
        self.process_pill.set_chevron("up" if self._processes_expanded else "down")

    def toggle_processes(self):
        self.set_processes_expanded(not self._processes_expanded)
        if self.on_toggle_processes:
            self.on_toggle_processes(self._processes_expanded)

    def set_processes_expanded(self, expanded):
        self._processes_expanded = bool(expanded)
        self.process_panel_wrap.setVisible(self._processes_expanded)
        self.process_panel.setVisible(self._processes_expanded)
        self._sync_pill_arrow()

    def update_claude_state(self, running, count, blocked, cutoff_triggered,
                            summary_text):
        self._running = bool(running)
        self._cutoff_triggered = bool(cutoff_triggered)
        tone = ("cutoff" if cutoff_triggered else
                "running" if running else "normal")
        if self.property("tone") != tone:
            self.setProperty("tone", tone)
            _repolish(self)
        if cutoff_triggered:
            self.state_icon_box.setStyleSheet(
                f"background: {PALETTE['danger_bg']}; "
                f"border: 1px solid {PALETTE['danger_border_soft']}; border-radius: 6px;")
            _set_label_icon(
                self.state_icon_label, "shield_alert", PALETTE["danger_dot"], 14)
        elif running:
            self.state_icon_box.setStyleSheet(
                f"background: {PALETTE['success_bg']}; "
                f"border: 1px solid {PALETTE['success_border']}; border-radius: 6px;")
            _set_label_icon(
                self.state_icon_label, "shield_check", PALETTE["success_dot"], 14)
        else:
            self.state_icon_box.setStyleSheet(
                f"background: {PALETTE['surface_subtle']}; "
                f"border: 1px solid {PALETTE['border']}; border-radius: 6px;")
            _set_label_icon(self.state_icon_label, "cpu", PALETTE["icon_muted"], 14)
        self.status_panel.setProperty(
            "running", "true" if running and not cutoff_triggered else "false")
        _repolish(self.status_panel)
        self.quick_fix_btn.setVisible(bool(cutoff_triggered))
        self._sync_launch_button()
        self._sync_kill_button()
        self._sync_pill_arrow()
        if cutoff_triggered:
            _repolish(self.process_pill, "PillRisk")
            self.process_pill.set_dot_color(PALETTE["danger_dot"])
            self.process_pill.set_chevron(
                "up" if self._processes_expanded else "down",
                PALETTE["danger_accent"])
            self.process_pill.setText(f"已紧急断流 · {count} 进程")
        elif running:
            _repolish(self.process_pill, "PillPass")
            self.process_pill.set_dot_color(PALETTE["success_dot"])
            self.process_pill.set_chevron(
                "up" if self._processes_expanded else "down",
                PALETTE["success_subtext"])
            self.process_pill.setText(f"安全守护中 · {count} 进程")
        else:
            _repolish(self.process_pill, "PillNeutral")
            self.process_pill.set_dot_color(PALETTE["icon_subtle"])
            self.process_pill.set_chevron(
                "up" if self._processes_expanded else "down",
                PALETTE["icon_muted"])
            lock_txt = " · 规则已检出" if blocked else ""
            self.process_pill.setText(f"未运行 · {count} 进程{lock_txt}")
        self.guard_summary.setText(summary_text)

    def set_actions_enabled(self, enabled):
        self._actions_enabled = bool(enabled)
        self.apply_button.setEnabled(enabled)
        self.kill_button.setEnabled(enabled)
        self.quick_fix_btn.setEnabled(enabled)
        self._sync_launch_button()
        self._sync_kill_button()

    def _sync_kill_button(self):
        urgent = self._running or self._cutoff_triggered
        target_name = "DangerBtn" if urgent else "DangerIdleBtn"
        if self.kill_button.objectName() != target_name:
            _repolish(self.kill_button, target_name)
        if not self._actions_enabled:
            icon_color = PALETTE["icon_disabled"]
        elif urgent:
            icon_color = PALETTE["danger_accent"]
        else:
            icon_color = PALETTE["icon_muted"]
        self.kill_button.setIcon(_icon("power", icon_color, 14))

    def _sync_launch_button(self):
        self.launch_button.setText(
            "Claude 已运行" if self._running else "安全启动 Claude")
        enabled = self._actions_enabled and not self._running
        self.launch_button.setEnabled(enabled)
        self.launch_button.setIcon(_icon(
            "play",
            PALETTE["surface"] if enabled else PALETTE["icon_disabled"],
            14, filled=True))

    def set_runtime_details(self, snapshot, active_ip="", wfp_isolated=False):
        blocked = bool(snapshot.get("firewall_blocked"))
        service_running = bool(snapshot.get("service_running"))
        processes = snapshot.get("processes") or []
        svc_suffix = " · Cowork 服务运行中" if service_running else ""
        if processes:
            fw_label = (
                "WFP 代理隔离中" if wfp_isolated
                else ("防火墙已锁定" if blocked else "规则未确认"))
            self.proc_meta_label.setText(
                f"受保护进程: {len(processes)} · {fw_label}{svc_suffix}")
        else:
            zero_fw = "直连出站已阻断" if blocked else "规则未确认"
            self.proc_meta_label.setText(
                f"残留进程: 0 · {zero_fw}{svc_suffix}")
        _clear_layout(self.proc_rows)
        if not processes:
            empty_row = QWidget()
            empty_layout = QHBoxLayout(empty_row)
            empty_layout.setContentsMargins(0, 6, 0, 2)
            empty_layout.setSpacing(8)
            empty_layout.addWidget(_label("未检测到运行中的 Claude 进程", "Muted"), 1)
            zero_tag = _label("已终止 · 无残留", "ProcZeroTag")
            zero_tag.setWordWrap(False)
            empty_layout.addWidget(zero_tag, 0, Qt.AlignVCenter)
            empty_row.show()
            self.proc_rows.addWidget(empty_row)
            return
        if wfp_isolated:
            rule_text = (
                f"WFP 网关隔离 → {active_ip}" if active_ip
                else "WFP 严格出站白名单")
        elif blocked:
            rule_text = "防火墙出站已阻断"
        else:
            rule_text = "出站规则未确认"
        protected = wfp_isolated or blocked
        for index, proc in enumerate(processes):
            if index:
                row_div = QFrame()
                row_div.setFixedHeight(1)
                row_div.setStyleSheet(f"background: {PALETTE['border']};")
                row_div.show()
                self.proc_rows.addWidget(row_div)
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 6, 0, 6)
            row_layout.setSpacing(8)
            name_lbl = _label(proc["name"], "ProcName")
            name_lbl.setWordWrap(False)
            role_lbl = _label(proc["role"], "ProcRole")
            role_lbl.setWordWrap(False)
            row_layout.addWidget(name_lbl)
            row_layout.addWidget(role_lbl)
            mem_mb = proc.get("memory_mb") or 0.0
            if mem_mb > 0:
                mem_lbl = _label(f"{mem_mb:.0f} MB", "ProcRole")
                mem_lbl.setWordWrap(False)
                row_layout.addWidget(mem_lbl)
            rule_lbl = _label(rule_text, "ProcRow")
            rule_lbl.setWordWrap(False)
            pid_text = (
                f"PID {proc['pid']} · 受控" if protected
                else f"PID {proc['pid']}")
            pid_tag = _label(pid_text, "ProcPidTag")
            pid_tag.setWordWrap(False)
            row_layout.addStretch(1)
            row_layout.addWidget(rule_lbl)
            row_layout.addWidget(pid_tag)
            row.show()
            self.proc_rows.addWidget(row)


class RiskCard(QFrame):
    toggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._expanded = False
        self._items = []
        self._checked_at = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        header_wrap = QWidget()
        header = QHBoxLayout(header_wrap)
        header.setContentsMargins(16, 12, 16, 12)
        header.setSpacing(10)

        left_col = QVBoxLayout()
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(3)
        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)
        title_row.addWidget(_icon_label("report", PALETTE["icon_muted"], 16))
        title_row.addWidget(_label("安全检测报告", "CardTitle"))
        self.summary_pill = QLabel("未检测")
        self.summary_pill.setObjectName("PillNeutral")
        title_row.addWidget(self.summary_pill, 0, Qt.AlignVCenter)
        title_row.addStretch(1)
        left_col.addLayout(title_row)

        self.checked_label = _label("最近检测：尚未检测", "Muted")
        left_col.addWidget(self.checked_label)
        header.addLayout(left_col, 1)

        self.recheck_button = QPushButton("重新检测")
        self.recheck_button.setObjectName("GhostBtn")
        self.recheck_button.setIcon(_icon("refresh", PALETTE["icon_muted"], 14))
        self.recheck_button.setCursor(Qt.PointingHandCursor)

        self.toggle_button = PillButton("展开详情", chevron="down")
        self.toggle_button.setObjectName("SoftBtn")
        self.toggle_button.setCursor(Qt.PointingHandCursor)
        self.toggle_button.clicked.connect(self.toggle)

        header.addWidget(self.recheck_button, 0, Qt.AlignVCenter)
        header.addWidget(self.toggle_button, 0, Qt.AlignVCenter)
        layout.addWidget(header_wrap)

        self.body = QWidget()
        body_layout = QVBoxLayout(self.body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        body_rule = QFrame()
        body_rule.setFixedHeight(1)
        body_rule.setStyleSheet(f"background: {PALETTE['divider']};")
        body_layout.addWidget(body_rule)

        inner_wrap = QWidget()
        inner_layout = QVBoxLayout(inner_wrap)
        inner_layout.setContentsMargins(16, 10, 16, 12)
        self.rows_box = QFrame()
        self.rows_box.setObjectName("AuditListBox")
        self.rows = QVBoxLayout(self.rows_box)
        self.rows.setContentsMargins(0, 4, 0, 4)
        self.rows.setSpacing(0)
        inner_layout.addWidget(self.rows_box)
        body_layout.addWidget(inner_wrap)
        self.body.setVisible(False)
        layout.addWidget(self.body)

        self._render_empty()

    def toggle(self):
        self.set_expanded(not self._expanded)

    def set_expanded(self, expanded):
        self._expanded = bool(expanded)
        self.body.setVisible(self._expanded)
        self.toggle_button.setText("收起详情" if self._expanded else "展开详情")
        self.toggle_button.set_chevron("up" if self._expanded else "down")
        self.toggled.emit(self._expanded)

    def _render_empty(self):
        _clear_layout(self.rows)
        empty = _label(
            "尚未执行检测，点击「重新检测」或「安全启动 Claude」获取完整报告。",
            "Muted")
        empty.setContentsMargins(14, 8, 14, 8)
        empty.show()
        self.rows.addWidget(empty)

    def set_checking(self):
        self._set_pending("检测中…", "正在执行安全检测，请等待本次结果。", True)

    def set_preparing(self):
        self._set_pending("准备中…", "正在准备环境，尚未开始本次安全检测。", True)

    def set_incomplete(self):
        self._set_pending("检测未完成", "本次未获得完整报告，请重新检测。", False)

    def _set_pending(self, badge, detail, active_blue):
        _repolish(self.summary_pill, "PillChecking" if active_blue else "PillNeutral")
        self.summary_pill.setText(badge)
        if self._items:
            self.checked_label.setText(
                detail + " 下方为上次报告（非本次结果）：" + self._checked_at)
        else:
            self.checked_label.setText("本次检测：" + badge)
            _clear_layout(self.rows)
            note = _label(detail, "Muted")
            note.setContentsMargins(14, 8, 14, 8)
            note.show()
            self.rows.addWidget(note)
        self.toggled.emit(self._expanded)

    def reset(self):
        self._items = []
        self._checked_at = ""
        self.checked_label.setText("最近检测：尚未检测")
        _repolish(self.summary_pill, "PillNeutral")
        self.summary_pill.setText("未检测")
        self._render_empty()
        self.toggled.emit(self._expanded)

    def set_items(self, items, auto_expand_on_risk=True):
        self._items = list(items or [])
        _clear_layout(self.rows)
        if not self._items:
            self.reset()
            return

        local_now = datetime.now().astimezone()
        checked_at = local_now.strftime("%Y-%m-%d %H:%M:%S")
        self._checked_at = checked_at
        self.checked_label.setText("最近检测：" + checked_at)
        tz_offset = local_now.strftime("%z")
        if len(tz_offset) == 5:
            tz_offset = f"UTC{tz_offset[:3]}:{tz_offset[3:]}"
        self.checked_label.setToolTip(
            f"检测完成时的系统本地时间（{tz_offset or '本地时区'}）")

        total = len(self._items)
        passed = sum(1 for entry in self._items if entry.get("status") == "pass")
        risks = sum(1 for entry in self._items if entry.get("status") == "risk")
        if passed == total:
            _repolish(self.summary_pill, "PillPass")
            self.summary_pill.setText(f"{passed}/{total} 安全通过")
        elif risks > 0:
            _repolish(self.summary_pill, "PillRisk")
            self.summary_pill.setText(f"发现 {risks} 项异常")
        else:
            _repolish(self.summary_pill, "PillNeutral")
            self.summary_pill.setText("有待确认")

        severity_order = {"risk": 0, "unknown": 1, "pass": 2}
        ordered_items = sorted(
            self._items,
            key=lambda entry: severity_order.get(entry.get("status"), 1))
        for index, entry in enumerate(ordered_items):
            if index:
                separator = QFrame()
                separator.setFixedHeight(1)
                separator.setStyleSheet(f"background: {PALETTE['divider']};")
                separator.show()
                self.rows.addWidget(separator)
            status = entry.get("status")
            if status == "pass":
                row_name = "AuditRowPass"
                icon_name, icon_color = "check_circle", PALETTE["success_dot"]
                badge_name, badge_text = "AuditBadgePass", "通过"
            elif status == "risk":
                row_name = "AuditRowRisk"
                icon_name, icon_color = "alert_triangle", PALETTE["danger_dot"]
                badge_name, badge_text = "AuditBadgeRisk", "风险"
            else:
                row_name = "AuditRowUnknown"
                icon_name, icon_color = "circle_dashed", PALETTE["warning_dot"]
                badge_name, badge_text = "AuditBadgeUnknown", "待确认"

            row = QWidget()
            row.setObjectName(row_name)
            row_layout = QGridLayout(row)
            row_layout.setContentsMargins(14, 7, 14, 7)
            row_layout.setHorizontalSpacing(10)
            row_layout.setVerticalSpacing(2)
            row_layout.setColumnStretch(1, 1)

            row_layout.addWidget(_icon_label(icon_name, icon_color, 16), 0, 0, Qt.AlignTop)
            row_layout.addWidget(_label(entry["name"], "RiskName"), 0, 1)
            row_layout.addWidget(_label(entry["detail"], "AuditDetail"), 1, 1)

            tag = QLabel(badge_text)
            tag.setObjectName(badge_name)
            tag.setAlignment(Qt.AlignCenter)
            tag.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            row_layout.addWidget(tag, 0, 2, 2, 1, Qt.AlignVCenter)
            row.show()
            self.rows.addWidget(row)

        if auto_expand_on_risk and passed < total:
            self.set_expanded(True)
        else:
            self.toggled.emit(self._expanded)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        _ensure_app_fonts()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumWidth(640)
        self.resize(700, 700)
        self.setWindowIcon(QIcon(str(ICON_PATH)))
        self.exit_allowed = False
        self.on_close = None
        self.on_settings_opening = None
        self._initial_focus_done = False
        self._fit_timer = QTimer(self)
        self._fit_timer.setSingleShot(True)
        self._fit_timer.setInterval(0)
        self._fit_timer.timeout.connect(self.fit_height)
        self._build()
        self.apply_active(None)
        self.fit_height()

    def _build(self):
        central = QWidget()
        central.setObjectName("Root")
        central.setFocusPolicy(Qt.ClickFocus)
        shell = QVBoxLayout(central)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        self.setCentralWidget(central)

        self.top_frame = QFrame()
        self.top_frame.setObjectName("TopBar")
        self.top_frame.setFixedHeight(56)
        top_frame = self.top_frame
        topbar = QHBoxLayout(top_frame)
        topbar.setContentsMargins(20, 10, 20, 10)
        topbar.setSpacing(8)

        brand_icon = _icon_label("brand_shield", PALETTE["surface"], 16)
        brand_box = QFrame()
        brand_box.setFixedSize(28, 28)
        brand_box.setStyleSheet(
            f"background: {PALETTE['ink']}; border-radius: 8px;")
        brand_layout = QHBoxLayout(brand_box)
        brand_layout.setContentsMargins(6, 6, 6, 6)
        brand_layout.addWidget(brand_icon)
        topbar.addWidget(brand_box)
        brand_title = _label(APP_TITLE, "BrandTitle")
        brand_title.setWordWrap(False)
        topbar.addWidget(brand_title)

        self.outbound_pill = QFrame()
        self.outbound_pill.setObjectName("OutboundPill")
        self.outbound_pill.setProperty("locked", "false")
        pill_layout = QHBoxLayout(self.outbound_pill)
        pill_layout.setContentsMargins(9, 4, 10, 4)
        pill_layout.setSpacing(5)
        self.outbound_icon = _icon_label(
            "shield_alert", PALETTE["warning_text"], 13)
        pill_layout.addWidget(self.outbound_icon, 0, Qt.AlignVCenter)
        self.firewall_badge = _label("出站规则未确认", "OutboundText")
        self.firewall_badge.setWordWrap(False)
        pill_layout.addWidget(self.firewall_badge, 0, Qt.AlignVCenter)
        topbar.addWidget(self.outbound_pill, 0, Qt.AlignVCenter)

        self.endpoint_pill = QPushButton("未指定节点 · 自动识别")
        self.endpoint_pill.setObjectName("EndpointPill")
        self.endpoint_pill.setCursor(Qt.PointingHandCursor)
        self.endpoint_pill.setToolTip("点击展开节点与 IP 设置")
        self.endpoint_pill.clicked.connect(lambda: self.settings_button.click())
        topbar.addWidget(self.endpoint_pill, 0, Qt.AlignVCenter)

        self.endpoint_label = _label("目标节点与 IP 尚未确认", "Endpoint", top_frame)
        self.endpoint_label.setWordWrap(False)
        self.endpoint_label.hide()

        topbar.addStretch(1)

        self.settings_button = QPushButton("节点与 IP 设置")
        self.settings_button.setObjectName("CompactOutlineBtn")
        self.settings_button.setIcon(_icon("sliders", PALETTE["icon_muted"], 14))
        self.settings_button.setCursor(Qt.PointingHandCursor)
        self.settings_button.clicked.connect(self.toggle_settings)
        topbar.addWidget(self.settings_button, 0, Qt.AlignVCenter)
        shell.addWidget(top_frame)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.root = QWidget()
        self.root.setObjectName("Root")
        self.scroll.setWidget(self.root)
        shell.addWidget(self.scroll, 1)

        content = QVBoxLayout(self.root)
        content.setContentsMargins(20, 16, 20, 16)
        content.setSpacing(12)

        initial_settings = risk_check.load_settings()
        self.settings_card = SettingsCard()
        self.settings_card.load_values(initial_settings)
        self.settings_card.setVisible(False)
        content.addWidget(self.settings_card)

        self.claude_card = ClaudeControlCard()
        self.apply_button = self.claude_card.apply_button
        self.launch_button = self.claude_card.launch_button
        self.kill_button = self.claude_card.kill_button
        self.status_panel = self.claude_card.status_panel
        self.status_title = self.claude_card.status_title
        self.status_detail = self.claude_card.status_detail
        content.addWidget(self.claude_card)

        profiles = QHBoxLayout()
        profiles.setContentsMargins(0, 0, 0, 0)
        profiles.setSpacing(12)
        self.china_card = ProfileCard(
            "中国", "北京", "简体中文 · 规则代理",
            icon_name="clock", region_key="china")
        self.usa_card = ProfileCard(
            "美国", "洛杉矶", "en-US · 全局 TUN 代理",
            icon_name="globe", region_key="usa")
        profiles.addWidget(self.china_card, 1)
        profiles.addWidget(self.usa_card, 1)
        content.addLayout(profiles)

        self.risk_card = RiskCard()
        self.recheck_button = self.risk_card.recheck_button
        content.addWidget(self.risk_card)
        content.addStretch(1)

        self.footer = QFrame()
        self.footer.setObjectName("Footer")
        footer = self.footer
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(20, 8, 20, 8)
        footer_layout.setSpacing(6)
        self.footer_dot = StatusDot(
            PALETTE["warning_dot"], PALETTE["warning_dot"], size=6, with_ring=False)
        footer_layout.addWidget(self.footer_dot, 0, Qt.AlignVCenter)
        self.footer_endpoint = _label("节点: 未指定节点", "EndpointFooter")
        self.footer_endpoint.setWordWrap(False)
        footer_layout.addWidget(self.footer_endpoint)
        footer_layout.addStretch(1)
        self.scroll_hint = _label("↓ 向下滚动查看全部", "ScrollHint")
        self.scroll_hint.setWordWrap(False)
        self.scroll_hint.setVisible(False)
        footer_layout.addWidget(self.scroll_hint)
        footer_layout.addStretch(1)
        self.footer_mode = _label("IP 模式: 自动识别", "EndpointFooter")
        self.footer_mode.setWordWrap(False)
        footer_layout.addWidget(self.footer_mode)
        shell.addWidget(footer)
        self.set_endpoint(initial_settings)
        self._sync_settings_header(False)

        self.risk_card.toggled.connect(lambda _exp: self._schedule_fit_height())
        self.settings_card.guide_toggled.connect(self._schedule_fit_height)
        self.settings_card.visibility_changed.connect(self._on_settings_visibility_changed)
        self.settings_card.close_btn.clicked.connect(self._schedule_fit_height)
        vbar = self.scroll.verticalScrollBar()
        vbar.valueChanged.connect(self._sync_scroll_hint)
        vbar.rangeChanged.connect(self._sync_scroll_hint)

    def _schedule_fit_height(self):
        self._fit_timer.start()

    def toggle_settings(self):
        visible = not self.settings_card.isVisible()
        if visible and self.on_settings_opening is not None:
            self.on_settings_opening()
        self.settings_card.setVisible(visible)
        self._schedule_fit_height()

    def _sync_scroll_hint(self, *_args):
        bar = self.scroll.verticalScrollBar()
        self.scroll_hint.setVisible(
            bar.maximum() > 0 and bar.value() < bar.maximum())

    def _on_settings_visibility_changed(self, visible):
        self._sync_settings_header(visible)
        self._schedule_fit_height()

    def _sync_settings_header(self, visible):
        if visible:
            _repolish(self.settings_button, "CompactActiveBtn")
            self.settings_button.setIcon(
                _icon("settings", PALETTE["accent_deep"], 14))
        else:
            _repolish(self.settings_button, "CompactOutlineBtn")
            self.settings_button.setIcon(
                _icon("sliders", PALETTE["icon_muted"], 14))
        self.endpoint_pill.setVisible(not visible)

    def set_apply_enabled(self, enabled):
        self.claude_card.set_actions_enabled(enabled)
        self.recheck_button.setEnabled(enabled)
        self.settings_button.setEnabled(enabled)
        self.china_card.setEnabled(enabled)
        self.usa_card.setEnabled(enabled)

    def set_apply_label(self, target_mode):
        if target_mode == "china":
            self.apply_button.setText("切回中国模式")
            _repolish(self.apply_button, "SecondaryBtn")
            self.apply_button.setIcon(_icon("switch", PALETTE["icon_muted"], 14))
            self.apply_button.setToolTip(
                "安全关闭 Claude，恢复北京时间、简体中文及 Clash 规则模式")
        else:
            self.apply_button.setText("切换美区模式")
            _repolish(self.apply_button, "BlueSecondaryBtn")
            self.apply_button.setIcon(_icon("switch", PALETTE["accent_deep"], 14))
            self.apply_button.setToolTip(
                "切换到洛杉矶时区、en-US 与 Clash 全局目标节点，并执行检测")

    def set_apply_tooltip(self, text):
        self.apply_button.setToolTip(text)

    def set_firewall_badge(self, blocked, wfp_isolated=False):
        if blocked:
            self.outbound_pill.setProperty("locked", "true")
            _repolish(self.outbound_pill)
            _repolish(self.firewall_badge)
            _set_label_icon(
                self.outbound_icon, "shield_check", PALETTE["success_subtext"], 13)
            self.firewall_badge.setText("已锁出站防漏")
            self.outbound_pill.setToolTip("已检出 Windows 防火墙出站阻止规则")
            self.footer_dot.set_colors(PALETTE["success_dot"], PALETTE["success_dot"])
        elif wfp_isolated:
            self.outbound_pill.setProperty("locked", "true")
            _repolish(self.outbound_pill)
            _repolish(self.firewall_badge)
            _set_label_icon(
                self.outbound_icon, "shield_check", PALETTE["success_subtext"], 13)
            self.firewall_badge.setText("WFP 代理隔离中")
            self.outbound_pill.setToolTip(
                "已启用 WFP 出站隔离，仅允许经本机受控代理网关出站")
            self.footer_dot.set_colors(PALETTE["success_dot"], PALETTE["success_dot"])
        else:
            self.outbound_pill.setProperty("locked", "false")
            _repolish(self.outbound_pill)
            _repolish(self.firewall_badge)
            _set_label_icon(
                self.outbound_icon, "shield_alert", PALETTE["warning_text"], 13)
            self.firewall_badge.setText("出站规则未确认")
            self.outbound_pill.setToolTip("尚未确认 Windows 防火墙出站阻止规则")
            self.footer_dot.set_colors(PALETTE["warning_dot"], PALETTE["warning_dot"])

    def set_endpoint(self, settings, active_ip=""):
        node = str(settings.get("targetNode") or "未指定节点")
        mode = str(settings.get("staticIpMode") or "auto")
        configured = str(settings.get("staticIp") or "").strip() if mode == "manual" else ""
        ip_display = str(active_ip or configured or "").strip()
        ip_text = ip_display or "待识别"
        self.endpoint_label.setText(
            f"目标节点：{node}  ·  IP 模式：" +
            ("自动识别" if mode == "auto" else f"手动指定 · {ip_text}"))
        elided_node = QFontMetrics(self.endpoint_pill.font()).elidedText(
            node, Qt.ElideRight, 72)
        suffix = ip_display if ip_display else "自动识别"
        self.endpoint_pill.setText(f"{elided_node} · {suffix}")
        self.footer_endpoint.setText(
            f"锁定出口: {ip_display}" if ip_display else f"节点: {elided_node}")
        self.footer_mode.setText(
            "IP 模式: 自动识别" if mode == "auto" else "IP 模式: 手动固定")

    def apply_active(self, mode):
        self.china_card.set_active(mode == "china")
        self.usa_card.set_active(mode == "usa")

    def set_pending_mode(self, mode):
        self.china_card.set_pending(mode == "china")
        self.usa_card.set_pending(mode == "usa")

    def set_status(self, title, detail, error, tone=None):
        self.status_panel.setVisible(True)
        is_error = bool(error)
        is_running = (not is_error and tone == "running")
        is_china = (not is_error and tone == "china")
        self.status_panel.setProperty("error", "true" if is_error else "false")
        self.status_panel.setProperty("running", "true" if is_running else "false")
        self.status_panel.setProperty("china", "true" if is_china else "false")
        _repolish(self.status_panel)
        _repolish(self.status_title)
        _repolish(self.status_detail)
        if is_error:
            _set_label_icon(
                self.claude_card.status_icon, "alert_octagon", PALETTE["danger_dot"], 16)
        elif is_running:
            _set_label_icon(
                self.claude_card.status_icon, "check_circle", PALETTE["success_dot"], 16)
        elif is_china:
            _set_label_icon(
                self.claude_card.status_icon, "switch", PALETTE["accent"], 16)
        else:
            _set_label_icon(
                self.claude_card.status_icon, "shield_check", PALETTE["icon_muted"], 16)
        self.status_title.setText(title)
        self.status_detail.setText(detail)
        self.fit_height()
        self._schedule_fit_height()

    def hide_status(self):
        self.status_panel.setVisible(False)
        self.fit_height()
        self._schedule_fit_height()

    def set_risk_items(self, items):
        if isinstance(items, dict):
            items = items.get("items") or []
        self.risk_card.set_items(items)
        self.fit_height()
        self._schedule_fit_height()

    def clear_risk(self):
        self.risk_card.reset()
        self.fit_height()
        self._schedule_fit_height()

    def set_clock(self, prefix, value, offset, daylight):
        card = self.china_card if prefix == "china" else self.usa_card
        card.set_time(value, offset, daylight)

    def fit_height(self):
        _invalidate_layout_tree(self.root)
        layout = self.root.layout()
        viewport_width = self.scroll.viewport().width()
        width = (viewport_width
                 if self.isVisible() and viewport_width > 0
                 else max(viewport_width, self.width(), self.minimumWidth()))
        content_hint = (layout.totalHeightForWidth(width)
                        if layout.hasHeightForWidth()
                        else layout.sizeHint().height())
        hint = (content_hint + self.top_frame.height()
                + self.footer.sizeHint().height())
        screen = self.screen()
        available = screen.availableGeometry().height() if screen else 1080
        height = min(max(hint + 4, 240), int(available * 0.9))
        if (not self.isMaximized() and not self.isFullScreen()
                and self.height() != height):
            self.resize(self.width(), height)
        self.root.updateGeometry()
        QTimer.singleShot(0, self._sync_scroll_hint)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._initial_focus_done:
            self._initial_focus_done = True
            if self.focusWidget() in (None, self.endpoint_pill, self.settings_button):
                self.centralWidget().setFocus()
        self._schedule_fit_height()

    def closeEvent(self, event):
        if self.on_close is not None:
            self.on_close(event)
            return
        if self.exit_allowed:
            event.accept()
        else:
            event.ignore()
            self.hide()


class ApplyTask(QThread):
    progress = Signal(str)
    done = Signal(bool)
    failed = Signal(object)

    def __init__(self, workflow, mode, close_claude_first=False):
        super().__init__()
        self.workflow = workflow
        self.mode = mode
        self.close_claude_first = close_claude_first

    def run(self):
        try:
            if self.close_claude_first:
                claude_desktop.close_claude_desktop(
                    graceful=True, block_network=True,
                    progress=self.progress.emit)
            restarted = self.workflow.apply(self.mode, self.progress.emit)
            self.done.emit(restarted)
        except Exception as error:
            self.failed.emit(error)


class RiskTask(QThread):
    done = Signal(object)
    failed = Signal(object)

    def run(self):
        try:
            self.done.emit(risk_check.run_checks(client=risk_check.HttpClient(
                proxy_port=risk_check._clash_mixed_port())))
        except Exception as error:
            self.failed.emit(error)


class SafeLaunchTask(QThread):
    progress = Signal(str)
    checking_started = Signal()
    risk_ready = Signal(object)
    done = Signal(object)
    failed = Signal(object, object)
    protection_failed = Signal(str, object)

    def __init__(self, workflow, service, proxy):
        super().__init__()
        self.workflow = workflow
        self.service = service
        self.proxy = proxy
        self.protection_callback = self.protection_failed.emit

    def run(self):
        report = None
        try:
            import protected_session
            protected_session.stop()
            claude_desktop.close_claude_desktop(
                graceful=False, block_network=True)
            state = self.service.read()
            effective_lang = (
                getattr(state, "languages", "")
                or getattr(state, "browser_languages", "")
                or ""
            ).lower()
            is_usa = (
                state.timezone_id.lower() == USA_TZ.lower()
                and (not effective_lang or effective_lang.startswith("en"))
            )
            usa_proxy_ok, _reason = self.proxy.verify_usa_active()
            if not is_usa or not usa_proxy_ok:
                self.progress.emit("正在自动切换到美国模式并启用目标节点…")
                self.workflow.apply("usa", self.progress.emit)

            self.progress.emit("正在执行启动前安全检查…")
            self.checking_started.emit()
            upstream_port = risk_check._clash_mixed_port()
            report = risk_check.run_checks(
                client=risk_check.HttpClient(proxy_port=upstream_port))
            self.risk_ready.emit(report)

            passed, message = claude_desktop.validate_prelaunch_report(report)
            if not passed:
                claude_desktop.block_claude_traffic()
                raise RuntimeError(message)

            if self.isInterruptionRequested():
                raise RuntimeError("紧急保护已触发，已取消本次启动。")
            monitor = claude_desktop.EnvironmentMonitor(
                self.service, self.proxy)
            monitor.proxy_port = upstream_port
            for entry in report.get("items", []):
                if entry.get("name") == risk_check.ITEM_NAMES[1]:
                    monitor.set_baseline_ip(risk_check._first_ipv4(
                        entry.get("detail", "")))
                    break
            binaries = claude_desktop.find_all_claude_binaries()
            protected_session.start(
                monitor, upstream_port, binaries, self.protection_callback)
            self.progress.emit(message + "，正在解锁防火墙并启动 Claude Desktop…")
            claude_desktop.launch_claude_desktop(binaries=binaries)
            self.done.emit(report)
        except Exception as error:
            try:
                protected_session.stop()
            except Exception as cleanup_error:
                error = RuntimeError("{}；保护清理失败：{}".format(
                    error, cleanup_error))
            self.failed.emit(error, report)


class CloseClaudeTask(QThread):
    progress = Signal(str)
    done = Signal()
    failed = Signal(object)

    def run(self):
        try:
            claude_desktop.close_claude_desktop(
                graceful=True, block_network=True,
                progress=self.progress.emit)
            self.done.emit()
        except Exception as error:
            self.failed.emit(error)


class IpMonitorTask(QThread):
    result_ready = Signal(bool, str)

    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def run(self):
        try:
            ok, reason = self.monitor.check_remote_ip()
            self.result_ready.emit(ok, reason)
        except Exception as error:
            self.result_ready.emit(False, str(error))


class DetectExitIpTask(QThread):
    done = Signal(str, str)

    def run(self):
        try:
            client = risk_check.HttpClient(
                total_timeout=8.0, proxy_port=risk_check._clash_mixed_port())
            ip = risk_check.fetch_trace_ip(client, risk_check.CLAUDE_TRACE_URL)
            if not ip:
                ip = risk_check.fetch_trace_ip(
                    client, risk_check.CLOUDFLARE_TRACE_URL)
            self.done.emit(ip, "" if ip else "未能获取当前公网出口 IP")
        except Exception as error:
            self.done.emit("", str(error))


class LoadNodesTask(QThread):
    done = Signal(object)

    def __init__(self, proxy):
        super().__init__()
        self.proxy = proxy

    def run(self):
        try:
            nodes = self.proxy.list_global_nodes()
        except Exception:
            nodes = []
        self.done.emit(nodes)


class ProcessDetailsTask(QThread):
    done = Signal(object)

    def run(self):
        try:
            snapshot = claude_desktop.inspect_claude_runtime()
            self.done.emit(snapshot)
        except Exception:
            pass


class StartupRegisterTask(QThread):
    failed = Signal(object)

    def run(self):
        try:
            startup_tasks.ensure_registered()
        except Exception as error:
            self.failed.emit(error)


def _format_drift_label(reason):
    text = str(reason or "").lower()
    if "rule" in text:
        return "→ rule"
    if "direct" in text:
        return "→ direct"
    if "tun" in text:
        return "→ TUN 关闭"
    if "时区" in text:
        return "→ 时区变更"
    if "语言" in text:
        return "→ 语言变更"
    if "节点" in text:
        return "→ 节点变更"
    if "出口 ip" in text:
        return "→ IP 异常"
    return "→ 异常"


class Controller(QObject):
    state_changed = Signal()
    risk_completed = Signal(object)
    emergency_cutoff = Signal(str)
    background_failure = Signal(object, str, object)

    def __init__(self, window, preview=False, service=None, browser=None,
                 proxy=None, risk_runner=None):
        super().__init__()
        self.window = window
        self.preview = preview
        self.service = service or RegionService()
        self.proxy = proxy or ClashProxySwitch()
        self.workflow = None
        self.monitor = claude_desktop.EnvironmentMonitor(
            self.service, self.proxy)
        self.busy = False
        self.switch_failed = False
        self.cutoff_triggered = False
        self._cutoff_lock = threading.Lock()
        self.target_mode = "usa"
        self.current_mode = "china"
        self.risk_status = None
        self.tray_status = APP_TITLE
        self._apply_task = None
        self._risk_task = None
        self._launch_task = None
        self._launch_generation = None
        self._close_task = None
        self._ip_task = None
        self._detect_ip_task = None
        self._nodes_task = None
        self._cached_nodes = []
        self._process_details_task = None
        self._startup_task = None
        self._tick_counter = 0
        self._firewall_blocked = False
        self._wfp_isolated = False
        self._was_claude_running = False
        self._has_explicit_status = False
        self._explicit_status_kind = None
        self._drift_label = "→ rule"
        self.background_failure.connect(self._on_background_cutoff)

        if not preview:
            self.workflow = self._make_workflow(browser, self.proxy)
            self._firewall_blocked = claude_desktop.is_traffic_blocked()
            self.window.set_firewall_badge(self._firewall_blocked)

        self.window.apply_button.clicked.connect(
            lambda: self.switch_mode(self.target_mode))
        self.window.china_card.clicked.connect(lambda: self.switch_mode("china"))
        self.window.usa_card.clicked.connect(lambda: self.switch_mode("usa"))
        self.window.launch_button.clicked.connect(self.safe_launch_claude)
        self.window.kill_button.clicked.connect(self.close_claude)
        self.window.claude_card.quick_fix_btn.clicked.connect(
            lambda: self.switch_mode("usa", force=True))
        self.window.recheck_button.clicked.connect(self.manual_recheck)
        self.window.on_settings_opening = self._load_settings_ui
        self.window.settings_card.refresh_nodes_btn.clicked.connect(
            self._start_load_nodes)
        self.window.settings_card.detect_ip_btn.clicked.connect(
            self._detect_current_exit_ip)
        self.window.settings_card.saved.connect(self._save_settings)
        self.window.claude_card.on_toggle_processes = self._on_toggle_processes
        self.window.on_close = self._on_close

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._on_tick)
        self.timer.start()
        self.read_state()
        self._update_clocks()
        self._refresh_claude_status()

    def _set_explicit_status(self, title, detail, error, tone=None, kind=None):
        self._has_explicit_status = True
        self._explicit_status_kind = kind
        self.window.set_status(title, detail, error, tone=tone)

    def _sync_ambient_status(self, running, count=0):
        if self._has_explicit_status or self.busy:
            return
        if self.cutoff_triggered:
            self.window.set_status(
                "紧急断流保护已触发：Claude 流量已切断",
                "检测到环境异常变化，已终止相关进程并锁定防火墙出站规则。",
                True)
        elif running:
            ip = self._active_whitelist_ip()
            proc_part = f"已识别 {count} 个进程，" if count else ""
            exit_part = f"（当前锁定出口 {ip}）" if ip else ""
            hint_part = (
                "" if self.window.claude_card._processes_expanded
                else "，可在右上角展开进程详情")
            self.window.set_status(
                "双重防漏守护运行中：Claude Desktop 受控运行",
                f"{proc_part}WFP 代理隔离与全局 TUN 隧道正常运行中{exit_part}{hint_part}。",
                False, tone="running")
        else:
            self.window.hide_status()

    def _make_workflow(self, browser, proxy):
        from edge_lifecycle import ClaudeGuardWorkflow
        return ClaudeGuardWorkflow(
            self.service,
            browser or WindowsBrowserLifecycle(),
            proxy or ClashProxySwitch())

    def _on_close(self, event):
        if self.busy:
            event.ignore()
            self._set_explicit_status(
                "正在执行操作，请稍候", "当前任务完成后即可关闭窗口。", False)
            return
        if self.window.exit_allowed:
            if not self.preview:
                import protected_session
                protected_session.close_gate("保护程序退出")
                claude_desktop.cut_off_claude_traffic("保护程序退出")
                protected_session.stop()
            self.timer.stop()
            for task in (self._ip_task, self._detect_ip_task, self._risk_task,
                         self._nodes_task, self._process_details_task,
                         self._startup_task):
                if task is not None and task.isRunning():
                    task.wait(1500)
            event.accept()
            return
        event.ignore()
        self.window.hide()

    def toggle_settings(self):
        self.window.toggle_settings()

    def _active_whitelist_ip(self):
        monitor = getattr(self, "monitor", None)
        baseline = str(getattr(monitor, "baseline_ip", "") or "").strip()
        if baseline:
            return baseline
        settings = risk_check.load_settings()
        if str(settings.get("staticIpMode") or "auto") != "manual":
            return ""
        return str(settings.get("staticIp") or "").strip()

    def _load_settings_ui(self):
        settings = risk_check.load_settings()
        self.window.set_endpoint(settings, self._active_whitelist_ip())
        self.window.settings_card.load_values(settings, self._cached_nodes)
        if not self.preview:
            self._start_load_nodes()

    def _start_load_nodes(self):
        if self.preview or self._nodes_task is not None:
            return
        self.window.settings_card.refresh_nodes_btn.setEnabled(False)
        self.window.settings_card.refresh_nodes_btn.setText("刷新中…")
        task = LoadNodesTask(self.proxy)
        self._nodes_task = task
        task.done.connect(self._on_nodes_loaded)
        task.finished.connect(self._clear_nodes_task)
        task.finished.connect(task.deleteLater)
        task.start()

    def _clear_nodes_task(self):
        self._nodes_task = None
        self.window.settings_card.refresh_nodes_btn.setText("刷新节点")
        self.window.settings_card.refresh_nodes_btn.setEnabled(not self.busy)

    def _on_nodes_loaded(self, nodes):
        self._cached_nodes = list(nodes or [])
        self.window.settings_card.set_nodes(self._cached_nodes)

    def start_startup_registration(self):
        if self.preview or self._startup_task is not None:
            return
        task = StartupRegisterTask()
        self._startup_task = task
        task.failed.connect(self.show_startup_error)
        task.finished.connect(self._clear_startup_task)
        task.finished.connect(task.deleteLater)
        task.start()

    def _clear_startup_task(self):
        self._startup_task = None

    def _detect_current_exit_ip(self):
        if self._detect_ip_task is not None:
            return
        self.window.settings_card.detect_ip_btn.setEnabled(False)
        self.window.settings_card.detect_ip_btn.setText("探测中…")
        task = DetectExitIpTask()
        self._detect_ip_task = task
        task.done.connect(self._on_detect_exit_ip_done)
        task.finished.connect(self._clear_detect_ip_task)
        task.finished.connect(task.deleteLater)
        task.start()

    def _clear_detect_ip_task(self):
        self._detect_ip_task = None

    def _on_detect_exit_ip_done(self, ip, error):
        self.window.settings_card.detect_ip_btn.setText("填入当前 IP")
        mode = self.window.settings_card.mode_combo.currentData()
        self.window.settings_card.detect_ip_btn.setEnabled(mode == "manual")
        if ip and mode == "manual":
            self.window.settings_card._manual_ip = ip
            self.window.settings_card.ip_input.setText(ip)
        elif error:
            self._set_explicit_status("未能获取出口 IP", error, True)

    def _save_settings(self, updates):
        mode = str(updates.get("staticIpMode") or "auto")
        target_node = str(updates.get("targetNode") or "").strip()
        if not target_node:
            self._set_explicit_status(
                "请选择目标节点", "请先刷新并在下拉列表中选择 Clash 目标节点。", True)
            return
        ip_value = str(updates.get("staticIp") or "").strip()
        if mode == "manual":
            if not risk_check.public_ipv4(ip_value):
                self._set_explicit_status(
                    "静态 IP 格式无效", "手动指定模式需要有效的公网 IPv4 地址。", True)
                return
            detail_msg = "目标节点：{} · 手动指定 IP：{}".format(target_node, ip_value)
        else:
            detail_msg = "目标节点：{} · 安全启动时实测并绑定出口 IP".format(target_node)
        saved_payload = {
            "targetNode": target_node,
            "staticIpMode": mode,
            "staticIp": ip_value,
        }
        risk_check.save_settings(saved_payload)
        self.window.settings_card.mark_saved(saved_payload)
        if not self.window.claude_card._running:
            self.monitor.set_baseline_ip("")
        self.window.set_endpoint(saved_payload, self._active_whitelist_ip())
        self.window.settings_card.setVisible(False)
        self._set_explicit_status("节点与 IP 设置已保存", detail_msg, False)
        self.window._schedule_fit_height()
        self._refresh_claude_status()

    def _on_toggle_processes(self, _expanded):
        self._refresh_claude_status()
        self.window._schedule_fit_height()

    def _refresh_process_details(self):
        if self.preview:
            self.window.claude_card.set_runtime_details({
                "processes": [],
                "service_running": False,
                "firewall_blocked": False,
            })
            return
        if self._process_details_task is not None:
            return
        task = ProcessDetailsTask()
        self._process_details_task = task
        task.done.connect(self._on_process_details_ready)
        task.finished.connect(self._clear_process_details_task)
        task.finished.connect(task.deleteLater)
        task.start()

    def _clear_process_details_task(self):
        self._process_details_task = None

    def _on_process_details_ready(self, snapshot):
        self._firewall_blocked = snapshot["firewall_blocked"]
        self.window.set_firewall_badge(
            self._firewall_blocked, wfp_isolated=self._wfp_isolated)
        self.window.claude_card.set_runtime_details(
            snapshot, self._active_whitelist_ip(), wfp_isolated=self._wfp_isolated)
        self.window._schedule_fit_height()

    def _on_tick(self):
        self._update_clocks()
        if self.preview:
            return
        self._tick_counter += 1
        if self._tick_counter % 2 == 0:
            self._refresh_claude_status()

    def _refresh_claude_status(self):
        if self.preview:
            self.window.claude_card.update_claude_state(
                False, 0, False, False, "未启动 · 点击展开进程与防火墙核验")
            self.window.usa_card.set_drift(False)
            self._sync_ambient_status(False)
            return
        try:
            procs = claude_desktop.list_claude_processes(include_children=True)
            running = bool(procs)
            count = len(procs)
            wfp_isolated = False
            if running and not self.cutoff_triggered:
                import protected_session
                try:
                    protected_session.active_port()
                    wfp_isolated = True
                except RuntimeError:
                    self._trigger_emergency_cutoff("未发现有效的独立保护会话")
                    return
                if self._explicit_status_kind in ("launch_sent", "risk_done"):
                    self._has_explicit_status = False
                    self._explicit_status_kind = None
                summary = "独立守护中 · 异常时关闭网关并终止 Claude"
            elif self.cutoff_triggered:
                summary = "已触发紧急保护，请查看已识别进程与出站规则状态"
            elif self._firewall_blocked:
                summary = "检测到出站阻止规则，点击查看进程确认零残留"
            else:
                summary = "未确认出站阻止规则，支持启动前检查与定期监测"
            if (self._was_claude_running and not running
                    and not self.cutoff_triggered and not self.busy):
                import protected_session
                try:
                    protected_session.stop()
                except Exception:
                    pass
                self.monitor.set_baseline_ip("")
                self.window.set_endpoint(
                    risk_check.load_settings(), self._active_whitelist_ip())
                if self._explicit_status_kind in (None, "launch_sent", "risk_done"):
                    self._has_explicit_status = False
                    self._explicit_status_kind = None
            self._was_claude_running = running
            self._wfp_isolated = wfp_isolated
            self.window.claude_card.update_claude_state(
                running, count, self._firewall_blocked,
                self.cutoff_triggered, summary)
            self.window.usa_card.set_drift(
                self.cutoff_triggered,
                getattr(self, "_drift_label", "→ rule") if self.cutoff_triggered else None)
            self.window.set_firewall_badge(
                self._firewall_blocked, wfp_isolated=self._wfp_isolated)
            self._sync_ambient_status(running, count)
            if not self.busy and not self.switch_failed:
                self.tray_status = APP_TITLE + " · " + (
                    "已触发紧急保护" if self.cutoff_triggered else
                    "Claude 已运行" if running else "Claude 已关闭")
                self.state_changed.emit()
            if self.window.claude_card._processes_expanded:
                self._refresh_process_details()
        except Exception:
            pass

    def _start_ip_guard(self):
        task = IpMonitorTask(self.monitor)
        self._ip_task = task
        task.result_ready.connect(self._on_ip_guard_result)
        task.finished.connect(self._clear_ip_task)
        task.finished.connect(task.deleteLater)
        task.start()

    def _clear_ip_task(self):
        self._ip_task = None

    def _on_ip_guard_result(self, ok, reason):
        if not ok:
            self._trigger_emergency_cutoff(reason)

    def _on_background_cutoff(self, generation, reason, error):
        """Render a cutoff already executed by the background supervisor."""
        if generation is not self._launch_generation:
            return
        with self._cutoff_lock:
            self.cutoff_triggered = True
        if self._launch_task is not None:
            try:
                self._launch_task.requestInterruption()
            except RuntimeError:
                self._launch_task = None
        self.risk_status = None
        self._wfp_isolated = False
        self._was_claude_running = False
        self._firewall_blocked = claude_desktop.is_traffic_blocked()
        self.monitor.set_baseline_ip("")
        self.window.set_endpoint(
            risk_check.load_settings(), self._active_whitelist_ip())
        self.window.set_firewall_badge(self._firewall_blocked)
        procs = claude_desktop.list_claude_processes(include_children=True)
        self.window.claude_card.update_claude_state(
            bool(procs), len(procs), self._firewall_blocked, True,
            f"已触发紧急保护：{reason}")
        self._drift_label = _format_drift_label(reason)
        self.window.usa_card.set_drift(True, self._drift_label)
        self._set_explicit_status(
            "紧急保护执行失败" if error else "已触发紧急保护",
            str(error) if error else reason, True, kind="cutoff")
        self.tray_status = APP_TITLE + " · 已触发紧急保护"
        if self.window.claude_card._processes_expanded:
            self._refresh_process_details()
        self.emergency_cutoff.emit(reason)
        self.state_changed.emit()

    def _trigger_emergency_cutoff(self, reason):
        with self._cutoff_lock:
            if self.cutoff_triggered:
                return
            self.cutoff_triggered = True
        task = getattr(self, "_launch_task", None)
        if task is not None:
            try:
                task.requestInterruption()
            except RuntimeError:
                self._launch_task = None
        self.risk_status = None
        self._wfp_isolated = False
        self._was_claude_running = False
        try:
            claude_desktop.cut_off_claude_traffic(reason)
        except Exception as error:
            self._firewall_blocked = False
            self.window.set_firewall_badge(False)
            self._has_explicit_status = True
            self._explicit_status_kind = "cutoff"
            self.window.set_status(
                "紧急保护执行失败，无法确认流量已封锁", str(error), True)
            raise
        self._firewall_blocked = claude_desktop.is_traffic_blocked()
        self.risk_status = None
        self.window.set_firewall_badge(self._firewall_blocked)
        procs = claude_desktop.list_claude_processes(include_children=True)
        self.window.claude_card.update_claude_state(
            bool(procs), len(procs), self._firewall_blocked, True,
            f"已触发紧急保护：{reason}")
        drift_label = _format_drift_label(reason)
        self._drift_label = drift_label
        self.window.usa_card.set_drift(True, drift_label)
        self._has_explicit_status = True
        self._explicit_status_kind = "cutoff"
        self.window.set_status(
            "已触发紧急保护",
            f"监测到环境变化（{reason}），已尝试终止进程并添加阻止规则，请查看实际状态。",
            True)
        self.tray_status = APP_TITLE + " · 已触发紧急保护"
        self.read_state()
        self.emergency_cutoff.emit(reason)

    def read_state(self):
        try:
            state = self.service.read()
            current = (
                "usa" if state.timezone_id.lower() == USA_TZ.lower()
                else "china" if state.timezone_id.lower() == CHINA_TZ.lower()
                else None)
            self.current_mode = current
            if not self.busy and not self.switch_failed:
                self.tray_status = (APP_TITLE + " · 已触发紧急保护"
                                    if self.cutoff_triggered else self.risk_status
                                    or APP_TITLE + " · "
                                    + (RegionProfile.for_mode(current).name + "时区"
                                       if current else "其他时区"))
            self.window.apply_active(current)
            self.target_mode = "china" if current == "usa" else "usa"
            self.window.set_apply_label(self.target_mode)
            self.window.set_apply_enabled(not self.busy and not self.preview)
            self._sync_ambient_status(self.window.claude_card._running)
        except Exception as error:
            self._set_explicit_status("无法读取当前配置", str(error), True)
            self.window.apply_active(None)
            self.window.set_apply_enabled(False)
            self.tray_status = APP_TITLE + " · 读取失败"
        self.state_changed.emit()

    def switch_mode(self, target, force=False):
        if not force and not self.cutoff_triggered and target == self.current_mode:
            return
        self._apply(target)

    def safe_launch_claude(self):
        if self.busy or self.preview:
            return
        try:
            claude_desktop.begin_safe_launch()
        except RuntimeError as error:
            self._has_explicit_status = True
            self.window.set_status("安全启动已拦截", str(error), True)
            return
        self.busy = True
        self.switch_failed = False
        self.cutoff_triggered = False
        self.window.usa_card.set_drift(False)
        self._launch_generation = object()
        self.risk_status = None
        self.tray_status = APP_TITLE + " · 正在安全启动"
        self.state_changed.emit()
        self.window.set_apply_enabled(False)
        self.window.risk_card.set_preparing()
        self.window.set_pending_mode("usa")
        self._has_explicit_status = True
        self.window.set_status(
            "正在安全启动 Claude Desktop",
            "正在准备环境，完成后执行启动前安全检测…", False)
        task = SafeLaunchTask(self.workflow, self.service, self.proxy)
        generation = self._launch_generation
        task.protection_callback = lambda reason, error: (
            self.background_failure.emit(generation, reason, error))
        self._launch_task = task
        task.progress.connect(self._on_progress)
        task.checking_started.connect(self.window.risk_card.set_checking)
        task.risk_ready.connect(self._on_safe_launch_risk_ready)
        task.done.connect(self._on_safe_launch_done)
        task.failed.connect(self._on_safe_launch_failed)
        task.finished.connect(lambda: self._clear_launch_task(task))
        task.finished.connect(task.deleteLater)
        task.start()

    def _clear_launch_task(self, task):
        if self._launch_task is task:
            self._launch_task = None

    def _on_safe_launch_risk_ready(self, report):
        if isinstance(report, dict) and isinstance(report.get("items"), list):
            self.window.set_risk_items(report["items"])

    def _record_baseline_from_report(self, report):
        if not isinstance(report, dict):
            return
        for entry in report.get("items") or []:
            if entry.get("name") == risk_check.ITEM_NAMES[1]:
                if entry.get("status") == "pass":
                    detail = str(entry.get("detail") or "")
                    ip = risk_check._first_ipv4(detail)
                    if ip:
                        self.monitor.set_baseline_ip(ip)
                        self.window.set_endpoint(risk_check.load_settings(), ip)
                elif not self.window.claude_card._running:
                    self.monitor.set_baseline_ip("")
                    self.window.set_endpoint(
                        risk_check.load_settings(), self._active_whitelist_ip())
                break

    def _on_safe_launch_done(self, report):
        if self.cutoff_triggered:
            self._on_safe_launch_failed(
                RuntimeError("启动期间触发紧急保护，请重新检查环境。"), report)
            return
        self.window.set_pending_mode(None)
        self._firewall_blocked = claude_desktop.is_traffic_blocked()
        if isinstance(report, dict) and isinstance(report.get("items"), list):
            self.window.set_risk_items(report["items"])
        self._record_baseline_from_report(report)
        self.risk_status = None
        self._set_explicit_status(
            "启动前必要检查通过，已发送 Claude 启动请求",
            "请查看进程状态；定期监测 IP、Clash 节点/TUN、系统时区与 Edge 网页语言配置。",
            False, tone="running", kind="launch_sent")
        self.busy = False
        self.read_state()
        self._refresh_claude_status()

    def _on_safe_launch_failed(self, error, report):
        write_error(error)
        self.window.set_pending_mode(None)
        self._firewall_blocked = claude_desktop.is_traffic_blocked()
        self.switch_failed = True
        if report and isinstance(report.get("items"), list):
            self.window.set_risk_items(report["items"])
        else:
            self.window.risk_card.set_incomplete()
        self.tray_status = APP_TITLE + " · 启动已拦截"
        self._set_explicit_status("已拦截 Claude Desktop 启动", str(error), True)
        self.busy = False
        self.read_state()
        self._refresh_claude_status()

    def close_claude(self):
        if self.busy or self.preview:
            return
        self.busy = True
        self.switch_failed = False
        self.cutoff_triggered = False
        self.window.usa_card.set_drift(False)
        self.window.set_apply_enabled(False)
        self._set_explicit_status(
            "正在安全关闭 Claude Desktop",
            "正在终止 Claude 主程序、子进程与后台服务并锁定防火墙…", False)
        task = CloseClaudeTask()
        self._close_task = task
        task.progress.connect(self._on_progress)
        task.done.connect(self._on_close_claude_done)
        task.failed.connect(self._on_close_claude_failed)
        task.finished.connect(task.deleteLater)
        task.start()

    def _on_close_claude_done(self):
        self.cutoff_triggered = False
        self.window.usa_card.set_drift(False)
        self._firewall_blocked = claude_desktop.is_traffic_blocked()
        self.risk_status = None
        self.monitor.set_baseline_ip("")
        self.window.set_endpoint(
            risk_check.load_settings(), self._active_whitelist_ip())
        self._set_explicit_status(
            "Claude Desktop 关闭任务已完成",
            "未检测到已识别的 Claude 进程，请查看服务与出站规则状态。",
            False)
        self.busy = False
        self.read_state()
        self._refresh_claude_status()

    def _on_close_claude_failed(self, error):
        write_error(error)
        self.switch_failed = True
        self._set_explicit_status("安全关闭未完成", str(error), True)
        self.busy = False
        self.read_state()
        self._refresh_claude_status()

    def manual_recheck(self):
        if self.busy or self.preview:
            return
        self.busy = True
        self.window.set_apply_enabled(False)
        self.window.risk_card.set_checking()
        self._set_explicit_status(
            "正在执行安全检测",
            "正在检测出口 IP、DNS、UDP 出口（STUN）、系统时区与 Edge 网页语言配置…", False)
        self._start_risk()

    def show_startup_error(self, error):
        write_error(error)
        self.switch_failed = True
        self._set_explicit_status("开机启动设置未完成", str(error), True)
        self.tray_status = APP_TITLE + " · 开机启动失败"
        self.state_changed.emit()

    def _apply(self, target):
        if self.busy or self.preview:
            return
        self.busy = True
        self.switch_failed = False
        self.cutoff_triggered = False
        self.window.usa_card.set_drift(False)
        self.risk_status = None
        self.tray_status = APP_TITLE + " · 正在切换"
        self.state_changed.emit()
        self.window.set_apply_enabled(False)
        self.window.apply_active(None)
        self.window.set_pending_mode(target)
        if target == "usa":
            self.window.risk_card.set_preparing()
        self._set_explicit_status(
            "正在切换到" + RegionProfile.for_mode(target).name + "模式",
            "正在准备浏览器会话与代理配置…", False)
        self.target_mode = target
        close_claude_first = (target == "china")
        task = ApplyTask(self.workflow, target, close_claude_first)
        self._apply_task = task
        task.progress.connect(self._on_progress)
        task.done.connect(lambda restarted: self._on_apply_done(target, restarted))
        task.failed.connect(self._on_apply_failed)
        task.finished.connect(task.deleteLater)
        task.start()

    def _on_progress(self, message):
        if self.busy:
            self.window.status_detail.setText(message)

    def _on_apply_done(self, target, restarted):
        self.window.set_pending_mode(None)
        self.window.apply_active(target)
        profile = RegionProfile.for_mode(target)
        if target == "china":
            self._firewall_blocked = claude_desktop.is_traffic_blocked()
            self._wfp_isolated = False
            self._was_claude_running = False
            self.monitor.set_baseline_ip("")
            self.window.set_endpoint(
                risk_check.load_settings(), self._active_whitelist_ip())
            self.window.risk_card.set_expanded(False)
            self.window.clear_risk()
            detail = "系统时区与 Edge 网页语言配置已切换；请确认 Clash 代理状态。"
            self._set_explicit_status(
                "已切回" + profile.name + "模式", detail, False, tone="china")
            self.busy = False
            self.read_state()
            self._refresh_claude_status()
        else:
            self.window.risk_card.set_checking()
            self._set_explicit_status(
                "美国模式已切换，正在检测风险",
                "正在检测出口 IP、DNS、UDP 出口（STUN）、系统时区与 Edge 网页语言配置…", False)
            self._start_risk()

    def _on_apply_failed(self, error):
        write_error(error)
        self.window.set_pending_mode(None)
        self.switch_failed = True
        if self.target_mode == "usa":
            self.window.risk_card.set_incomplete()
        self.tray_status = APP_TITLE + " · 切换未完成"
        self._set_explicit_status("切换未完成", str(error), True)
        self.busy = False
        self.read_state()
        self._refresh_claude_status()

    def _start_risk(self):
        task = RiskTask()
        self._risk_task = task
        task.done.connect(self._on_risk_done)
        task.failed.connect(self._on_risk_failed)
        task.finished.connect(task.deleteLater)
        task.start()

    def _on_risk_done(self, report):
        self._record_baseline_from_report(report)
        self.risk_status = APP_TITLE + " · " + report["title"]
        self.window.set_risk_items(report["items"])
        items = report.get("items") or []
        has_actual_risk = any(entry.get("status") == "risk" for entry in items)
        has_unknown = any(entry.get("status") == "unknown" for entry in items)
        running = bool(self.window.claude_card._running)
        if has_actual_risk:
            self._set_explicit_status(
                report["title"],
                "发现异常风险项，请立即查看下方安全检测报告。",
                True, tone="neutral", kind="risk_done")
        elif has_unknown:
            detail = (
                "检测已完成，部分待确认项可查看下方安全检测报告；Claude 仍在受控运行。"
                if running else "检测已完成，部分待确认项可查看下方安全检测报告。"
            )
            self._set_explicit_status(
                report["title"],
                detail,
                False,
                tone="running" if running else "neutral",
                kind="risk_done")
        else:
            self._set_explicit_status(
                report["title"],
                "所有检测项已通过，Claude 仍在受控运行。"
                if running else "检测已完成，请查看安全检测结果。",
                False, tone="running", kind="risk_done")
        self.busy = False
        self.read_state()
        self.risk_completed.emit(report)

    def _on_risk_failed(self, error):
        write_error(error)
        items = [{"name": name, "status": "unknown",
                  "detail": "检测程序未能完成，结果待确认"}
                 for name in risk_check.ITEM_NAMES]
        report = risk_check.build_report(items)
        report["title"] = "风险检测未完成"
        self.risk_status = APP_TITLE + " · " + report["title"]
        self.window.risk_card.set_incomplete()
        self._set_explicit_status(report["title"], str(error), True)
        self.busy = False
        self.read_state()
        self.risk_completed.emit(report)

    def _update_clocks(self):
        now = datetime.now(timezone.utc)
        self._update_clock("china", CHINA_TZ, now)
        self._update_clock("usa", USA_TZ, now)

    def _update_clock(self, prefix, windows_zone, now):
        name = ("Asia/Shanghai" if windows_zone == CHINA_TZ
                else "America/Los_Angeles")
        try:
            local = now.astimezone(ZoneInfo(name))
            offset = local.utcoffset()
            minutes = int(offset.total_seconds() // 60) if offset else 0
            sign = "+" if minutes >= 0 else "−"
            value = abs(minutes)
            text = "UTC{}{:02d}:{:02d}".format(sign, value // 60, value % 60)
            daylight = bool(local.dst() and local.dst().total_seconds())
            self.window.set_clock(
                prefix, local.strftime("%H:%M:%S"), text, daylight)
        except Exception:
            self.window.set_clock(prefix, "—", "—", False)

    @property
    def is_busy(self):
        return self.busy

    @property
    def tray_status_text(self):
        return self.tray_status


class TrayHost(QObject):
    def __init__(self, window, controller):
        super().__init__()
        self.window = window
        self.controller = controller
        self.tray = QSystemTrayIcon(QIcon(str(ICON_PATH)))
        self.tray.setToolTip(APP_TITLE)
        menu = QMenu()
        self.open_action = QAction("打开主窗口", menu)
        self.launch_action = QAction("安全启动 Claude", menu)
        self.kill_action = QAction("安全关闭 Claude", menu)
        self.china_action = QAction("切回中国模式", menu)
        self.usa_action = QAction("切至美国模式", menu)
        self.quit_action = QAction("退出", menu)

        self.open_action.triggered.connect(self.show_window)
        self.launch_action.triggered.connect(controller.safe_launch_claude)
        self.kill_action.triggered.connect(controller.close_claude)
        self.china_action.triggered.connect(
            lambda: controller.switch_mode("china"))
        self.usa_action.triggered.connect(
            lambda: controller.switch_mode("usa"))
        self.quit_action.triggered.connect(self.try_exit)

        menu.addAction(self.open_action)
        menu.addSeparator()
        menu.addAction(self.launch_action)
        menu.addAction(self.kill_action)
        menu.addSeparator()
        menu.addAction(self.china_action)
        menu.addAction(self.usa_action)
        menu.addSeparator()
        menu.addAction(self.quit_action)
        self.menu = menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._activated)
        self.tray.messageClicked.connect(self.show_window)
        self.tray.show()
        controller.state_changed.connect(self.update_state)
        controller.risk_completed.connect(self.on_risk_completed)
        controller.emergency_cutoff.connect(self.on_emergency_cutoff)
        self.update_state()

    def _activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_window()

    def show_window(self):
        self.window.show()
        self.window.setWindowState(
            self.window.windowState() & ~Qt.WindowMinimized)
        self.window.raise_()
        self.window.activateWindow()

    def try_exit(self):
        if self.controller.is_busy:
            return False
        self.window.exit_allowed = True
        self.tray.hide()
        QApplication.quit()
        return True

    def on_risk_completed(self, report):
        self.show_window()
        icon = (QSystemTrayIcon.Warning if report["hasRisk"]
                else QSystemTrayIcon.Information)
        self.tray.showMessage(
            report["title"], "点击查看安全检测报告。", icon, 8000)

    def on_emergency_cutoff(self, reason):
        self.show_window()
        self.tray.showMessage(
            "已触发紧急保护",
            f"检测到环境异常（{reason}），已尝试终止进程并添加阻止规则，请查看实际状态。",
            QSystemTrayIcon.Critical, 15000)

    def update_state(self):
        enabled = not self.controller.is_busy
        running = bool(self.window.claude_card._running)
        self.launch_action.setText("Claude 已运行" if running else "安全启动 Claude")
        self.launch_action.setEnabled(enabled and not running)
        self.kill_action.setEnabled(enabled)
        self.china_action.setEnabled(enabled)
        self.usa_action.setEnabled(enabled)
        self.quit_action.setEnabled(enabled)
        text = self.controller.tray_status_text
        self.tray.setToolTip(text[:63])


class InstanceMessageFilter(QAbstractNativeEventFilter):
    def __init__(self, message, show_callback, exit_callback, is_busy):
        super().__init__()
        self.message = message
        self.show_callback = show_callback
        self.exit_callback = exit_callback
        self.is_busy = is_busy

    def nativeEventFilter(self, event_type, message):
        try:
            msg = wintypes.MSG.from_address(int(message))
        except Exception:
            return False, 0
        if msg.message != self.message:
            return False, 0
        if msg.wParam == 1:
            QTimer.singleShot(0, self.show_callback)
            return True, 1
        if msg.wParam == 2:
            if self.is_busy():
                return True, 0
            QTimer.singleShot(0, self.exit_callback)
            return True, 1
        return False, 0


class InstanceWindow(QWidget):
    def __init__(self, name):
        super().__init__()
        self.setWindowTitle(name)
        self.setAttribute(Qt.WA_DontShowOnScreen, True)
        self.resize(0, 0)
        self.winId()


def _set_dpi_awareness():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _parse_arguments(arguments):
    if arguments[:1] == ["--capture"]:
        if len(arguments) < 2:
            raise ValueError("无法识别的启动参数。")
        scale = 1.0
        if len(arguments) > 2:
            try:
                scale = float(arguments[2])
            except ValueError as error:
                raise ValueError("无效的截图缩放比例。") from error
            if not 0.5 <= scale <= 3:
                raise ValueError("无效的截图缩放比例。")
        if len(arguments) > 3:
            raise ValueError("无法识别的启动参数。")
        return True, scale, False, False, False, None
    startup = False
    preview = False
    exit_flag = False
    expected_sid = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--tray-startup" and not startup:
            startup = True
        elif argument == "--preview" and not preview:
            preview = True
        elif (argument == "--expected-sid" and expected_sid is None
              and index + 1 < len(arguments)):
            index += 1
            expected_sid = arguments[index]
        elif argument == "--exit" and len(arguments) == 1:
            exit_flag = True
        else:
            raise ValueError("无法识别的启动参数。")
        index += 1
    return False, 1.0, startup, preview, exit_flag, expected_sid


def _instance_name():
    return (INSTANCE_PREFIX + win32util.current_sid() + "."
            + str(win32util.current_session_id()))


def _create_application():
    """Set the process identity before Qt creates any native windows."""
    if sys.platform == "win32":
        os.environ.setdefault("QT_QPA_PLATFORM", "windows:fontengine=freetype")
        set_app_id = (
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID)
        set_app_id.argtypes = [wintypes.LPCWSTR]
        set_app_id.restype = ctypes.c_long
        result = set_app_id(APP_USER_MODEL_ID)
        if result != 0:
            raise OSError(result, "Unable to set the application identity.")
    app = QApplication(sys.argv)
    _ensure_app_fonts()
    app.setWindowIcon(QIcon(str(ICON_PATH)))
    app.setQuitOnLastWindowClosed(False)
    app.setStyle(GuardStyle())
    app.setFont(QFont("Inter"))
    app.setStyleSheet(QSS)
    return app


def _run_capture(path, scale, preview):
    app = _create_application()
    window = MainWindow()
    controller = Controller(window, preview=True)
    controller._update_clocks()
    window.set_apply_enabled(True)
    window.show()
    app.processEvents()
    controller._update_clocks()
    app.processEvents()
    image = window.centralWidget().grab()
    if scale != 1.0:
        image = image.scaled(
            int(image.width() * scale), int(image.height() * scale),
            Qt.KeepAspectRatio, Qt.SmoothTransformation)
    if not image.save(str(path), "PNG"):
        raise RuntimeError("无法写入截图文件。")
    window.exit_allowed = True
    window.close()
    return 0


def main(arguments=None):
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    capture = False
    preview = False
    startup = False
    exit_flag = False
    expected_sid = None
    try:
        capture, scale, startup, preview, exit_flag, expected_sid = (
            _parse_arguments(arguments))
    except ValueError as error:
        win32util.message_box(str(error), APP_TITLE, True)
        return 1
    try:
        if capture:
            _set_dpi_awareness()
            return _run_capture(arguments[1], scale, preview)
        sid = win32util.current_sid()
        session = win32util.current_session_id()
        instance_name = INSTANCE_PREFIX + sid + "." + str(session)
        command_message = win32util.register_window_message(
            instance_name + ".Command")
        if exit_flag:
            return 0 if win32util.notify_existing_instance(
                instance_name, command_message, True) else 2
        if not win32util.is_admin():
            if startup:
                raise RuntimeError(
                    "开机任务未以所需权限运行，请从桌面打开工具修复开机启动设置。")
            if expected_sid is not None:
                raise RuntimeError("未能获得管理员权限，已停止启动。")
            if win32util.notify_existing_instance(
                    instance_name, command_message, False):
                return 0
            if not win32util.run_elevated(["--expected-sid", sid]):
                win32util.message_box(
                    "已取消管理员授权，未修改任何设置。", APP_TITLE, False)
            return 0
        if expected_sid is not None and sid != expected_sid:
            raise RuntimeError(
                "提升权限时使用了其他账户，已停止。请使用原账户授权，避免修改错误账户的 Edge 语言。")
        _set_dpi_awareness()
        app = _create_application()
        mutex_handle = win32util.create_mutex("Local\\" + instance_name)
        if not win32util.acquire_mutex(mutex_handle, 0):
            notified = win32util.notify_existing_instance(
                instance_name, command_message, False)
            win32util.close_handle(mutex_handle)
            if not notified and not startup:
                win32util.message_box(
                    "检测到工具已在后台运行，但未能自动唤醒其窗口。\n"
                    "请查看右下角系统托盘图标，或在任务管理器中结束旧进程后重试。",
                    APP_TITLE, True)
            return 0
        window = MainWindow()
        controller = Controller(window, preview=preview)
        tray = None if preview else TrayHost(window, controller)
        message_window = InstanceWindow(instance_name)
        win32util.allow_window_message(
            int(message_window.winId()), command_message)
        message_filter = InstanceMessageFilter(
            command_message,
            (tray.show_window if tray else window.show),
            (tray.try_exit if tray else app.quit),
            lambda: controller.is_busy)
        app.installNativeEventFilter(message_filter)
        if preview:
            window.set_apply_enabled(False)
            window.show()
        elif startup:
            QTimer.singleShot(0, lambda: controller.switch_mode("china", force=True))
            controller.start_startup_registration()
        else:
            if tray:
                tray.show_window()
            controller.start_startup_registration()
        result = app.exec()
        if tray:
            tray.tray.hide()
        win32util.release_mutex(mutex_handle)
        win32util.close_handle(mutex_handle)
        return result
    except Exception as error:
        path = write_error(error)
        if capture:
            print(str(error), file=sys.stderr)
        elif not startup:
            win32util.message_box(
                str(error) + "\n\n错误记录：" + path,
                APP_TITLE + " 未能启动", True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
