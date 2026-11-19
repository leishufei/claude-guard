"""Claude exit risk checks based on the ip.net.coffee public endpoints.

The checks mirror the public https://ip.net.coffee/claude/ page: IP and
reputation data come from its JSON endpoints. DNS, Python UDP STUN and device
facts are observed locally; STUN does not check browser WebRTC state.
"""

import binascii
import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import math
import os
import queue
import re
import secrets
import socket
import ssl
import string
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

SITE_URL = "https://ip.net.coffee"
CLAUDE_TRACE_URL = "https://claude.ai/cdn-cgi/trace"
CLOUDFLARE_TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
CHINA_URLS = ("https://2026.ip138.com/", "https://my.ip.cn/")
DNS_SUFFIX = ".d.ip.net.coffee"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT = 10.0
TOTAL_TIMEOUT = 50.0
DNS_RESULT_ATTEMPTS = 4
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
)
DEFAULT_STATIC_IP = ""
DEFAULT_TARGET_NODE = ""
SETTINGS_PATH = os.path.join(
    os.environ.get("LOCALAPPDATA", ""), "ClaudeGuard",
    "settings.json")
RESTRICTED_COUNTRIES = {
    "CN", "HK", "MO", "RU", "KP", "IR", "SY", "CU", "BY", "VE"
}
ITEM_NAMES = (
    "中国出口 IPv4", "Claude AI 出口 IP", "Claude AI 信任评分", "Claude 支持地区",
    "Claude AI 出口 IP 属性", "Claude AI 出口 IP 安全检测", "DNS 泄露检测",
    "UDP 出口检测（STUN）", "Claude AI 出口 IP 用户设备信息",
)
LANG_MAP = {
    "CN": ["zh"], "TW": ["zh"], "HK": ["zh", "en"], "MO": ["zh", "en"],
    "JP": ["ja"], "KR": ["ko"], "TH": ["th"], "VN": ["vi"],
    "SG": ["en", "zh", "ms", "ta"], "MY": ["ms", "en", "zh", "ta"],
    "ID": ["id", "en"], "PH": ["en", "tl", "fil"], "IN": ["en", "hi"],
    "PK": ["ur", "en"], "BD": ["bn", "en"], "LK": ["si", "ta", "en"],
    "NP": ["ne", "en"], "US": ["en"], "GB": ["en"], "IE": ["en", "ga"],
    "AU": ["en"], "NZ": ["en", "mi"], "CA": ["en", "fr"],
    "DE": ["de"], "AT": ["de"], "CH": ["de", "fr", "it", "rm"],
    "BE": ["nl", "fr", "de"], "FR": ["fr"], "IT": ["it"],
    "ES": ["es", "ca", "gl", "eu"], "PT": ["pt"], "NL": ["nl", "fy"],
    "LU": ["lb", "fr", "de"], "SE": ["sv"], "NO": ["no", "nb", "nn"],
    "DK": ["da"], "FI": ["fi", "sv"], "IS": ["is", "en"],
    "PL": ["pl"], "CZ": ["cs"], "SK": ["sk"], "HU": ["hu"],
    "RO": ["ro"], "BG": ["bg"], "GR": ["el"], "RU": ["ru"],
    "UA": ["uk", "ru"], "BY": ["be", "ru"], "TR": ["tr"],
    "IL": ["he", "ar", "en"], "SA": ["ar"], "AE": ["ar", "en"],
    "EG": ["ar"], "IR": ["fa"], "IQ": ["ar", "ku"], "ZA": ["en", "af"],
    "KE": ["en", "sw"], "NG": ["en"], "ET": ["am", "en"],
    "BR": ["pt"], "AR": ["es"], "MX": ["es"], "CL": ["es"],
    "CO": ["es"], "PE": ["es"], "VE": ["es"],
}
CC_TO_TZ = {
    "CN": "Asia/Shanghai", "TW": "Asia/Taipei", "HK": "Asia/Hong_Kong",
    "MO": "Asia/Macau", "JP": "Asia/Tokyo", "KR": "Asia/Seoul",
    "SG": "Asia/Singapore", "MY": "Asia/Kuala_Lumpur",
    "TH": "Asia/Bangkok", "VN": "Asia/Ho_Chi_Minh", "ID": "Asia/Jakarta",
    "PH": "Asia/Manila", "IN": "Asia/Kolkata", "PK": "Asia/Karachi",
    "BD": "Asia/Dhaka", "IR": "Asia/Tehran", "IL": "Asia/Jerusalem",
    "AE": "Asia/Dubai", "SA": "Asia/Riyadh", "TR": "Europe/Istanbul",
    "RU": "Europe/Moscow", "UA": "Europe/Kyiv", "GB": "Europe/London",
    "IE": "Europe/Dublin", "FR": "Europe/Paris", "DE": "Europe/Berlin",
    "IT": "Europe/Rome", "ES": "Europe/Madrid", "PT": "Europe/Lisbon",
    "NL": "Europe/Amsterdam", "BE": "Europe/Brussels",
    "CH": "Europe/Zurich", "AT": "Europe/Vienna",
    "SE": "Europe/Stockholm", "NO": "Europe/Oslo",
    "DK": "Europe/Copenhagen", "FI": "Europe/Helsinki",
    "PL": "Europe/Warsaw", "CZ": "Europe/Prague",
    "GR": "Europe/Athens", "RO": "Europe/Bucharest",
    "US": "America/Los_Angeles", "CA": "America/Toronto",
    "MX": "America/Mexico_City", "BR": "America/Sao_Paulo",
    "AR": "America/Argentina/Buenos_Aires", "CL": "America/Santiago",
    "AU": "Australia/Sydney", "NZ": "Pacific/Auckland",
    "ZA": "Africa/Johannesburg", "EG": "Africa/Cairo",
    "NG": "Africa/Lagos", "KE": "Africa/Nairobi",
}


_SSL_CONTEXT_LOCK = threading.Lock()
_SSL_CONTEXT = None


def _get_ssl_context():
    global _SSL_CONTEXT
    if _SSL_CONTEXT is None:
        with _SSL_CONTEXT_LOCK:
            if _SSL_CONTEXT is None:
                _SSL_CONTEXT = ssl.create_default_context()
    return _SSL_CONTEXT


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers,
                         new_url):
        raise ValueError("Redirects are unsupported")


class ProxyConnectionPool:
    """Thread-safe keep-alive connection pool routed via a local HTTP proxy."""

    def __init__(self):
        self._lock = threading.Lock()
        self._locks = {}
        self._conns = {}

    def lock_for(self, key):
        with self._lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock

    def pop(self, key):
        with self._lock:
            return self._conns.pop(key, None)

    def put(self, key, conn):
        with self._lock:
            old = self._conns.pop(key, None)
            self._conns[key] = conn
        if old is not None and old is not conn:
            try:
                old.close()
            except Exception:
                pass

    def close_all(self):
        with self._lock:
            conns = list(self._conns.values())
            self._conns.clear()
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass


class HttpClient:
    """Bound request duration, total duration, and response size."""

    def __init__(self, total_timeout=TOTAL_TIMEOUT, proxy_port=None,
                 deadline=None, session_pool=None):
        self.deadline = time.monotonic() + total_timeout
        if deadline is not None:
            self.deadline = min(self.deadline, deadline)
        if proxy_port is not None and (type(proxy_port) is not int
                                       or not 1 <= proxy_port <= 65535):
            raise ValueError("Invalid local proxy port")
        self.proxy_port = proxy_port
        self.session_pool = session_pool

    def get(self, url):
        for attempt in range(2):
            try:
                return self._get_once(url)
            except Exception as error:
                if isinstance(error, urllib.error.HTTPError):
                    retryable = error.code in (408, 429, 502, 503, 504)
                else:
                    reason = (error.reason if isinstance(
                        error, urllib.error.URLError) else error)
                    retryable = isinstance(reason, (
                        TimeoutError, ConnectionError, socket.gaierror,
                        http.client.IncompleteRead, http.client.RemoteDisconnected))
                if attempt or not retryable:
                    raise
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.25, remaining))

    def _get_once(self, url):
        timeout = min(REQUEST_TIMEOUT, self.deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("Detection deadline exceeded")
        result = queue.Queue(maxsize=1)

        def request():
            try:
                result.put((True, self._download(url, timeout)))
            except Exception as error:
                result.put((False, error))

        worker = threading.Thread(target=request, daemon=True)
        worker.start()
        try:
            succeeded, data = result.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("Request deadline exceeded") from None
        if not succeeded:
            raise data
        return data

    def _download(self, url, timeout):
        if self.proxy_port is not None:
            return self._download_proxy(url, timeout)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirectHandler())
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/142.0.0.0 Safari/537.36 "
                               "Edg/142.0.0.0"),
                "Accept": "*/*",
            })
        with opener.open(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("Detection response exceeded size limit")
        return data

    def _download_proxy(self, url, timeout):
        """Send target hostnames to the proxy without local target DNS lookup."""
        target = urllib.parse.urlsplit(url)
        if target.scheme not in ("http", "https") or not target.hostname:
            raise ValueError("Unsupported proxy target")
        port = target.port or (443 if target.scheme == "https" else 80)
        if self.session_pool is None:
            return self._download_proxy_once(target, url, timeout, None)
        key = (self.proxy_port, target.scheme, target.hostname, port)
        with self.session_pool.lock_for(key):
            cached = self.session_pool.pop(key)
            if cached is not None:
                try:
                    return self._download_proxy_once(
                        target, url, timeout, cached, pool_key=key)
                except (http.client.HTTPException, OSError):
                    pass
            return self._download_proxy_once(
                target, url, timeout, None, pool_key=key)

    def _download_proxy_once(self, target, url, timeout, connection=None,
                             pool_key=None):
        keep_alive = pool_key is not None
        headers = {
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
            "Connection": "keep-alive" if keep_alive else "close",
        }
        reused = connection is not None
        if reused:
            if getattr(connection, "sock", None) is None:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = None
                reused = False
            else:
                connection.timeout = timeout
                connection.sock.settimeout(timeout)
        if connection is None:
            if target.scheme == "https":
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", self.proxy_port, timeout=timeout,
                    context=_get_ssl_context())
                connection.set_tunnel(target.hostname, target.port or 443)
            else:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", self.proxy_port, timeout=timeout)
        if target.scheme == "https":
            path = urllib.parse.urlunsplit(("", "", target.path or "/",
                                           target.query, ""))
        else:
            path = url
        responses = []

        def response_factory(*args, **kwargs):
            response = http.client.HTTPResponse(*args, **kwargs)
            responses.append(response)
            return response

        # Python 3.10 leaves the CONNECT response open on tunnel failures.
        connection.response_class = response_factory
        returned_to_pool = False
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise urllib.error.HTTPError(
                    url, response.status, response.reason,
                    response.headers, None)
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ValueError("Detection response exceeded size limit")
            conn_hdr = str(response.getheader("Connection") or "").lower()
            if (keep_alive and conn_hdr != "close"
                    and getattr(connection, "sock", None) is not None):
                self.session_pool.put(pool_key, connection)
                returned_to_pool = True
            return data
        finally:
            if not returned_to_pool:
                for response in responses:
                    response.close()
                connection.close()


def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return ""
    if (address.version != 4 or not address.is_global
            or address.is_multicast):
        return ""
    return str(address)


def fetch_text(client, url):
    try:
        data = client.get(url)
        if not isinstance(data, bytes) or len(data) > MAX_RESPONSE_BYTES:
            return ""
        return data.decode("utf-8", errors="strict")
    except Exception:
        return ""


def fetch_json(client, url):
    try:
        value = json.loads(fetch_text(client, url))
        return value if isinstance(value, dict) else {}
    except (ValueError, RecursionError):
        return {}


def _first_ipv4(text):
    match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)
    return public_ipv4(match.group(0)) if match else ""


def fetch_china_ip(client):
    for url in CHINA_URLS:
        address = _first_ipv4(fetch_text(client, url))
        if address:
            return address
    return ""


def fetch_trace_ip(client, url):
    text = fetch_text(client, url)
    match = re.search(r"^ip=([^\r\n]+)", text, flags=re.MULTILINE)
    return public_ipv4(match.group(1).strip()) if match else ""


def _normalize_mode(value):
    mode = str(value or "").strip().lower()
    return mode if mode in ("auto", "manual") else "auto"


def load_settings(path=None):
    path = path or SETTINGS_PATH
    defaults = {
        "staticIp": DEFAULT_STATIC_IP,
        "targetNode": DEFAULT_TARGET_NODE,
        "staticIpMode": "auto",
    }
    try:
        with open(path, encoding="utf-8") as file:
            value = json.load(file)
        if isinstance(value, dict):
            for key, entry in defaults.items():
                value.setdefault(key, entry)
            value["targetNode"] = str(value.get("targetNode") or "").strip()
            value["staticIpMode"] = _normalize_mode(value.get("staticIpMode"))
            return value
    except (OSError, ValueError):
        pass
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as file:
            json.dump(defaults, file, ensure_ascii=False, indent=2)
            file.write("\n")
    except OSError:
        pass
    return defaults


def save_settings(updates, path=None):
    path = path or SETTINGS_PATH
    current = load_settings(path)
    if isinstance(updates, dict):
        current.update(updates)
    current["staticIpMode"] = _normalize_mode(current.get("staticIpMode"))
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(current, file, ensure_ascii=False, indent=2)
        file.write("\n")
    return current


def resolve_node_ip(node_name):
    if not node_name:
        return ""
    try:
        import clash_proxy
        server = clash_proxy.read_proxy_server(node_name)
        ip = public_ipv4(server)
        if ip:
            return ip
        if server and not any(c.isspace() for c in server):
            resolved = socket.gethostbyname(server)
            return public_ipv4(resolved)
    except Exception:
        pass
    return ""


def static_targets(settings):
    if not isinstance(settings, dict):
        return "", ""
    mode = str(settings.get("staticIpMode") or "").lower()
    if mode == "auto":
        return "", ""
    base = settings.get("staticIp")
    china = settings.get("chinaStaticIp") or base
    claude = settings.get("claudeStaticIp") or base
    return (public_ipv4(china) if china else "",
            public_ipv4(claude) if claude else "")


def item(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def static_item(name, observed, expected, error_reason=""):
    if error_reason:
        return item(name, "risk", error_reason)
    if not expected:
        return item(name, "unknown", "未配置静态 IP")
    if not observed:
        return item(name, "unknown", "未获取有效公网 IPv4")
    if observed != expected:
        return item(name, "risk",
                    "实际 {}，期望 {}".format(observed, expected))
    return item(name, "pass", observed)


def score_item(risk):
    score = risk.get("trust_score")
    country = risk.get("countryCode")
    if isinstance(country, str) and country.upper() in RESTRICTED_COUNTRIES:
        score = 0
    if (isinstance(score, bool) or not isinstance(score, (int, float))
            or not 0 <= score <= 100 or not math.isfinite(score)):
        return item(ITEM_NAMES[2], "unknown", "评分缺失或无效")
    status = "pass" if score >= 80 else "risk"
    return item(ITEM_NAMES[2], status, "{} 分".format(score))


def region_item(risk, geography):
    country_code = risk.get("countryCode")
    if not isinstance(country_code, str) or not re.fullmatch(
            r"[A-Za-z]{2}", country_code):
        return item(ITEM_NAMES[3], "unknown", "风险接口未提供有效地区代码")
    country_code = country_code.upper()
    country = risk.get("country") or geography.get("country")
    country = country if isinstance(country, str) else country_code
    country = " ".join(country.split())[:60]
    restricted = country_code in RESTRICTED_COUNTRIES
    return item(ITEM_NAMES[3], "risk" if restricted else "pass",
                country or country_code)


def property_item(risk, geography):
    country_code = risk.get("countryCode")
    if (isinstance(country_code, str)
            and country_code.upper() in RESTRICTED_COUNTRIES):
        return item(ITEM_NAMES[4], "risk", "出口位于受限地区")
    region = risk.get("country") or geography.get("country")
    city = risk.get("city") or geography.get("city")
    asn = risk.get("asn")
    asn_text = "AS{}".format(asn) if asn not in (None, "") else ""
    operator = risk.get("asOrganization") or geography.get("isp")
    if not all(isinstance(value, str) and value
               for value in (region, city, asn_text, operator)):
        return item(ITEM_NAMES[4], "unknown",
                    "地区、城市、ASN 或运营商数据缺失")
    if risk.get("isBroadcast") is True:
        return item(ITEM_NAMES[4], "risk", "IP 被标记为广播地址")
    residential = risk.get("isResidential")
    company_type = risk.get("company_type")
    company_type = company_type if isinstance(company_type, str) else ""
    detail = "{}，{}，{}，{}".format(region, city, asn_text, operator)
    if residential is True:
        return item(ITEM_NAMES[4], "pass", "家庭住宅 IP；" + detail)
    if residential is False or company_type.lower() == "hosting":
        return item(ITEM_NAMES[4], "pass", "机房 IP (Hosting)；" + detail)
    if company_type:
        return item(ITEM_NAMES[4], "pass",
                    "{}；{}".format(company_type, detail))
    return item(ITEM_NAMES[4], "unknown", "住宅与机房属性数据缺失；" + detail)


def security_item(risk):
    fields = (
        ("is_vpn", "VPN"), ("is_proxy", "代理"), ("is_tor", "Tor"),
        ("is_crawler", "机器人"), ("is_abuser", "滥用记录"),
    )
    values = [risk.get(key) for key, _label in fields]
    statuses = {True: "检出", False: "未检测到"}
    detail = "，".join(
        label + (statuses[value] if type(value) is bool else "未知")
        for (_key, label), value in zip(fields, values))
    if any(value is True for value in values):
        status = "risk"
    elif all(value is False for value in values):
        status = "pass"
    else:
        status = "unknown"
    return item(ITEM_NAMES[5], status, detail)


def dns_item(servers, geo_map, claude_country):
    if servers is None:
        return item(ITEM_NAMES[6], "unknown", "DNS 检测结果不可用")
    if not servers:
        return item(ITEM_NAMES[6], "unknown",
                    "未获取 DNS 出口，无法确认 DNS 检测结果")
    claude_country = claude_country or ""
    claude_in_china = ("china" in claude_country.lower()
                       or claude_country.upper() == "CN")
    leaked = None
    first = None
    incomplete = False
    for server in servers:
        geo = geo_map.get(server) or {}
        country_code = str(geo.get("country_code") or "").lower()
        try:
            address = ipaddress.ip_address(server)
            valid_address = address.is_global and not address.is_multicast
        except (ValueError, TypeError):
            valid_address = False
        if (not valid_address or len(country_code) != 2
                or not country_code.isascii() or not country_code.isalpha()):
            incomplete = True
        isp = str(geo.get("isp") or "")
        if first is None:
            first = (server, isp)
        if country_code == "cn" and not claude_in_china:
            leaked = (server, isp)
            break
    if leaked:
        server, isp = leaked
        detail = "DNS 出口 {}（中国 DNS".format(server)
        if isp:
            detail += "，{}".format(isp)
        detail += "）"
        return item(ITEM_NAMES[6], "risk", detail)
    if incomplete:
        return item(ITEM_NAMES[6], "unknown", "DNS 出口或归属信息不完整，无法确认")
    if first:
        server, isp = first
        detail = "DNS 出口 {}".format(server)
        if isp:
            detail += "（{}）".format(isp)
        return item(ITEM_NAMES[6], "pass", detail)
    return item(ITEM_NAMES[6], "unknown",
                "未获取 DNS 出口，无法确认 DNS 检测结果")


def webrtc_item(udp_ips, claude_ip):
    if udp_ips is None:
        return item(ITEM_NAMES[7], "unknown", "STUN 检测未完成，UDP 出口待确认")
    public = []
    for address in udp_ips:
        normalized = public_ipv4(address)
        if normalized and normalized not in public:
            public.append(normalized)
    if not public:
        return item(ITEM_NAMES[7], "unknown",
                    "STUN 未获取有效公网 IPv4，无法确认 UDP 出口")
    detail = "UDP 出口 " + "，".join(public)
    if not claude_ip:
        return item(ITEM_NAMES[7], "unknown",
                    detail + "；未获取 Claude 出口 IP，无法比较")
    if any(address != claude_ip for address in public):
        return item(ITEM_NAMES[7], "risk", detail)
    return item(ITEM_NAMES[7], "pass", detail)


def _zone_offset_minutes(name):
    if not name:
        return None
    try:
        zone = ZoneInfo(name)
        offset = datetime.datetime.now(zone).utcoffset()
        return int(offset.total_seconds() // 60)
    except Exception:
        return None


def _win32_local_offset_minutes():
    import ctypes
    from ctypes import wintypes

    class _SYSTEMTIME(ctypes.Structure):
        _fields_ = [
            ("wYear", wintypes.WORD),
            ("wMonth", wintypes.WORD),
            ("wDayOfWeek", wintypes.WORD),
            ("wDay", wintypes.WORD),
            ("wHour", wintypes.WORD),
            ("wMinute", wintypes.WORD),
            ("wSecond", wintypes.WORD),
            ("wMilliseconds", wintypes.WORD),
        ]

    class _TIME_ZONE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Bias", wintypes.LONG),
            ("StandardName", wintypes.WCHAR * 32),
            ("StandardDate", _SYSTEMTIME),
            ("StandardBias", wintypes.LONG),
            ("DaylightName", wintypes.WCHAR * 32),
            ("DaylightDate", _SYSTEMTIME),
            ("DaylightBias", wintypes.LONG),
        ]

    tzi = _TIME_ZONE_INFORMATION()
    result = ctypes.windll.kernel32.GetTimeZoneInformation(ctypes.byref(tzi))
    if result == 0xFFFFFFFF:
        return None
    if result == 2:
        bias = tzi.Bias + tzi.DaylightBias
    elif result == 1:
        bias = tzi.Bias + tzi.StandardBias
    else:
        bias = tzi.Bias
    return -int(bias)


def _local_offset_minutes():
    if sys.platform == "win32":
        try:
            minutes = _win32_local_offset_minutes()
            if minutes is not None:
                return minutes
        except Exception:
            pass
    offset = datetime.datetime.now().astimezone().utcoffset()
    return int(offset.total_seconds() // 60) if offset is not None else None


def _format_offset(minutes):
    sign = "+" if minutes >= 0 else "−"
    value = abs(minutes)
    text = "UTC{}{:02d}:{:02d}".format(sign, value // 60, value % 60)
    return text


def device_item(risk, geography, edge_state, local_offset=None,
                windows_timezone=None):
    if edge_state is None:
        return item(ITEM_NAMES[8], "unknown", "无法读取 Edge 设备信息")
    country_code = str(
        risk.get("countryCode") or geography.get("country_code") or "").upper()
    timezone_name = risk.get("timezone") or CC_TO_TZ.get(country_code)
    claude_offset = _zone_offset_minutes(timezone_name)
    if local_offset is None:
        local_offset = _local_offset_minutes()
    parts = []
    problems = []
    unknown = []
    if claude_offset is None or local_offset is None:
        unknown.append("时区")
    else:
        difference = abs(claude_offset - local_offset)
        matches = difference <= 60
        if (windows_timezone or "").lower() == "china standard time" \
                and country_code != "CN":
            matches = False
        label = "时区一致" if matches else "时区不一致"
        parts.append("{}（{}，{}）".format(
            label, timezone_name or "未知", _format_offset(local_offset)))
        if not matches:
            problems.append("时区")
    languages = edge_state.get("languages") or ""
    primary = languages.split(",")[0].strip().split("-")[0].lower()
    region_languages = LANG_MAP.get(country_code)
    if not primary or not region_languages:
        unknown.append("语言")
    else:
        matches = primary in region_languages
        label = "Edge 网页语言一致" if matches else "Edge 网页语言不一致"
        parts.append("{}（{}）".format(label, languages))
        if not matches:
            problems.append("语言")
    cookie_enabled = edge_state.get("cookie_enabled")
    if cookie_enabled is None:
        unknown.append("Cookie")
    elif cookie_enabled:
        parts.append("Cookie 已启用")
    else:
        parts.append("Cookie 已禁用")
        problems.append("Cookie")
    detail = "；".join(parts) if parts else "设备信息不足"
    if problems:
        return item(ITEM_NAMES[8], "risk", detail)
    if unknown:
        return item(ITEM_NAMES[8], "unknown", detail)
    return item(ITEM_NAMES[8], "pass", detail)


def _clash_mixed_port():
    path = os.path.join(
        os.environ.get("APPDATA", ""),
        "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml")
    try:
        with open(path, encoding="utf-8") as file:
            for line in file:
                key, sep, value = line.partition(":")
                if sep and key.strip() == "mixed-port":
                    port = int(value.split("#")[0].strip())
                    if 1 <= port <= 65535:
                        return port
    except (OSError, ValueError):
        pass
    return 7890


def _trigger_dns(host, timeout=6.0, proxy_port=None):
    path = "/pixel.gif?_=" + str(int(time.time() * 1000))
    headers = {"User-Agent": _USER_AGENT, "Accept": "*/*"}
    context = _get_ssl_context()
    port = _clash_mixed_port() if proxy_port is None else proxy_port
    try:
        proxy_conn = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=timeout, context=context)
        try:
            proxy_conn.set_tunnel(host, 443)
            proxy_conn.request("GET", path, headers=headers)
            proxy_conn.getresponse()
            return
        finally:
            proxy_conn.close()
    except Exception:
        return


def probe_dns(client, claude_country):
    token = "".join(
        secrets.choice(string.ascii_lowercase + string.digits)
        for _ in range(24))
    proxy_port = getattr(client, "proxy_port", None)
    threads = [
        threading.Thread(
            target=_trigger_dns,
            args=("{}-{}{}".format(token, index, DNS_SUFFIX),),
            kwargs={"proxy_port": proxy_port},
            daemon=True,
        )
        for index in (1, 2)
    ]
    for worker in threads:
        worker.start()
    for worker in threads:
        worker.join(7.0)
    time.sleep(0.25)
    servers = None
    for attempt in range(DNS_RESULT_ATTEMPTS):
        data = fetch_json(client, SITE_URL + "/api/dns/result/" + token)
        value = data.get("dns_servers")
        if isinstance(value, list):
            servers = list(dict.fromkeys(
                entry for entry in value if isinstance(entry, str)
            ))[:8]
            if servers:
                break
        if attempt < DNS_RESULT_ATTEMPTS - 1:
            time.sleep(0.75)
    if servers is None:
        return None
    geo_map = {}
    if isinstance(client, HttpClient) and len(servers) > 1:
        def _lookup_geo(server):
            sub = HttpClient(
                total_timeout=12.0,
                proxy_port=client.proxy_port,
                deadline=client.deadline,
                session_pool=client.session_pool,
            )
            info = fetch_json(sub, SITE_URL + "/api/geoip/" + server)
            if not info and sub.deadline - time.monotonic() > 1.0:
                info = fetch_json(sub, SITE_URL + "/api/geoip/" + server)
            return server, info

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(6, len(servers))) as pool:
            for server, info in pool.map(_lookup_geo, servers):
                geo_map[server] = info
    else:
        for server in servers:
            geo_map[server] = fetch_json(
                client, SITE_URL + "/api/geoip/" + server)
    return servers, geo_map


def _build_stun_request(transaction):
    # Include RFC 5389 FINGERPRINT; servers such as Cloudflare drop bare headers.
    body = b"\x00\x01\x00\x08\x21\x12\xa4\x42" + transaction
    fingerprint = binascii.crc32(body) ^ 0x5354554E
    return body + struct.pack("!HHI", 0x8028, 4, fingerprint)


def _stun_query(server, port, timeout=3.0):
    target = socket.getaddrinfo(
        server, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transaction = os.urandom(12)
    request = _build_stun_request(transaction)
    deadline = time.monotonic() + timeout
    intervals = (0.35, 0.55, 0.85, 1.25, 1.5, 1.5)
    step_index = 0
    data = b""
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out")
            sock.sendto(request, target)
            step = intervals[min(step_index, len(intervals) - 1)]
            step_deadline = min(deadline, time.monotonic() + step)
            while True:
                wait = step_deadline - time.monotonic()
                if wait <= 0:
                    break
                sock.settimeout(wait)
                try:
                    packet, _address = sock.recvfrom(2048)
                except TimeoutError:
                    break
                if (len(packet) >= 20
                        and packet[4:8] == b"\x21\x12\xa4\x42"
                        and packet[8:20] == transaction):
                    data = packet
                    break
            if data:
                break
            step_index += 1
    finally:
        sock.close()
    if len(data) < 20 or data[4:8] != b"\x21\x12\xa4\x42":
        return None
    position = 20
    while position + 4 <= len(data):
        attribute_type, length = (
            int.from_bytes(data[position:position + 2], "big"),
            int.from_bytes(data[position + 2:position + 4], "big"))
        value = data[position + 4:position + 4 + length]
        if attribute_type in (0x0020, 0x0001) and len(value) >= 8 and value[1] == 1:
            if attribute_type == 0x0020:
                address = bytes(
                    first ^ second for first, second in zip(
                        value[4:8], b"\x21\x12\xa4\x42"))
            else:
                address = value[4:8]
            if len(address) == 4:
                return socket.inet_ntoa(address)
        position += 4 + length + ((4 - length % 4) % 4)
    return None


def probe_stun():
    servers = (
        ("stun1.l.google.com", 19302),
        ("stun2.l.google.com", 19302),
        ("stun.cloudflare.com", 3478),
        ("global.stun.twilio.com", 3478),
        ("stun.nextcloud.com", 3478),
        ("stun.voip.blackberry.com", 3478),
        ("stun.l.google.com", 19302),
    )
    results = queue.Queue()

    def _query(server, port):
        try:
            address = public_ipv4(_stun_query(server, port, 6.0))
            results.put(address)
        except Exception:
            results.put("")

    for server, port in servers:
        threading.Thread(target=_query, args=(server, port), daemon=True).start()

    deadline = time.monotonic() + 7.5
    for _ in servers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            address = results.get(timeout=remaining)
        except queue.Empty:
            break
        if address:
            return [address]
    return []


def read_edge_state():
    try:
        from region_core import EdgePreferences
        return EdgePreferences().read_language_state()
    except Exception:
        return None


def read_windows_timezone():
    try:
        from region_core import WindowsRegionSystem
        return WindowsRegionSystem().get_timezone_id()
    except Exception:
        return None


def build_report(items):
    labels = {"pass": "通过", "risk": "风险", "unknown": "待确认"}
    has_risk = any(entry["status"] != "pass" for entry in items)
    detail = "\n".join(
        "{}｜{}｜{}".format(entry["name"], labels[entry["status"]],
                          entry["detail"])
        for entry in items)
    return {
        "title": "检测完成，有风险或待确认项" if has_risk else "检测通过",
        "detail": detail,
        "hasRisk": has_risk,
        "items": items,
    }


def run_checks(client=None, settings=None, dns_probe=None, stun_probe=None,
               edge_state=None, local_offset=None, windows_timezone=None,
               baseline_ip=None):
    created_pool = ProxyConnectionPool() if client is None else None
    client = client or HttpClient(
        proxy_port=_clash_mixed_port(), session_pool=created_pool)
    try:
        settings = load_settings() if settings is None else settings
        mode = (str(settings.get("staticIpMode") or "").lower()
                if isinstance(settings, dict) else "")
        china_expected, claude_expected = static_targets(settings)
        auto_error = ""
        if isinstance(client, HttpClient):
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                china_future = pool.submit(fetch_china_ip, client)
                claude_future = pool.submit(
                    fetch_trace_ip, client, CLAUDE_TRACE_URL)
                confirm_future = (
                    pool.submit(fetch_trace_ip, client, CLOUDFLARE_TRACE_URL)
                    if mode == "auto" else None)
                stun_future = pool.submit(
                    probe_stun if stun_probe is None else stun_probe)
                early_dns_future = (
                    pool.submit(probe_dns, client, "")
                    if dns_probe is None else None)
                claude_ip = claude_future.result()
                if claude_ip:
                    risk_future = pool.submit(
                        fetch_json, client, SITE_URL + "/api/iprisk/" + claude_ip)
                    geo_future = pool.submit(
                        fetch_json, client, SITE_URL + "/api/geoip/" + claude_ip)
                    risk = risk_future.result()
                    geography = geo_future.result()
                else:
                    risk = {}
                    geography = {}
                china_ip = china_future.result()
                confirmation = (
                    confirm_future.result() if confirm_future is not None else "")
                udp_ips = stun_future.result()
                claude_country = str(
                    risk.get("country") or geography.get("country")
                    or risk.get("countryCode") or "")
                dns_observation = (
                    early_dns_future.result()
                    if early_dns_future is not None
                    else dns_probe(client, claude_country))
        else:
            china_ip = fetch_china_ip(client)
            claude_ip = fetch_trace_ip(client, CLAUDE_TRACE_URL)
            confirmation = (
                fetch_trace_ip(client, CLOUDFLARE_TRACE_URL)
                if mode == "auto" else "")
            risk = {}
            geography = {}
            if claude_ip:
                risk = fetch_json(client, SITE_URL + "/api/iprisk/" + claude_ip)
                geography = fetch_json(
                    client, SITE_URL + "/api/geoip/" + claude_ip)
            claude_country = str(
                risk.get("country") or geography.get("country")
                or risk.get("countryCode") or "")
            dns_observation = (
                probe_dns(client, claude_country) if dns_probe is None
                else dns_probe(client, claude_country))
            udp_ips = probe_stun() if stun_probe is None else stun_probe()

        if mode == "auto":
            if not china_ip or not claude_ip or not confirmation:
                auto_error = "无法确认多个实际出口 IP"
            elif len({china_ip, claude_ip, confirmation}) != 1:
                auto_error = "多个实际出口 IP 不一致，无法确认自动基准"
            else:
                expected = public_ipv4(baseline_ip) if baseline_ip else claude_ip
                china_expected = claude_expected = expected
                if baseline_ip and not expected:
                    auto_error = "无法确认有效启动基准 IP"

        if dns_observation is None:
            dns_entry = dns_item(None, {}, claude_country)
        else:
            servers, geo_map = dns_observation
            dns_entry = dns_item(servers, geo_map, claude_country)
        if edge_state is None:
            edge_state = read_edge_state()
        if windows_timezone is None:
            windows_timezone = read_windows_timezone()
        items = [
            static_item(ITEM_NAMES[0], china_ip, china_expected, auto_error),
            static_item(ITEM_NAMES[1], claude_ip, claude_expected, auto_error),
            score_item(risk) if claude_ip else item(
                ITEM_NAMES[2], "unknown", "未获取到 Claude 出口 IP"),
            region_item(risk, geography) if claude_ip else item(
                ITEM_NAMES[3], "unknown", "未获取到 Claude 出口 IP"),
            property_item(risk, geography) if claude_ip else item(
                ITEM_NAMES[4], "unknown", "未获取到 Claude 出口 IP"),
            security_item(risk) if claude_ip else item(
                ITEM_NAMES[5], "unknown", "未获取到 Claude 出口 IP"),
            dns_entry,
            webrtc_item(udp_ips, claude_ip),
            device_item(risk, geography, edge_state, local_offset,
                        windows_timezone),
        ]
        if auto_error:
            items[0] = item(ITEM_NAMES[0], "unknown", auto_error)
            items[1] = item(ITEM_NAMES[1], "unknown", auto_error)
        return build_report(items)
    finally:
        if created_pool is not None:
            created_pool.close_all()


def main():
    try:
        report = run_checks()
    except Exception:
        report = build_report([
            item(name, "unknown", "本项未能完成，结果待确认")
            for name in ITEM_NAMES
        ])
    sys.stdout.reconfigure(encoding="utf-8")
    output = {key: report[key] for key in ("title", "detail", "hasRisk")}
    print(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
