import json
import queue
import socket
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import risk_check


STATIC_IP = "8.8.8.8"
DNS_IP = "9.9.9.9"


def clean_risk():
    return {
        "trust_score": 87, "countryCode": "us", "country": "United States",
        "city": "Los Angeles", "asn": 2914,
        "asOrganization": "NTT America, Inc.", "isResidential": False,
        "company_type": "hosting", "isBroadcast": False,
        "is_vpn": False, "is_proxy": False, "is_tor": False,
        "is_crawler": False, "is_abuser": False,
        "timezone": "America/Los_Angeles",
    }


def clean_geo():
    return {
        "country": "United States", "city": "Los Angeles",
        "country_code": "us", "isp": "NTT America",
    }


class FakeClient:
    def __init__(self, risk=None, geo=None, china=STATIC_IP,
                 claude=STATIC_IP):
        self.risk = clean_risk() if risk is None else risk
        self.geo = clean_geo() if geo is None else geo
        self.china = china
        self.claude = claude

    def get(self, url):
        if url in risk_check.CHINA_URLS:
            return ("<html>" + self.china + "</html>").encode()
        if url in (risk_check.CLAUDE_TRACE_URL, risk_check.CLOUDFLARE_TRACE_URL):
            return ("ip=" + self.claude + "\nloc=US\n").encode()
        if "/api/iprisk/" in url:
            return json.dumps(self.risk).encode()
        if "/api/geoip/" in url:
            if url.endswith("/" + DNS_IP):
                return json.dumps(
                    {"country": "United States", "country_code": "us",
                     "isp": "Quad9"}).encode()
            return json.dumps(self.geo).encode()
        raise AssertionError("Unexpected endpoint: " + url)


def run(client, **overrides):
    arguments = dict(
        client=client,
        settings={"staticIp": STATIC_IP},
        dns_probe=lambda client, country: (
            [DNS_IP], {DNS_IP: {"country_code": "us", "isp": "Quad9"}}),
        stun_probe=lambda: [STATIC_IP],
        edge_state={"languages": "en-US,en", "cookie_enabled": True},
        local_offset=-480,
        windows_timezone="Pacific Standard Time",
    )
    arguments.update(overrides)
    return risk_check.run_checks(**arguments)


class HttpClientTests(unittest.TestCase):

    def test_explicit_proxy_uses_real_connect_hostname_without_target_dns(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        self.addCleanup(listener.close)
        received = queue.Queue()

        def proxy():
            try:
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(2)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    received.put(data)
                    connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except Exception as error:
                received.put(error)

        worker = threading.Thread(target=proxy, daemon=True)
        worker.start()
        resolver = socket.getaddrinfo
        with patch("risk_check.socket.getaddrinfo", wraps=resolver) as dns, \
                patch.dict("os.environ", {"NO_PROXY": "*"}):
            client = risk_check.HttpClient(
                proxy_port=listener.getsockname()[1], total_timeout=1)
            self.assertEqual(risk_check.fetch_text(
                client, "https://never-resolve.invalid/cdn-cgi/trace"), "")
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertIn(b"CONNECT never-resolve.invalid:443 ", received.get_nowait())
        self.assertTrue(dns.call_args_list)
        self.assertTrue(all(call.args[0] == "127.0.0.1"
                            for call in dns.call_args_list))

    def test_invalid_proxy_port_is_rejected(self):
        for port in (0, 65536, True, "7890"):
            with self.assertRaises(ValueError):
                risk_check.HttpClient(proxy_port=port)

    def test_transient_transport_failure_recovers_with_one_retry(self):
        for error in (TimeoutError(), ConnectionResetError(),
                      urllib.error.URLError(ConnectionRefusedError()),
                      urllib.error.HTTPError("https://example.com", 503,
                                             "Unavailable", {}, None)):
            with self.subTest(error=type(error).__name__):
                client = risk_check.HttpClient()
                with patch.object(client, "_download", side_effect=[
                        error, b"observed"]) as download, patch(
                            "risk_check.time.sleep"):
                    self.assertEqual(client.get("https://example.com"),
                                     b"observed")
                self.assertEqual(download.call_count, 2)

    def test_persistent_failure_is_bounded_and_not_a_pass(self):
        client = risk_check.HttpClient()
        with patch.object(client, "_download",
                          side_effect=TimeoutError) as download:
            with patch("risk_check.time.sleep"):
                self.assertEqual(risk_check.fetch_text(
                    client, "https://example.com"), "")
        self.assertEqual(download.call_count, 2)

    def test_certificate_http_denial_and_invalid_data_are_not_retried(self):
        for error in (
                ssl.SSLCertVerificationError(),
                urllib.error.URLError(ssl.SSLCertVerificationError()),
                urllib.error.HTTPError("https://example.com", 403,
                                       "Forbidden", {}, None),
                ValueError("Detection response exceeded size limit")):
            with self.subTest(error=type(error).__name__):
                client = risk_check.HttpClient()
                with patch.object(client, "_download",
                                  side_effect=error) as download:
                    self.assertEqual(risk_check.fetch_text(
                        client, "https://example.com"), "")
                self.assertEqual(download.call_count, 1)

    def test_expired_total_deadline_prevents_retry(self):
        with patch("risk_check.time.monotonic", side_effect=[0, 0, 51]):
            client = risk_check.HttpClient()
            with patch.object(client, "_download",
                              side_effect=TimeoutError) as download:
                self.assertEqual(risk_check.fetch_text(
                    client, "https://example.com"), "")
        self.assertEqual(download.call_count, 1)


class RiskCheckTests(unittest.TestCase):

    def test_all_nine_pass_with_clean_observations(self):
        report = run(FakeClient())
        self.assertEqual(len(report["items"]), 9)
        self.assertFalse(report["hasRisk"])
        self.assertEqual(report["title"], "检测通过")
        self.assertTrue(all(entry["status"] == "pass"
                            for entry in report["items"]))

    def test_static_ip_mismatch_is_reported(self):
        report = run(FakeClient(china="1.1.1.1"))
        self.assertEqual(report["items"][0]["status"], "risk")
        self.assertIn("期望", report["items"][0]["detail"])
        self.assertTrue(report["hasRisk"])

    def test_missing_static_configuration_is_unknown(self):
        report = run(FakeClient(), settings={})
        self.assertEqual(report["items"][0]["status"], "unknown")
        self.assertEqual(report["items"][1]["status"], "unknown")

    def test_auto_consensus_uses_exit_not_node_and_does_not_bind(self):
        with patch("risk_check.resolve_node_ip", return_value="9.9.9.9") as node:
            report = run(FakeClient(), settings={"staticIpMode": "auto"})
        self.assertEqual(report["items"][1]["status"], "pass")
        self.assertEqual(report["items"][1]["detail"], STATIC_IP)
        node.assert_not_called()

    def test_auto_route_disagreement_cannot_be_replaced_by_good_score(self):
        report = run(FakeClient(china="1.1.1.1"),
                     settings={"staticIpMode": "auto"})
        self.assertEqual(report["items"][1]["status"], "unknown")
        self.assertEqual(report["items"][2]["status"], "pass")

    def test_auto_bound_baseline_rejects_new_consistent_exit(self):
        report = run(FakeClient(), settings={"staticIpMode": "auto"},
                     baseline_ip="9.9.9.9")
        self.assertEqual(report["items"][1]["status"], "risk")

    def test_trust_score_boundaries(self):
        for value, expected in ((79.9, "risk"), (80, "pass"), (100, "pass"),
                                (-1, "unknown"), (101, "unknown"),
                                (True, "unknown"), ("95", "unknown"),
                                (float("nan"), "unknown")):
            with self.subTest(value=value):
                self.assertEqual(
                    risk_check.score_item({"trust_score": value})["status"],
                    expected)

    def test_restricted_country_forces_zero(self):
        for country in risk_check.RESTRICTED_COUNTRIES:
            risk = {"trust_score": 99, "countryCode": country.lower()}
            self.assertEqual(risk_check.score_item(risk)["status"], "risk")
            self.assertEqual(
                risk_check.region_item(risk, {})["status"], "risk")

    def test_hosting_property_is_accepted(self):
        entry = risk_check.property_item(clean_risk(), clean_geo())
        self.assertEqual(entry["status"], "pass")
        self.assertIn("Hosting", entry["detail"])
        risk = dict(clean_risk(), isResidential=True, company_type="isp")
        self.assertEqual(
            risk_check.property_item(risk, clean_geo())["status"], "pass")

    def test_missing_property_data_is_unknown(self):
        risk = dict(clean_risk(), city="")
        self.assertEqual(
            risk_check.property_item(risk, {})["status"], "unknown")

    def test_security_requires_five_false_values(self):
        self.assertEqual(
            risk_check.security_item(clean_risk())["status"], "pass")
        for field in ("is_vpn", "is_proxy", "is_tor", "is_crawler",
                      "is_abuser"):
            for value, expected in ((True, "risk"), (None, "unknown"),
                                    (0, "unknown"), ("false", "unknown")):
                changed = dict(clean_risk(), **{field: value})
                self.assertEqual(
                    risk_check.security_item(changed)["status"], expected)

    def test_dns_leak_rules(self):
        cn = {"country_code": "cn", "isp": "China DNS"}
        us = {"country_code": "us", "isp": "Quad9"}
        self.assertEqual(
            risk_check.dns_item([DNS_IP], {DNS_IP: cn}, "United States")["status"],
            "risk")
        self.assertEqual(
            risk_check.dns_item([DNS_IP], {DNS_IP: us}, "United States")["status"],
            "pass")
        self.assertEqual(
            risk_check.dns_item(None, {}, "United States")["status"],
            "unknown")
        self.assertEqual(
            risk_check.dns_item([DNS_IP], {DNS_IP: cn}, "China")["status"],
            "pass")

    def test_empty_dns_observation_is_unknown(self):
        entry = risk_check.dns_item([], {}, "United States")
        self.assertEqual(entry["status"], "unknown")
        self.assertEqual(entry["detail"], "未获取 DNS 出口，无法确认 DNS 检测结果")

    def test_empty_dns_observation_leaves_report_unconfirmed(self):
        report = run(FakeClient(), dns_probe=lambda client, country: ([], {}))
        self.assertEqual(report["items"][6]["status"], "unknown")
        self.assertTrue(report["hasRisk"])
        self.assertIn("DNS 泄露检测｜待确认", report["detail"])

    def test_webrtc_rules(self):
        for addresses, reason in (
                (None, "STUN 检测未完成"),
                ([], "未获取有效公网 IPv4"),
                (["10.0.0.1", "bad", None], "未获取有效公网 IPv4")):
            with self.subTest(addresses=addresses):
                entry = risk_check.webrtc_item(addresses, STATIC_IP)
                self.assertEqual(entry["status"], "unknown")
                self.assertEqual(entry["name"], "UDP 出口检测（STUN）")
                self.assertIn(reason, entry["detail"])
                self.assertNotIn("WebRTC", entry["detail"])
        self.assertEqual(
            risk_check.webrtc_item([STATIC_IP], STATIC_IP)["status"], "pass")
        self.assertEqual(
            risk_check.webrtc_item(["1.1.1.1"], STATIC_IP)["status"], "risk")
        self.assertEqual(
            risk_check.webrtc_item([STATIC_IP], "")["status"], "unknown")

    def test_failed_stun_queries_leave_report_unconfirmed(self):
        with patch("risk_check._stun_query", side_effect=TimeoutError):
            report = run(FakeClient(), stun_probe=risk_check.probe_stun)
        self.assertEqual(report["items"][7]["status"], "unknown")
        self.assertTrue(report["hasRisk"])
        self.assertEqual(report["title"], "检测完成，有风险或待确认项")
        self.assertIn("UDP 出口检测（STUN）｜待确认", report["detail"])

    def test_device_info_rules(self):
        risk = clean_risk()
        geo = clean_geo()
        state = {"languages": "en-US,en", "cookie_enabled": True}
        entry = risk_check.device_item(
            risk, geo, state, -480, "Pacific Standard Time")
        self.assertEqual(entry["status"], "pass")
        self.assertIn("Edge 网页语言一致", entry["detail"])
        mismatch = risk_check.device_item(
            risk, geo, {"languages": "zh-CN", "cookie_enabled": True},
            -480, "Pacific Standard Time")
        self.assertEqual(mismatch["status"], "risk")
        china = risk_check.device_item(
            risk, geo, state, -480, "China Standard Time")
        self.assertEqual(china["status"], "risk")
        disabled = risk_check.device_item(
            risk, geo, {"languages": "en-US", "cookie_enabled": False},
            -480, "Pacific Standard Time")
        self.assertEqual(disabled["status"], "risk")

    def test_public_ipv4_validation(self):
        for value in ("127.0.0.1", "10.0.0.1", "192.0.2.1", "224.0.0.1",
                      "::1", "2606:4700:4700::1111", "8.8.8.8/24", "bad",
                      None):
            self.assertEqual(risk_check.public_ipv4(value), "")
        self.assertEqual(risk_check.public_ipv4("8.8.8.8"), "8.8.8.8")

    def test_missing_claude_ip_keeps_nine_items(self):
        report = run(FakeClient(claude=""))
        self.assertEqual(len(report["items"]), 9)
        self.assertTrue(report["hasRisk"])
        self.assertEqual(report["items"][1]["status"], "unknown")
        self.assertEqual(report["items"][2]["status"], "unknown")

    def test_dns_probe_failure_is_unknown(self):
        report = run(FakeClient(), dns_probe=lambda client, country: None)
        self.assertEqual(report["items"][6]["status"], "unknown")

    def test_dns_requires_complete_geography_but_preserves_known_leak(self):
        cn = {"country_code": "cn"}
        for servers, geography, expected in (
                ([DNS_IP], {}, "unknown"),
                ([DNS_IP], {DNS_IP: {"country_code": "unknown"}}, "unknown"),
                (["bad"], {"bad": {"country_code": "us"}}, "unknown"),
                (["2606:4700:4700::1111"],
                 {"2606:4700:4700::1111": {"country_code": "us"}}, "pass"),
                ([DNS_IP, STATIC_IP], {STATIC_IP: cn}, "risk")):
            with self.subTest(servers=servers, geography=geography):
                entry = risk_check.dns_item(servers, geography, "United States")
                self.assertEqual(entry["status"], expected)

    def test_dns_polling_accepts_delayed_observation(self):
        client = unittest.mock.Mock()
        client.get.side_effect = [
            b'{"dns_servers": []}', b'{"dns_servers": []}',
            json.dumps({"dns_servers": [DNS_IP]}).encode(),
            b'{"country_code": "us"}',
        ]
        with patch("risk_check._trigger_dns"), patch("risk_check.time.sleep"):
            servers, geography = risk_check.probe_dns(client, "United States")
        self.assertEqual(servers, [DNS_IP])
        self.assertEqual(geography[DNS_IP]["country_code"], "us")

    def test_dns_trigger_uses_client_proxy_and_never_falls_back_direct(self):
        client = unittest.mock.Mock(proxy_port=18080)
        client.get.return_value = b'{"dns_servers": []}'
        with patch("risk_check._trigger_dns") as trigger, patch(
                "risk_check.time.sleep"):
            risk_check.probe_dns(client, "US")
        self.assertEqual(trigger.call_count, 2)
        self.assertTrue(all(call.kwargs["proxy_port"] == 18080
                            for call in trigger.call_args_list))
        with patch("risk_check.http.client.HTTPSConnection",
                   side_effect=ConnectionRefusedError) as connection:
            risk_check._trigger_dns("probe.invalid", proxy_port=18080)
        connection.assert_called_once()
        self.assertEqual(connection.call_args.args[:2], ("127.0.0.1", 18080))

    def test_dns_polling_exhaustion_remains_unknown(self):
        client = unittest.mock.Mock()
        client.get.return_value = b'{"dns_servers": []}'
        with patch("risk_check._trigger_dns"), patch("risk_check.time.sleep"):
            observation = risk_check.probe_dns(client, "United States")
        self.assertEqual(client.get.call_count, risk_check.DNS_RESULT_ATTEMPTS)
        self.assertEqual(observation, ([], {}))
        self.assertEqual(risk_check.dns_item(*observation, "US")["status"],
                         "unknown")

    def test_unused_cloudflare_probe_is_not_requested(self):
        client = FakeClient()
        with patch.object(client, "get", wraps=client.get) as get:
            self.assertFalse(run(client)["hasRisk"])
        self.assertNotIn(unittest.mock.call("https://1.1.1.1/cdn-cgi/trace"),
                         get.call_args_list)

    def test_report_detail_has_nine_lines(self):
        report = run(FakeClient())
        self.assertEqual(len(report["detail"].splitlines()), 9)
        self.assertEqual(set(report), {"title", "detail", "hasRisk", "items"})

    def test_load_settings_creates_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "settings.json")
            settings = risk_check.load_settings(path)
            self.assertEqual(settings["staticIp"], "")
            self.assertEqual(settings["targetNode"], "")
            self.assertEqual(settings["staticIpMode"], "auto")
            self.assertTrue(Path(path).is_file())

    def test_win32_local_offset_matches_live_timezone(self):
        offset = risk_check._local_offset_minutes()
        self.assertIsInstance(offset, int)
        self.assertTrue(-720 <= offset <= 840)

    def test_save_settings_merges_and_persists_and_normalizes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "settings.json")
            saved = risk_check.save_settings(
                {
                    "targetNode": "US Static",
                    "staticIpMode": "manual",
                    "staticIp": "8.8.8.8",
                },
                path,
            )
            self.assertEqual(saved["targetNode"], "US Static")
            self.assertEqual(saved["staticIpMode"], "manual")
            self.assertEqual(saved["staticIp"], "8.8.8.8")
            legacy = risk_check.save_settings({"staticIpMode": "quality_only"}, path)
            self.assertEqual(legacy["staticIpMode"], "auto")
            reloaded = risk_check.load_settings(path)
            self.assertEqual(reloaded["targetNode"], "US Static")
            self.assertEqual(reloaded["staticIpMode"], "auto")
            self.assertEqual(reloaded["staticIp"], "8.8.8.8")

    def test_auto_mode_missing_actual_exit_is_unknown(self):
        with unittest.mock.patch("risk_check.resolve_node_ip", return_value=""):
            self.assertEqual(
                risk_check.static_targets({
                    "staticIpMode": "auto",
                    "targetNode": "MissingNode",
                    "staticIp": "8.8.8.8",
                }),
                ("", ""),
            )
            report = run(
                FakeClient(claude=""),
                settings={
                    "staticIpMode": "auto",
                    "targetNode": "MissingNode",
                    "staticIp": STATIC_IP,
                },
            )
        self.assertEqual(report["items"][0]["status"], "unknown")
        self.assertEqual(report["items"][1]["status"], "unknown")
        self.assertIn("无法确认", report["items"][1]["detail"])
        self.assertTrue(report["hasRisk"])

    def test_probe_stun_races_fallback_google_servers(self):
        def fake_stun(server, _port, _timeout=3.0):
            if server == "stun2.l.google.com":
                return STATIC_IP
            raise TimeoutError("timed out")

        with patch("risk_check._stun_query", side_effect=fake_stun):
            self.assertEqual(risk_check.probe_stun(), [STATIC_IP])

    def test_stun_query_sends_fingerprint_and_retries_after_timeout(self):
        import binascii
        import struct

        received_requests = []
        stop = threading.Event()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(2)
        self.addCleanup(sock.close)
        self.addCleanup(stop.set)

        def server():
            attempt = 0
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                except TimeoutError:
                    break
                received_requests.append(data)
                attempt += 1
                if attempt == 1:
                    continue
                tx = data[8:20]
                wrong_tx = b"\x00" * 12
                sock.sendto(b"\x01\x01\x00\x00\x21\x12\xa4\x42" + wrong_tx, addr)
                xor_ip = bytes(a ^ b for a, b in zip(
                    socket.inet_aton(STATIC_IP), b"\x21\x12\xa4\x42"))
                attr = struct.pack("!HHBBH", 0x0020, 8, 0, 1, 0) + xor_ip
                header = b"\x01\x01" + struct.pack("!H", len(attr)) + b"\x21\x12\xa4\x42" + tx
                sock.sendto(header + attr, addr)
                break

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        host, port = sock.getsockname()
        ip = risk_check._stun_query(host, port, timeout=2.0)
        worker.join(2)
        self.assertEqual(ip, STATIC_IP)
        self.assertEqual(len(received_requests), 2)
        req = received_requests[0]
        self.assertEqual(len(req), 28)
        self.assertEqual(req[20:24], b"\x80\x28\x00\x04")
        expected_fp = binascii.crc32(req[:20]) ^ 0x5354554E
        self.assertEqual(struct.unpack("!I", req[24:28])[0], expected_fp)

    def test_keepalive_pool_reuses_and_recovers_from_closed_socket(self):
        connections = []

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(2)
        self.addCleanup(listener.close)
        requests_served = []
        stop = threading.Event()
        self.addCleanup(stop.set)

        def server_loop():
            while not stop.is_set():
                try:
                    conn, _addr = listener.accept()
                except TimeoutError:
                    continue
                connections.append(conn)
                conn.settimeout(2)
                idx = len(connections)
                try:
                    if idx == 1:
                        for count in range(2):
                            buf = b""
                            while b"\r\n\r\n" not in buf:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                buf += chunk
                            if not buf:
                                break
                            requests_served.append((idx, count))
                            body = b"ip=8.8.8.8\n"
                            header = (
                                b"HTTP/1.1 200 OK\r\nContent-Length: "
                                + str(len(body)).encode()
                                + (b"\r\nConnection: close\r\n\r\n" if count == 1 else b"\r\n\r\n")
                            )
                            conn.sendall(header + body)
                    else:
                        buf = b""
                        while b"\r\n\r\n" not in buf:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            buf += chunk
                        requests_served.append((idx, 0))
                        body = b"ip=8.8.8.8\n"
                        conn.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\nConnection: close\r\n\r\n" + body
                        )
                finally:
                    conn.close()

        worker = threading.Thread(target=server_loop, daemon=True)
        worker.start()
        pool = risk_check.ProxyConnectionPool()
        self.addCleanup(pool.close_all)
        with patch.dict("os.environ", {"NO_PROXY": "*"}):
            client = risk_check.HttpClient(
                proxy_port=listener.getsockname()[1],
                total_timeout=3,
                session_pool=pool,
            )
            for _ in range(3):
                self.assertEqual(
                    risk_check.fetch_trace_ip(client, "http://trace.invalid/cdn-cgi/trace"),
                    "8.8.8.8",
                )
        stop.set()
        worker.join(2)
        self.assertEqual(len(requests_served), 3)
        self.assertEqual(requests_served[0], (1, 0))
        self.assertEqual(requests_served[1], (1, 1))
        self.assertEqual(requests_served[2], (2, 0))


if __name__ == "__main__":
    unittest.main()
