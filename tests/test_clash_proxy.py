import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import clash_proxy


class HotkeyTests(unittest.TestCase):

    def test_shift_s(self):
        key = clash_proxy.parse_hotkey("SHIFT+S")
        self.assertEqual(key["id"], 33554469)
        self.assertEqual(key["windows_modifiers"], 4)
        self.assertEqual(key["virtual_key"], ord("S"))

    def test_ctrl_alt_t(self):
        key = clash_proxy.parse_hotkey("CTRL+ALT+T")
        self.assertEqual(key["windows_modifiers"], 3)
        self.assertEqual(key["virtual_key"], ord("T"))

    def test_cmd_or_ctrl(self):
        key = clash_proxy.parse_hotkey("CMDORCTRL+1")
        self.assertEqual(key["windows_modifiers"], 2)

    def test_invalid(self):
        for value in ("SHIFT+", "SHIFT+SS", "FOO+S"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    clash_proxy.parse_hotkey(value)


class ConfigParserTests(unittest.TestCase):

    def test_verge_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verge.yaml"
            path.write_text(
                "enable_tun_mode: true\n"
                "enable_system_proxy: false\n"
                "hotkeys:\n"
                "- toggle_system_proxy,SHIFT+S\n"
                "- toggle_tun_mode,SHIFT+V\n"
                "enable_global_hotkey: true\n"
                "other:\n"
                "  enable_tun_mode: false\n",
                encoding="utf-8")
            settings = clash_proxy.VergeHotkeySettings(str(path))
            config = settings._read_config()
            self.assertEqual(config["enable_tun_mode"], "true")
            self.assertEqual(config["enable_system_proxy"], "false")
            self.assertEqual(config["toggle_system_proxy"], "SHIFT+S")
            self.assertEqual(config["toggle_tun_mode"], "SHIFT+V")
            self.assertTrue(clash_proxy._flag(
                config, "enable_tun_mode", False))

    def test_flag_invalid(self):
        with self.assertRaises(RuntimeError):
            clash_proxy._flag({"enable_tun_mode": "yes"},
                              "enable_tun_mode", False)

    def test_clash_yaml_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-verge.yaml"
            path.write_text(
                "external-controller-pipe: '\\\\.\\pipe\\verge-test'\n"
                "secret: 'a#b''c'\n"
                "external-controller: ''\n",
                encoding="utf-8")
            values = clash_proxy.read_settings(str(path))
            self.assertEqual(values["external-controller-pipe"],
                             "\\\\.\\pipe\\verge-test")
            self.assertEqual(values["secret"], "a#b'c")


class ResponseTests(unittest.TestCase):

    def test_chunked_response(self):
        body = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        self.assertEqual(clash_proxy._parse_response(body), b"hello world")

    def test_content_length_response(self):
        body = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        self.assertEqual(clash_proxy._parse_response(body), b"{}")

    def test_non_success_response(self):
        with self.assertRaises(ValueError):
            clash_proxy._parse_response(
                b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n")

    def test_address_must_be_loopback(self):
        with self.assertRaises(RuntimeError):
            clash_proxy.LocalClashApi(address="http://example.com:9090/")
        with self.assertRaises(RuntimeError):
            clash_proxy.LocalClashApi(address="http://127.0.0.1:9090/path")
        clash_proxy.LocalClashApi(address="http://127.0.0.1:9090/")

    def test_read_proxy_server_parses_yaml_node(self):
        import tempfile
        from pathlib import Path

        yaml_text = (
            "proxies:\n"
            "  - {name: StaticNode, type: socks5, server: 93.184.216.34, port: 1080}\n"
            "- name: 'Unindented Static'\n"
            "  type: socks5\n"
            "  server: 1.1.1.1\n"
            "  - name: 'US Static'\n"
            "    type: http\n"
            '    server: "8.8.8.8"\n'
            "    port: 8080\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "clash-verge.yaml"
            cfg.write_text(yaml_text, encoding="utf-8")
            self.assertEqual(
                clash_proxy.read_proxy_server("StaticNode", str(cfg)),
                "93.184.216.34",
            )
            self.assertEqual(
                clash_proxy.read_proxy_server("Unindented Static", str(cfg)),
                "1.1.1.1",
            )
            self.assertEqual(
                clash_proxy.read_proxy_server("US Static", str(cfg)),
                "8.8.8.8",
            )
            self.assertEqual(clash_proxy.read_proxy_server("Missing", str(cfg)), "")

    def test_target_node_and_list_global_nodes(self):
        class FakeApi:
            def request(self, method, path):
                if method == "GET" and path == "/proxies":
                    return {
                        "proxies": {
                            "DIRECT": {"type": "Direct"},
                            "GLOBAL": {
                                "type": "Selector",
                                "all": ["DIRECT", "StaticNode", "US Static"],
                            },
                            "StaticNode": {"type": "Socks5"},
                            "US Static": {"type": "Shadowsocks"},
                        }
                    }
                return {}

        switcher = clash_proxy.ClashProxySwitch(
            connect=lambda: FakeApi(),
            target_node="US Static",
        )
        self.assertEqual(switcher.get_target_node(), "US Static")
        self.assertEqual(switcher.list_global_nodes(), ["StaticNode", "US Static"])

    def test_verify_usa_active_reads_configs_once(self):
        calls = []

        class FakeApi:
            def request(self, method, path):
                calls.append((method, path))
                if path == "/configs":
                    return {"mode": "global", "tun": {"enable": True}}
                if path == "/proxies/GLOBAL":
                    return {"now": "StaticNode"}
                return {}

        class FakeClient:
            def read(self):
                return clash_proxy.VergeProxyState(
                    system_proxy=False, tun=True,
                    windows_proxy=False, windows_pac=False)

        switcher = clash_proxy.ClashProxySwitch(
            connect=lambda: FakeApi(),
            connect_client=lambda: FakeClient(),
            target_node="StaticNode",
        )
        ok, reason = switcher.verify_usa_active()
        self.assertTrue(ok)
        self.assertIn("StaticNode", reason)
        self.assertEqual(calls, [("GET", "/configs"), ("GET", "/proxies/GLOBAL")])

    def test_missing_target_node_is_rejected_without_hardcoded_fallback(self):
        switcher = clash_proxy.ClashProxySwitch(
            connect=lambda: None,
            connect_client=lambda: None,
        )
        with patch(
                "risk_check.load_settings",
                return_value={"targetNode": "", "staticIpMode": "auto", "staticIp": ""}):
            self.assertEqual(switcher.get_target_node(), "")
            with self.assertRaises(RuntimeError):
                switcher.prepare_usa()
            ok, reason = switcher.verify_usa_active()
            self.assertFalse(ok)
            self.assertIn("未配置", reason)


if __name__ == "__main__":
    unittest.main()
