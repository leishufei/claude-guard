import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import region_core


def write_profile(root, languages, selected=None):
    profile = Path(root) / "Default"
    profile.mkdir(parents=True, exist_ok=True)
    preferences = {
        "intl": {
            "accept_languages": languages,
            "selected_languages": selected or languages,
        },
        "profile": {"cookie_behavior": 0},
    }
    (profile / "Preferences").write_text(
        json.dumps(preferences), encoding="utf-8")
    (Path(root) / "Local State").write_text(
        json.dumps({"profile": {"last_used": "Default",
                                "last_active_profiles": ["Default"]}}),
        encoding="utf-8")


class EdgePreferencesTests(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = self.directory.name
        write_profile(self.root, "zh-CN,zh")

    def tearDown(self):
        self.directory.cleanup()

    def test_read_write_and_restore(self):
        preferences = region_core.EdgePreferences(
            self.root, lambda: False)
        snapshot = preferences.read()
        self.assertEqual(snapshot.profile_name, "Default")
        self.assertEqual(snapshot.languages, "zh-CN,zh")
        original = (Path(self.root) / "Default" / "Preferences").read_bytes()
        preferences.write(snapshot, "en-US,en")
        updated = json.loads(
            (Path(self.root) / "Default" / "Preferences").read_text(
                encoding="utf-8"))
        self.assertEqual(updated["intl"]["accept_languages"], "en-US,en")
        self.assertEqual(updated["intl"]["selected_languages"], "en-US,en")
        backup = (Path(self.root) / "Default"
                  / "Preferences.claudeguard.bak")
        self.assertEqual(backup.read_bytes(), original)
        preferences.restore(snapshot)
        self.assertEqual(
            (Path(self.root) / "Default" / "Preferences").read_bytes(),
            original)

    def test_browser_running_blocks_write(self):
        preferences = region_core.EdgePreferences(
            self.root, lambda: True)
        snapshot = preferences.read()
        with self.assertRaises(RuntimeError):
            preferences.write(snapshot, "en-US,en")

    def test_concurrent_change_blocks_write(self):
        preferences = region_core.EdgePreferences(
            self.root, lambda: False)
        snapshot = preferences.read()
        path = Path(self.root) / "Default" / "Preferences"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(RuntimeError):
            preferences.write(snapshot, "en-US,en")

    def test_language_state_cookie_setting(self):
        preferences = region_core.EdgePreferences(
            self.root, lambda: False)
        state = preferences.read_language_state()
        self.assertTrue(state["cookie_enabled"])
        profile = Path(self.root) / "Default" / "Preferences"
        data = json.loads(profile.read_text(encoding="utf-8"))
        data["profile"]["cookie_behavior"] = 3
        profile.write_text(json.dumps(data), encoding="utf-8")
        state = preferences.read_language_state()
        self.assertFalse(state["cookie_enabled"])

    def test_profile_name_validation(self):
        preferences = region_core.EdgePreferences(
            self.root, lambda: False)
        local_state = Path(self.root) / "Local State"
        local_state.write_text(
            json.dumps({"profile": {"last_used": "../../evil"}}),
            encoding="utf-8")
        with self.assertRaises(RuntimeError):
            preferences.read()


class ActiveProfileTests(unittest.TestCase):

    def test_last_used_is_restored_last(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "Local State").write_text(json.dumps({
                "profile": {
                    "last_active_profiles": ["Default", "Profile 1"],
                    "last_used": "Default",
                }}), encoding="utf-8")
            for name in ("Default", "Profile 1"):
                directory = Path(root) / name
                directory.mkdir()
                (directory / "Preferences").write_text("{}", encoding="utf-8")
            from edge_lifecycle import read_active_profiles
            self.assertEqual(
                read_active_profiles(root), ["Profile 1", "Default"])

    def test_unknown_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "Local State").write_text(json.dumps({
                "profile": {"last_used": "../../evil"}}), encoding="utf-8")
            from edge_lifecycle import read_active_profiles
            with self.assertRaises(RuntimeError):
                read_active_profiles(root)


class PolicyTests(unittest.TestCase):

    def test_policy_comparison(self):
        first = region_core.PolicyValue(True, "en-US,en", 1)
        self.assertTrue(region_core._same_policy(first, first))
        self.assertFalse(region_core._same_policy(
            first, region_core.PolicyValue(True, "zh-CN,zh", 1)))
        self.assertFalse(region_core._same_policy(
            first, region_core.PolicyValue(True, "en-US,en", 2)))
        self.assertFalse(region_core._same_policy(
            first, region_core.PolicyValue(False)))

    def test_profiles(self):
        self.assertEqual(region_core.RegionProfile.for_mode("usa").languages,
                         "en-US,en")
        self.assertEqual(region_core.RegionProfile.for_mode("china").languages,
                         "zh-CN,zh")
        with self.assertRaises(ValueError):
            region_core.RegionProfile.for_mode("other")


if __name__ == "__main__":
    unittest.main()
