import sys
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import startup

SID = "S-1-5-21-100-200-300-1001"


class TaskXmlTests(unittest.TestCase):

    def build(self):
        return startup.build_task_xml(
            SID, executable=r"C:\Tools\ClaudeGuard.exe",
            arguments='"C:\\Tools\\ClaudeGuard.exe" --tray-startup',
            working_directory=r"C:\Tools")

    def test_task_name_contains_sid(self):
        self.assertEqual(startup.task_name(SID),
                         "ClaudeGuard-" + SID)

    def test_xml_is_well_formed_and_namespaced(self):
        root = ElementTree.fromstring(self.build())
        self.assertEqual(root.tag, "{" + startup.NAMESPACE + "}Task")
        self.assertEqual(
            root.find("t:RegistrationInfo/t:Source",
                      {"t": startup.NAMESPACE}).text, startup.SOURCE)

    def test_exec_action_roundtrip(self):
        root = ElementTree.fromstring(self.build())
        self.assertTrue(startup._matches(
            root, r"C:\Tools\ClaudeGuard.exe",
            '"C:\\Tools\\ClaudeGuard.exe" --tray-startup', SID))

    def test_matches_rejects_other_executable(self):
        root = ElementTree.fromstring(self.build())
        self.assertFalse(startup._matches(
            root, r"C:\Other\ClaudeGuard.exe",
            '"C:\\Tools\\ClaudeGuard.exe" --tray-startup', SID))

    def test_matches_rejects_other_user(self):
        root = ElementTree.fromstring(self.build())
        self.assertFalse(startup._matches(
            root, r"C:\Tools\ClaudeGuard.exe",
            '"C:\\Tools\\ClaudeGuard.exe" --tray-startup', SID + "0"))

    def test_matches_requires_all_elements(self):
        root = ElementTree.fromstring(
            '<Task xmlns="' + startup.NAMESPACE + '"></Task>')
        self.assertFalse(startup._matches(
            root, r"C:\Tools\ClaudeGuard.exe", "--tray-startup", SID))

    def test_validate_existing_accepts_own_task(self):
        root = startup._validate_existing(self.build(), "name")
        self.assertIsNotNone(root)

    def test_validate_existing_rejects_foreign_task(self):
        foreign = ('<Task xmlns="' + startup.NAMESPACE + '">'
                   "<RegistrationInfo><Source>Other</Source>"
                   "</RegistrationInfo></Task>")
        with self.assertRaises(RuntimeError):
            startup._validate_existing(foreign, "name")

    def test_validate_existing_rejects_malformed(self):
        with self.assertRaises(RuntimeError):
            startup._validate_existing("<Task", "name")

    def test_escaped_characters_survive_roundtrip(self):
        xml = startup.build_task_xml(
            SID, executable=r"C:\A & B\tool.exe",
            arguments='"C:\\A & B\\tool.exe" --tray-startup',
            working_directory=r"C:\A & B")
        root = ElementTree.fromstring(xml)
        command = root.find("t:Actions/t:Exec/t:Command",
                            {"t": startup.NAMESPACE})
        self.assertEqual(command.text, r"C:\A & B\tool.exe")
        self.assertTrue(startup._matches(
            root, r"C:\A & B\tool.exe",
            '"C:\\A & B\\tool.exe" --tray-startup', SID))


if __name__ == "__main__":
    unittest.main()
