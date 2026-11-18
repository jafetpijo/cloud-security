"""Tests for the event classifier. Run with:  python3 -m unittest -v"""
import tempfile
import unittest
from pathlib import Path

import clasificador as c


class TestClassifyLine(unittest.TestCase):
    def cat(self, line):
        result = c.classify_line(line)
        return result[0] if result else None

    def test_rules(self):
        cases = {
            "eventName=StopLogging": "defense_evasion",
            "eventName=DeleteBucket bucket=x": "data_destruction",
            "eventName=CreateAccessKey": "persistence_access_key",
            "eventName=AttachUserPolicy": "privilege_escalation",
            "sshd: Failed password for ana": "failed_authentication",
            "sudo: session opened for user root": "root_session",
            '"GET /admin HTTP/1.1" 403 512': "access_denied",
            "app ERROR timeout": "application_error",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(self.cat(line), expected)

    def test_similar_names_do_not_collide(self):
        # Old bug: these matched "DeleteBucket" and were called data destruction
        self.assertEqual(self.cat("eventName=DeleteBucketPolicy"), "data_exposure")
        self.assertEqual(self.cat("eventName=DeleteBucketPublicAccessBlock"), "data_exposure")

    def test_numbers_alone_are_not_access_denied(self):
        # Old bug: a file name or size of 401/403 was flagged
        self.assertIsNone(self.cat('"GET /img/401.png HTTP/1.1" 200 403'))

    def test_normal_line(self):
        self.assertIsNone(c.classify_line("all good"))


class TestMain(unittest.TestCase):
    def test_missing_file_is_error(self):
        self.assertEqual(c.main(["--log", "does/not/exist.log"]), c.EXIT_ERROR)

    def test_demo_finds_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(c.main(["--demo", "--output-dir", tmp]), c.EXIT_ALERTS)

    def test_empty_log_clears_old_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "alerts.log").write_text("[CRITICAL] old alert\n")
            empty = Path(tmp) / "empty.log"
            empty.write_text("")
            self.assertEqual(c.main(["--log", str(empty), "--output-dir", tmp]), c.EXIT_OK)
            self.assertEqual((Path(tmp) / "alerts.log").read_text(), "")


if __name__ == "__main__":
    unittest.main()
