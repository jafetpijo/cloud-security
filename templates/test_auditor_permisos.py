"""Tests for the permission auditor. Run with:  python3 -m unittest -v"""
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import auditor_permisos as a


class TestRiskyMode(unittest.TestCase):
    def test_risky(self):
        for mode, reason in [("777", "world-writable"), ("666", "world-writable"),
                             ("4755", "setuid/setgid bit"), ("2755", "setuid/setgid bit"),
                             ("o+w", "world-writable"), ("a+rwx", "world-writable"),
                             ("+s", "setuid/setgid bit"), ("u+s", "setuid/setgid bit")]:
            with self.subTest(mode=mode):
                self.assertEqual(a.is_risky_mode(mode), reason)

    def test_safe(self):
        for mode in ["644", "0644", "750", "g-w", "u=rwx,go=rx", "+t"]:
            with self.subTest(mode=mode):
                self.assertIsNone(a.is_risky_mode(mode))


class TestParseLine(unittest.TestCase):
    def test_new_cloud_events_are_risky(self):
        for event in ["CreateAccessKey", "PutUserPolicy"]:
            ev = a.parse_line(f"2026-06-01 10:00:00 user=x action={event}")
            self.assertEqual(ev["detail"], event)
            self.assertTrue(ev["risk"])

    def test_public_access_block_is_counted_not_flagged(self):
        ev = a.parse_line("user=x action=PutBucketPublicAccessBlock")
        self.assertEqual(ev["kind"], "cloud_permission")
        self.assertIsNone(ev["risk"])

    def test_deleting_public_access_block_is_risky(self):
        self.assertTrue(a.parse_line("user=x action=DeleteBucketPublicAccessBlock")["risk"])

    def test_irrelevant_line(self):
        self.assertIsNone(a.parse_line("user=x action=login_ok"))


class TestWindow(unittest.TestCase):
    def test_sliding_window(self):
        t0 = datetime(2026, 6, 1, 10, 0)
        times = [t0, t0 + timedelta(minutes=2), t0 + timedelta(minutes=4), t0 + timedelta(minutes=30)]
        n, _, _ = a.max_in_window(times, timedelta(minutes=10))
        self.assertEqual(n, 3)


class TestMain(unittest.TestCase):
    def test_missing_file_is_error(self):
        self.assertEqual(a.main(["--log", "does/not/exist.log"]), a.EXIT_ERROR)

    def test_demo_finds_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(a.main(["--demo", "--output-dir", tmp]), a.EXIT_ALERTS)

    def test_clean_log_returns_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "clean.log"
            log_file.write_text("2026-06-01 10:00:00 user=ana action=chmod 644 /a\n")
            self.assertEqual(a.main(["--log", str(log_file), "--output-dir", tmp]), a.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
