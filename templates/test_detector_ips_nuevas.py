"""Tests for the new-IP login detector. Run with:  python3 -m unittest -v"""
import tempfile
import unittest
from pathlib import Path

import detector_acceso_ips_nuevas as d


class TestParseLogin(unittest.TestCase):
    def test_app_line_any_order(self):
        self.assertEqual(d.parse_login("2026-11-17 08:00:00 LOGIN OK ip=10.0.0.4 user=Ana", 2026),
                         ("ana", "10.0.0.4", "2026-11-17 08:00:00"))

    def test_sshd_line(self):
        # Old bug: real SSH logins were ignored
        line = "Nov 17 10:00:30 web01 sshd[99]: Accepted password for admin from 198.51.100.9 port 22"
        self.assertEqual(d.parse_login(line, 2026), ("admin", "198.51.100.9", "2026-11-17 10:00:30"))

    def test_failed_and_unrelated_lines(self):
        self.assertIsNone(d.parse_login("Failed password for admin from 1.2.3.4", 2026))
        self.assertIsNone(d.parse_login("TOKEN refreshed user=ana ip=1.2.3.4", 2026))

    def test_invalid_ip(self):
        self.assertIsNone(d.parse_login("LOGIN OK user=ana ip=999.1.1.1", 2026))


class TestFindNewLogins(unittest.TestCase):
    def test_demo(self):
        alerts = d.find_new_logins(d.DEMO_LOG.splitlines(), d.DEMO_BASELINE, {"admin"}, 2026)
        found = {(a["pair"], a["severity"]) for a in alerts}
        # Admin vs admin is the same user (old bug: counted as two)
        # and the repeated sshd login is reported once
        self.assertEqual(found, {("ana,192.168.1.35", "MEDIUM"), ("admin,198.51.100.9", "HIGH")})


class TestMain(unittest.TestCase):
    def test_missing_file_is_error(self):
        self.assertEqual(d.main(["--log", "does/not/exist.log"]), d.EXIT_ERROR)

    def test_demo_finds_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(d.main(["--demo", "--output-dir", tmp]), d.EXIT_ALERTS)

    def test_learn_then_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "a.log"
            log_file.write_text("2026-11-17 08:00:00 LOGIN OK user=ana ip=192.168.1.20\n")
            args = ["--log", str(log_file), "--baseline", str(Path(tmp) / "known.txt"),
                    "--output-dir", tmp]
            self.assertEqual(d.main(args + ["--learn"]), d.EXIT_ALERTS)  # first run: new
            self.assertEqual(d.main(args), d.EXIT_OK)                     # now known


if __name__ == "__main__":
    unittest.main()
