"""Tests for the shared helpers. Run with:  python3 -m unittest -v"""
import unittest
from datetime import datetime, timedelta

import common


class TestTimestamps(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(common.parse_timestamp("2026-11-17T10:00:05 x"), datetime(2026, 11, 17, 10, 0, 5))

    def test_syslog_explicit_year(self):
        self.assertEqual(common.parse_timestamp("Nov 17 10:00:05 h sshd: x", 2025),
                         datetime(2025, 11, 17, 10, 0, 5))

    def test_syslog_current_year(self):
        now = datetime(2026, 11, 25, 12, 0)
        self.assertEqual(common.parse_timestamp("Nov 17 10:00:05 h x", now=now),
                         datetime(2026, 11, 17, 10, 0, 5))

    def test_december_log_read_in_january(self):
        # Old bug: with the current year, December dates landed in the future
        now = datetime(2027, 1, 2, 9, 0)
        self.assertEqual(common.parse_timestamp("Dec 31 23:59:00 h x", now=now),
                         datetime(2026, 12, 31, 23, 59))
        self.assertEqual(common.parse_timestamp("Jan  1 00:01:00 h x", now=now),
                         datetime(2027, 1, 1, 0, 1))

    def test_burst_across_new_year_stays_in_one_window(self):
        now = datetime(2027, 1, 1, 0, 10)
        times = [common.parse_timestamp(line, now=now)
                 for line in ("Dec 31 23:58:00 h x", "Dec 31 23:59:30 h x", "Jan  1 00:01:00 h x")]
        self.assertEqual(common.max_in_window(times, timedelta(minutes=5))[0], 3)

    def test_feb_29_in_non_leap_year_does_not_crash(self):
        self.assertIsNone(common.parse_timestamp("Feb 29 10:00:00 h x", 2026))

    def test_no_timestamp(self):
        self.assertIsNone(common.parse_timestamp("no date here"))


class TestHelpers(unittest.TestCase):
    def test_valid_ip(self):
        self.assertEqual(str(common.valid_ip("8.8.8.8")), "8.8.8.8")
        self.assertIsNone(common.valid_ip("999.1.1.1"))

    def test_find_user(self):
        self.assertEqual(common.find_user("Failed password for invalid user Bob from 1.2.3.4"), "bob")
        self.assertEqual(common.find_user("LOGIN OK usuario=Ana ip=1.2.3.4"), "ana")
        self.assertIsNone(common.find_user("nothing"))

    def test_parse_privileged(self):
        self.assertEqual(common.parse_privileged(" root, Admin ,,"), {"root", "admin"})


if __name__ == "__main__":
    unittest.main()
