"""Tests for the daily summary. Run with:  python3 -m unittest -v"""
import tempfile
import unittest

import resumen_diario as r


class TestEventType(unittest.TestCase):
    def test_types(self):
        cases = {
            "LOGIN OK user=ana": "successful_login",
            "Accepted password for ana from 1.2.3.4": "successful_login",
            "Failed password for root from 1.2.3.4": "failed_login",
            "contraseña INCORRECTA usuario=ana": "failed_login",
            "ALERT disk full": "alert",
            "DOWNLOAD usuario=juan tamaño=5 ip=10.0.0.99": "download",
            "app ERROR timeout": "error",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(r.event_type(line), expected)

    def test_words_inside_other_words_are_not_matched(self):
        # Old bug: TOKEN and BROKEN were counted as successful logins ("OK")
        self.assertEqual(r.event_type("TOKEN refreshed"), "other")
        self.assertEqual(r.event_type("job BROKEN pipe"), "other")
        self.assertEqual(r.event_type("3 ERRORS ignored"), "other")


class TestExtraction(unittest.TestCase):
    def test_ip_and_user_formats(self):
        # Old bug: only "IP:" and "Usuario:" were understood
        self.assertEqual(r.find_ip("LOGIN OK user=ana ip=10.0.0.4"), "10.0.0.4")
        self.assertEqual(r.find_ip("Failed password for root from 203.0.113.7"), "203.0.113.7")
        self.assertEqual(r.find_ip("IP: 10.0.0.9 Usuario: luis"), "10.0.0.9")
        self.assertEqual(r.find_user("LOGIN OK user=Ana"), "ana")
        self.assertEqual(r.find_user("Failed password for invalid user test from 1.2.3.4"), "test")
        self.assertEqual(r.find_user("IP: 10.0.0.9 Usuario: luis"), "luis")


class TestSummary(unittest.TestCase):
    def test_demo(self):
        s = r.summarize(r.DEMO_LOG.splitlines(), 2026)
        self.assertEqual(s["total_events"], 9)
        self.assertEqual(s["by_type"]["successful_login"], 2)
        self.assertEqual(s["by_type"]["failed_login"], 3)
        self.assertEqual(s["top_failed_ips"][0], ("203.0.113.7", 3))
        self.assertEqual(s["first_event"], "2026-11-17 08:00:00")
        self.assertEqual(s["last_event"], "2026-11-17 12:00:00")


class TestMain(unittest.TestCase):
    def test_missing_file_is_error(self):
        self.assertEqual(r.main(["--log", "does/not/exist.log"]), r.EXIT_ERROR)

    def test_demo_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(r.main(["--demo", "--output-dir", tmp]), r.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
