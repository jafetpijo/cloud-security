"""Tests for the exfiltration detector. Run with:  python3 -m unittest -v"""
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import detector_exfiltracion as x


class TestParseLine(unittest.TestCase):
    def test_web_line(self):
        ip, ts, size = x.parse_line(
            '203.0.113.7 - - [17/Nov/2026:10:00:00 -0600] "GET /a.zip HTTP/1.1" 200 1048576')
        self.assertEqual((str(ip), ts, size), ("203.0.113.7", datetime(2026, 11, 17, 10, 0), 1048576))

    def test_app_line(self):
        ip, ts, size = x.parse_line("2026-11-17 11:00:00 download ip=192.168.1.50 bytes=500")
        self.assertEqual((str(ip), size), ("192.168.1.50", 500))

    def test_spanish_size_field(self):
        ip, ts, size = x.parse_line(
            "2026-11-01 10:00:00 DOWNLOAD usuario=juan tamaño=52428800 ip=10.0.0.99")
        self.assertEqual((str(ip), size), ("10.0.0.99", 52428800))

    def test_ignored_lines(self):
        self.assertIsNone(x.parse_line(  # not modified, no bytes
            '1.2.3.4 - - [17/Nov/2026:10:00:00 -0600] "GET / HTTP/1.1" 304 -'))
        self.assertIsNone(x.parse_line(  # failed request
            '1.2.3.4 - - [17/Nov/2026:10:00:00 -0600] "GET / HTTP/1.1" 404 512'))
        self.assertIsNone(x.parse_line("download ip=999.1.1.1 bytes=5"))


class TestWindow(unittest.TestCase):
    def test_sliding_sum(self):
        t0 = datetime(2026, 11, 17, 10, 0)
        transfers = [(t0, 10), (t0 + timedelta(minutes=5), 20), (t0 + timedelta(minutes=90), 25)]
        peak, _, _ = x.max_bytes_in_window(transfers, timedelta(minutes=60))
        self.assertEqual(peak, 30)

    def test_untimed_bytes_still_count(self):
        peak, _, _ = x.max_bytes_in_window([(None, 50)], timedelta(minutes=60))
        self.assertEqual(peak, 50)


class TestAnalyze(unittest.TestCase):
    def test_demo_severities(self):
        authorized = set(x.DEMO_AUTHORIZED.split(","))
        results = x.analyze(x.read_transfers(x.DEMO_LOG.splitlines()), authorized, 20, 100, 60)
        sev = {r["ip"]: r["severity"] for r in results}
        self.assertEqual(sev, {"203.0.113.7": "HIGH", "192.168.1.50": "MEDIUM",
                               "198.51.100.20": "OK", "192.168.1.100": "OK"})


class TestAuthorized(unittest.TestCase):
    LINES = ["2026-11-17 10:00:00 download ip=10.1.2.3 bytes=52428800",
             "2026-11-17 10:00:00 download ip=203.0.113.7 bytes=52428800"]

    def test_networks_can_be_authorized(self):
        results = x.analyze(x.read_transfers(self.LINES), ["10.1.2.0/24"], 20, 100, 60)
        auth = {r["ip"]: r["authorized"] for r in results}
        self.assertEqual(auth, {"10.1.2.3": True, "203.0.113.7": False})

    def test_invalid_entry_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "access.log"
            log_file.write_text("\n".join(self.LINES) + "\n")
            self.assertEqual(x.main(["--log", str(log_file), "--authorized-ips", "10.0.0.999"]),
                             x.EXIT_ERROR)


class TestMain(unittest.TestCase):
    def test_missing_file_is_error(self):
        self.assertEqual(x.main(["--log", "does/not/exist.log"]), x.EXIT_ERROR)

    def test_demo_finds_alerts(self):
        self.assertEqual(x.main(["--demo"]), x.EXIT_ALERTS)


if __name__ == "__main__":
    unittest.main()
