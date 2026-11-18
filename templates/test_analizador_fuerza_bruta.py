"""Tests for the brute-force analyzer. Run with:  python3 -m unittest -v"""
import unittest
from datetime import datetime

import analizador_fuerza_bruta as b


class TestParsing(unittest.TestCase):
    def test_attacker_ip_not_server_ip(self):
        # Old bug: picked the first IP (the server), not the attacker
        line = "host=10.0.0.5 sshd: Failed password for root from 203.0.113.7"
        self.assertEqual(str(b.source_ip(line)), "203.0.113.7")

    def test_first_valid_ip_fallback(self):
        self.assertEqual(str(b.source_ip("blocked 999.1.1.1 then 8.8.8.8")), "8.8.8.8")

    def test_users(self):
        self.assertEqual(b.target_user("Failed password for invalid user Bob from 1.2.3.4"), "bob")
        self.assertEqual(b.target_user("Failed password for root from 1.2.3.4"), "root")
        self.assertEqual(b.target_user("contraseña INCORRECTA usuario=Carlos ip=1.2.3.4"), "carlos")

    def test_spanish_app_failure(self):
        ev = b.parse_line("2026-11-17 10:00:00 login contraseña INCORRECTA usuario=ana ip=1.2.3.4",
                          True, 2026)
        self.assertEqual((ev["kind"], ev["user"], str(ev["ip"])), ("fail", "ana", "1.2.3.4"))

    def test_syslog_timestamp(self):
        # Old bug: /var/log/auth.log format was ignored, so it never alerted
        ts = b.parse_timestamp("Nov 17 10:00:05 web01 sshd: Failed password", 2026)
        self.assertEqual(ts, datetime(2026, 11, 17, 10, 0, 5))

    def test_numbers_alone_are_not_failures(self):
        self.assertIsNone(b.parse_line('"GET /img/401.png HTTP/1.1" 200 403', True, 2026))

    def test_success_line(self):
        ev = b.parse_line("Accepted password for ana from 192.168.1.20", True, 2026)
        self.assertEqual((ev["kind"], ev["user"]), ("ok", "ana"))


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.events = b.read_events(b.DEMO_LOG.splitlines(), True, 2026)

    def test_by_ip(self):
        sev = {r["ip"]: r["severity"] for r in b.analyze_by(self.events, "ip", 10, 5)}
        self.assertEqual(sev["198.51.100.9"], "CRITICAL")   # burst, then logged in
        self.assertEqual(sev["192.0.2.66"], "HIGH")         # password spraying
        self.assertEqual(sev["203.0.113.10"], "OK")         # each distributed IP looks quiet
        self.assertEqual(sev["192.168.1.20"], "OK")         # typos

    def test_by_user_catches_distributed_attack(self):
        results = {r["user"]: r for r in b.analyze_by(self.events, "user", 10, 5)}
        self.assertEqual(results["admin"]["severity"], "CRITICAL")
        self.assertEqual(results["carlos"]["severity"], "HIGH")
        self.assertEqual(results["carlos"]["distinct_ips"], 12)
        self.assertEqual(results["ana"]["severity"], "OK")

    def test_spraying_counts_many_users(self):
        spray = next(r for r in b.analyze_by(self.events, "ip", 10, 5) if r["ip"] == "192.0.2.66")
        self.assertEqual(spray["distinct_users"], 12)


class TestMain(unittest.TestCase):
    def test_missing_file_is_error(self):
        self.assertEqual(b.main(["--log", "does/not/exist.log"]), b.EXIT_ERROR)

    def test_demo_finds_alerts(self):
        self.assertEqual(b.main(["--demo"]), b.EXIT_ALERTS)


if __name__ == "__main__":
    unittest.main()
