#!/usr/bin/env python3
"""
Failed-login analyzer (brute force detection by IP and by user).

Counts authentication failures within a sliding time window, grouped two ways:
  by IP    one IP failing many times      -> classic brute force or scanning
           (and failing on many users     -> password spraying)
  by user  one account failing many times -> targeted attack, even when it
           comes from many IPs (distributed brute force) that look quiet one by one
If, after the burst, the same IP or user logs in successfully, the alert becomes
CRITICAL: the attack may have worked.

Understands two timestamp formats:
  ISO     2026-11-17 10:00:00   (or 2026-11-17T10:00:00)
  syslog  Nov 17 10:00:00       (the default in /var/log/auth.log; no year, see --year)

MITRE ATT&CK: T1110 (Brute Force), T1110.003 (Password Spraying),
              T1078 (Valid Accounts) when it succeeds

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import ipaddress
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger("bruteforce")

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
IP_REGEX = re.compile(rf"\b{IPV4}\b")
# Where the attacker's IP usually is: "from 1.2.3.4", "rhost=1.2.3.4", "src=1.2.3.4", "ip=1.2.3.4"
SOURCE_IP_REGEX = re.compile(rf"\b(?:from|rhost=|src=|ip=|client=?)\s*({IPV4})\b", re.IGNORECASE)
# Target account: sshd style first, then key=value style (usuario= or user=)
SSHD_USER_REGEX = re.compile(r"\bfor (?:invalid user )?([\w.@-]+) from\b", re.IGNORECASE)
KV_USER_REGEX = re.compile(r"\b(?:usuario|user)=([\w.@-]+)", re.IGNORECASE)
ISO_TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
SYSLOG_TS_REGEX = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})")

# Failed access attempts (not application failures). Includes the Spanish
# "contraseña incorrecta" style used by the app logs.
# Only authentication wording: a bare "denied" or "forbidden" also matches
# AppArmor, firewall or web server rules that have nothing to do with logins.
AUTH_FAIL_REGEX = re.compile(
    r"failed (?:password|keyboard-interactive/pam) for|invalid user|authentication failure|"
    r"access\s?denied|\bincorrect[ao]?\b|\bunauthorized\b|"
    r"\"\s+(?:401|403)\b|status=(?:401|403)\b",
    re.IGNORECASE,
)
# sshd logs every failed password twice in auth.log: once from PAM
# ("pam_unix(sshd:auth): authentication failure") and once from sshd itself
# ("Failed password for ..."), plus a "PAM N more authentication failures"
# summary when the connection closes. Counting all of them would inflate the
# number of attempts, so these PAM copies are skipped.
SSHD_PAM_DUPLICATE_REGEX = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure|\bPAM \d+ more authentication failures?",
    re.IGNORECASE,
)
# Any sshd method: password, publickey, keyboard-interactive/pam (2FA), gssapi...
AUTH_OK_REGEX = re.compile(r"accepted [\w/-]+ for|login (?:ok|success)", re.IGNORECASE)
ERROR_REGEX = re.compile(r"\bERROR\b", re.IGNORECASE)

DEMO_LOG = "\n".join(
    # 1) One IP, 15 fast failures, then gets in -> CRITICAL (by IP and by user)
    [f"Nov 17 10:00:{i:02d} web01 sshd[99]: Failed password for admin from 198.51.100.9 port 22"
     for i in range(15)]
    + ["Nov 17 10:00:30 web01 sshd[99]: Accepted password for admin from 198.51.100.9 port 22"]
    # 2) Distributed: 12 different IPs, 1 failure each, all against "carlos" -> HIGH by user only
    + [f"2026-11-17 10:10:{i:02d} login contraseña INCORRECTA usuario=carlos ip=203.0.113.{i + 10}"
       for i in range(12)]
    # 3) Password spraying: one IP tries 12 different users once each -> HIGH by IP
    + [f"Nov 17 10:20:{i:02d} web01 sshd[99]: Failed password for invalid user user{i} from 192.0.2.66"
       for i in range(12)]
    # 4) Normal user: 2 typos, then logs in -> OK
    + ["2026-11-17 11:00:00 sshd: Failed password for ana from 192.168.1.20",
       "2026-11-17 11:00:10 sshd: Failed password for ana from 192.168.1.20",
       "2026-11-17 11:00:20 sshd: Accepted password for ana from 192.168.1.20"]
)

# Example ranges reserved for documentation (used in DEMO_LOG); Python counts them as private
DOC_NETWORKS = [ipaddress.ip_network(n) for n in
                ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


# --- Parsing -----------------------------------------------------------------
def source_ip(line):
    """Return the attacker's IP: prefer 'from/rhost/src/ip=', else the first valid IP."""
    m = SOURCE_IP_REGEX.search(line)
    candidates = [m.group(1)] if m else IP_REGEX.findall(line)
    for candidate in candidates:
        try:
            return ipaddress.ip_address(candidate)
        except ValueError:      # rejects values like 999.999.999.999
            continue
    return None


def target_user(line):
    m = SSHD_USER_REGEX.search(line) or KV_USER_REGEX.search(line)
    return m.group(1).lower() if m else None


def parse_timestamp(line, year):
    if m := ISO_TS_REGEX.search(line):
        return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    if m := SYSLOG_TS_REGEX.search(line):
        return datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}",
                                 "%Y %b %d %H:%M:%S")
    return None


def parse_line(line, auth_only, year):
    """Return {'kind': 'fail'|'ok', 'ip', 'user', 'time'} if relevant, otherwise None."""
    if SSHD_PAM_DUPLICATE_REGEX.search(line):
        return None
    if AUTH_OK_REGEX.search(line):
        kind = "ok"
    elif (AUTH_FAIL_REGEX if auth_only else ERROR_REGEX).search(line):
        kind = "fail"
    else:
        return None
    return {"kind": kind, "ip": source_ip(line), "user": target_user(line),
            "time": parse_timestamp(line, year)}


def read_events(lines, auth_only, year):
    return [ev for ev in (parse_line(line, auth_only, year) for line in lines) if ev]


# --- Analysis ----------------------------------------------------------------
def max_in_window(times, window):
    """Maximum number of events in any interval of length `window` (sliding window)."""
    times = sorted(t for t in times if t is not None)
    best, left = (0, None, None), 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        n = right - left + 1
        if n > best[0]:
            best = (n, times[left], t)
    return best


def ip_type(ip):
    if ip.is_global:
        return "public"
    if any(ip in net for net in DOC_NETWORKS):
        return "documentation"
    return "private" if ip.is_private else "reserved"


def analyze_by(events, field, threshold, window_min):
    """Group failures by 'ip' or 'user' and assign a severity to each group."""
    other = "user" if field == "ip" else "ip"
    window = timedelta(minutes=window_min)
    failures, successes = defaultdict(list), defaultdict(list)
    for ev in events:
        key = ev[field]
        if key is None:
            continue
        (failures if ev["kind"] == "fail" else successes)[key].append(ev)

    results = []
    for key, evs in failures.items():
        n_window, start, end = max_in_window([e["time"] for e in evs], window)
        burst = n_window > threshold
        later_success = burst and any(
            e["time"] and start and e["time"] >= start for e in successes.get(key, []))
        severity = "CRITICAL" if later_success else "HIGH" if burst else "OK"
        distinct = {str(e[other]) for e in evs if e[other] is not None}
        results.append({
            field: str(key),
            "type": ip_type(key) if field == "ip" else None,
            "severity": severity,
            "total_failures": len(evs), "max_in_window": n_window,
            f"distinct_{other}s": len(distinct),
            "window_start": start.isoformat() if start else None,
            "window_end": end.isoformat() if end else None,
            "success_after_burst": later_success,
        })
    order = {"CRITICAL": 2, "HIGH": 1, "OK": 0}
    return sorted(results, key=lambda r: (order[r["severity"]], r["max_in_window"],
                                          r["total_failures"]), reverse=True)


# --- Output ------------------------------------------------------------------
def print_section(title, results, field, window_min, top):
    other = "user" if field == "ip" else "ip"
    log.info("--- %s ---", title)
    for r in results[:top]:
        level = log.warning if r["severity"] != "OK" else log.info
        name = f"{r['ip']} ({r['type']})" if field == "ip" else r["user"]
        level("%-8s %s: %d failures in %d min, %d in total, %d different %ss%s",
              r["severity"], name, r["max_in_window"], window_min, r["total_failures"],
              r[f"distinct_{other}s"], other,
              " -> LOGGED IN AFTERWARDS" if r["success_after_burst"] else "")


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Failed-login analyzer (by IP and by user)")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file to analyze")
    p.add_argument("--demo", action="store_true", help="Run on a built-in sample log (ignores --log)")
    p.add_argument("--by", choices=["ip", "user", "both"], default="both",
                   help="Group failures by IP, by user, or both (default both)")
    p.add_argument("--threshold", type=int, default=10,
                   help="Failures allowed within the window (default 10)")
    p.add_argument("--window", type=int, default=5, help="Window size in minutes (default 5)")
    p.add_argument("--all-errors", action="store_true",
                   help="Count any ERROR line, not just authentication failures")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="Year for syslog timestamps, which don't include one (default: current)")
    p.add_argument("--top", type=int, default=10, help="Show only the top N per section (default 10)")
    p.add_argument("--json-output", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.demo:
        log.info("Demo mode: using built-in sample log")
        lines = DEMO_LOG.splitlines()
    else:
        src = Path(args.log)
        if not src.is_file():
            log.error("Log file not found: %s", src)   # never invent data
            return EXIT_ERROR
        try:
            lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as e:
            log.error("Could not read %s: %s", src, e)
            return EXIT_ERROR

    events = read_events(lines, not args.all_errors, args.year)
    fails = [e for e in events if e["kind"] == "fail"]
    if not fails:
        log.info("No relevant failures found.")
        return EXIT_OK

    no_time = sum(1 for e in fails if e["time"] is None)
    log.info("Failures: %d | without IP: %d | without user: %d | without timestamp: %d",
             len(fails), sum(1 for e in fails if e["ip"] is None),
             sum(1 for e in fails if e["user"] is None), no_time)
    if no_time:
        log.warning("%d failures have no timestamp and can't count toward the window", no_time)

    output = {"threshold": args.threshold, "window_min": args.window}
    for field, title in (("ip", "By IP"), ("user", "By user")):
        if args.by in (field, "both"):
            results = analyze_by(events, field, args.threshold, args.window)
            print_section(title, results, field, args.window, args.top)
            output[f"by_{field}"] = results

    if args.json_output:
        try:
            Path(args.json_output).write_text(json.dumps(output, indent=2), encoding="utf-8")
            log.info("Results saved to %s", args.json_output)
        except OSError as e:
            log.error("Could not write output: %s", e)
            return EXIT_ERROR

    alert = any(r["severity"] != "OK"
                for key in ("by_ip", "by_user") for r in output.get(key, []))
    return EXIT_ALERTS if alert else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())