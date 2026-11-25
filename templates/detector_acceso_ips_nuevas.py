#!/usr/bin/env python3
"""
New-IP login detector.

Learns which IPs each user normally logs in from (the baseline) and alerts when
a user logs in successfully from an IP never seen before for that user. A stolen
password often shows up exactly like this: a valid login from an unusual place.

Understands two log styles:
  app     2026-11-17 10:00:00 LOGIN OK user=ana ip=192.168.1.20
  sshd    Nov 17 10:00:00 web01 sshd[99]: Accepted password for ana from 192.168.1.20

MITRE ATT&CK: T1078 (Valid Accounts)

Workflow:
  1. First run on a normal log with --learn to build the baseline.
  2. Later runs alert on new user/IP pairs. Review them before using --learn
     again: learning during an attack would mark the attacker's IP as "known".

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

from common import (EXIT_ALERTS, EXIT_ERROR, EXIT_OK, KV_USER_REGEX, SSHD_ACCEPTED,
                    add_year_argument, parse_privileged, parse_timestamp, read_log_lines,
                    setup_logging, valid_ip, write_json)

log = logging.getLogger("new_ips")

# Match "LOGIN OK" / "SUCCESS", not just "OK" (avoids TOKEN, BROKEN)
APP_SUCCESS_REGEX = re.compile(r"LOGIN OK|LOGIN SUCCESS|SUCCESSFUL LOGIN", re.IGNORECASE)
# Two separate patterns, so the order of user/ip in the line does not matter
APP_USER_REGEX = KV_USER_REGEX
APP_IP_REGEX = re.compile(r"\bip=([0-9.]+)", re.IGNORECASE)
# Any sshd method: password, publickey, keyboard-interactive/pam (2FA), gssapi...
SSHD_REGEX = re.compile(rf"{SSHD_ACCEPTED} ([\w.@-]+) from ([0-9.]+)", re.IGNORECASE)

DEMO_BASELINE = {"ana,192.168.1.20", "admin,10.0.0.4"}
DEMO_LOG = """2026-11-17 08:00:00 LOGIN OK user=ana ip=192.168.1.20
2026-11-17 08:05:00 LOGIN OK user=Admin ip=10.0.0.4
2026-11-17 09:00:00 LOGIN OK user=ana ip=192.168.1.35
Nov 17 10:00:30 web01 sshd[99]: Accepted password for admin from 198.51.100.9 port 22
Nov 17 10:02:00 web01 sshd[99]: Accepted password for admin from 198.51.100.9 port 22
"""


# --- Baseline ----------------------------------------------------------------
def load_baseline(path):
    """Return the set of known 'user,ip' pairs (empty if the file doesn't exist)."""
    path = Path(path)
    if not path.is_file():
        return set()
    return {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()}


def save_baseline(path, pairs):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for pair in sorted(pairs):
            f.write(pair + "\n")


# --- Parsing -----------------------------------------------------------------
def timestamp_text(line, year=None):
    ts = parse_timestamp(line, year)
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None


def parse_login(line, year=None):
    """Return (user, ip, timestamp) for a successful login line, otherwise None."""
    if m := SSHD_REGEX.search(line):
        user, ip = m.group(1), m.group(2)
    elif APP_SUCCESS_REGEX.search(line):
        m_user, m_ip = APP_USER_REGEX.search(line), APP_IP_REGEX.search(line)
        if not (m_user and m_ip):
            return None
        user, ip = m_user.group(1), m_ip.group(1)
    else:
        return None
    if (ip := valid_ip(ip)) is None:          # rejects values like 999.1.1.1
        return None
    return user.lower(), str(ip), timestamp_text(line, year)


# --- Analysis ----------------------------------------------------------------
def find_new_logins(lines, baseline, privileged, year=None):
    """Return the first login of each user/IP pair not in the baseline."""
    seen = set(baseline)
    alerts = []
    for line in lines:
        login = parse_login(line, year)
        if login is None:
            continue
        user, ip, ts = login
        pair = f"{user},{ip}"
        if pair in seen:
            continue
        seen.add(pair)     # report each new pair once per run
        alerts.append({
            "user": user, "ip": ip, "time": ts, "pair": pair,
            "privileged": user in privileged,
            "severity": "HIGH" if user in privileged else "MEDIUM",
            "line": line.strip(),
        })
    return alerts


# --- Output ------------------------------------------------------------------
def print_summary(alerts):
    for a in sorted(alerts, key=lambda a: a["severity"] != "HIGH"):
        log.warning("%-6s new IP for %s%s: %s (first seen %s)", a["severity"], a["user"],
                    " [privileged]" if a["privileged"] else "", a["ip"], a["time"] or "no timestamp")


def write_report(out_dir, alerts):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / "new_ip_logins.log"
    run_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # "a" on purpose: this report is a history of detections across runs
    with open(report, "a", encoding="utf-8") as f:
        f.write(f"\n[run {run_ts}] new user/IP pairs: {len(alerts)}\n")
        for a in alerts:
            # Use the time from the log, not the time the script ran
            f.write(f"[{a['time'] or 'no timestamp'}] [{a['severity']}] user={a['user']} ip={a['ip']}\n")
    log.info("Report written to %s", report)


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="New-IP login detector")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file to analyze")
    p.add_argument("--demo", action="store_true",
                   help="Run on a built-in sample log and baseline (ignores --log and --baseline)")
    p.add_argument("--baseline", default="reportes/known_ips.txt",
                   help="File with known 'user,ip' pairs (default: reportes/known_ips.txt)")
    p.add_argument("--learn", action="store_true",
                   help="Add the new pairs to the baseline after reporting them")
    p.add_argument("--privileged-users", default="root,admin",
                   help="Comma-separated privileged accounts (default: root,admin)")
    add_year_argument(p)
    p.add_argument("--output-dir", default="reportes", help="Directory for the report (default: reportes)")
    p.add_argument("--json-output", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    if args.demo:
        log.info("Demo mode: using built-in sample log and baseline")
        lines, baseline = DEMO_LOG.splitlines(), set(DEMO_BASELINE)
    else:
        if (lines := read_log_lines(args.log, log)) is None:
            return EXIT_ERROR
        try:
            baseline = load_baseline(args.baseline)
        except OSError as e:
            log.error("Could not read the baseline: %s", e)
            return EXIT_ERROR
        if not baseline:
            log.warning("Baseline is empty: every login will look new. "
                        "Run once on a normal log with --learn to build it.")

    privileged = parse_privileged(args.privileged_users)
    alerts = find_new_logins(lines, baseline, privileged, args.year)

    if not alerts:
        log.info("No logins from new IPs.")
        return EXIT_OK

    print_summary(alerts)
    try:
        write_report(args.output_dir, alerts)
        if args.json_output:
            write_json(args.json_output, {"alerts": alerts})
            log.info("Results saved to %s", args.json_output)
        if args.learn and not args.demo:
            save_baseline(args.baseline, {a["pair"] for a in alerts})
            log.info("Baseline updated with %d new user/IP pairs", len(alerts))
        elif not args.demo:
            log.info("Review these IPs, then use --learn to mark them as known")
    except OSError as e:
        log.error("Could not write output: %s", e)
        return EXIT_ERROR

    return EXIT_ALERTS


if __name__ == "__main__":
    sys.exit(main())