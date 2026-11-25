#!/usr/bin/env python3
"""
Daily security summary.

Reads a log and gives a one-screen overview: how many events of each type,
which time range the log covers, and the most active IPs and users. It does
not raise alerts by itself; it's the "how did today look" report you read
before running the detectors.

Understands the same formats as the rest of the kit:
  app     2026-11-17 10:00:00 LOGIN OK user=ana ip=192.168.1.20
  sshd    Nov 17 10:00:00 web01 sshd[99]: Failed password for ana from 192.168.1.20

Exit codes: 0 = summary written, 2 = error.
"""
import argparse
import logging
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from common import (EXIT_ERROR, EXIT_OK, IPV4, SSHD_ACCEPTED, SSHD_PAM_DUPLICATE_REGEX,
                    add_year_argument, parse_timestamp, read_log_lines, setup_logging,
                    valid_ip, write_json)

log = logging.getLogger("summary")

# Event types, checked in order (first match wins). Whole words only, so
# "TOKEN" or "BROKEN" are not counted as "OK", and "ERRORS" is not "ERROR".
EVENT_TYPES = [
    ("failed_login", re.compile(
        r"failed password|invalid user|authentication failure|\bincorrect[ao]?\b|access\s?denied",
        re.IGNORECASE)),
    ("successful_login", re.compile(
        rf"{SSHD_ACCEPTED}|login (?:ok|success)|successful login", re.IGNORECASE)),
    ("alert", re.compile(r"\bALERT\b|\bCRITICAL\b", re.IGNORECASE)),
    ("download", re.compile(r"\bDOWNLOAD\b|\bGetObject\b", re.IGNORECASE)),
    ("error", re.compile(r"\bERROR\b", re.IGNORECASE)),
]

IP_REGEX = re.compile(rf"\b(?:from|ip[=:]|rhost=|src=)\s*({IPV4})\b", re.IGNORECASE)
USER_REGEX = re.compile(
    r"\bfor (?:invalid user )?([\w.@-]+) from\b|\b(?:usuario|user)[=:]\s*([\w.@-]+)", re.IGNORECASE)

DEMO_LOG = """2026-11-17 08:00:00 LOGIN OK user=ana ip=192.168.1.20
2026-11-17 08:01:00 TOKEN refreshed user=ana ip=192.168.1.20
2026-11-17 08:30:00 LOGIN OK usuario=carlos ip=192.168.1.35
Nov 17 09:00:01 web01 sshd[99]: Failed password for root from 203.0.113.7 port 22
Nov 17 09:00:02 web01 sshd[99]: Failed password for root from 203.0.113.7 port 22
Nov 17 09:00:03 web01 sshd[99]: Failed password for invalid user test from 203.0.113.7 port 22
2026-11-17 10:15:00 ALERT disk usage 91% on /var
2026-11-17 11:00:00 app ERROR timeout talking to db
2026-11-17 12:00:00 job BROKEN pipe, retrying
"""


# --- Parsing -----------------------------------------------------------------
def event_type(line):
    if SSHD_PAM_DUPLICATE_REGEX.search(line):
        return "other"      # PAM copy of an sshd failure: the sshd line is the one counted
    for name, regex in EVENT_TYPES:
        if regex.search(line):
            return name
    return "other"


def find_ip(line):
    if (m := IP_REGEX.search(line)) and (ip := valid_ip(m.group(1))):
        return str(ip)
    return None


def find_user(line):
    if m := USER_REGEX.search(line):
        return (m.group(1) or m.group(2)).lower()
    return None


# --- Summary -----------------------------------------------------------------
def summarize(lines, year=None, top=5):
    by_type, ips, users = Counter(), Counter(), Counter()
    failed_by_ip = Counter()
    first = last = None
    total = 0
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        total += 1
        kind = event_type(line)
        by_type[kind] += 1
        ip, user = find_ip(line), find_user(line)
        if ip:
            ips[ip] += 1
            if kind == "failed_login":
                failed_by_ip[ip] += 1
        if user:
            users[user] += 1
        if ts := parse_timestamp(line, year):
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
    return {
        "total_events": total,
        "by_type": {name: by_type[name] for name, _ in EVENT_TYPES} | {"other": by_type["other"]},
        "first_event": first.isoformat(sep=" ") if first else None,
        "last_event": last.isoformat(sep=" ") if last else None,
        "unique_ips": len(ips), "unique_users": len(users),
        "top_ips": ips.most_common(top),
        "top_users": users.most_common(top),
        "top_failed_ips": failed_by_ip.most_common(top),
    }


# --- Output ------------------------------------------------------------------
def pct(n, total):
    return n / total * 100 if total else 0


def format_report(s):
    total = s["total_events"]
    out = [
        "=" * 60,
        f"DAILY SECURITY SUMMARY  (generated {datetime.now():%Y-%m-%d %H:%M:%S})",
        "=" * 60,
        f"Log covers:        {s['first_event'] or '?'}  ->  {s['last_event'] or '?'}",
        f"Total events:      {total}",
        "",
        "By type:",
    ]
    for name, n in s["by_type"].items():
        out.append(f"  {name:<18}{n:>5}  ({pct(n, total):5.1f}%)")
    out += ["", f"Unique IPs: {s['unique_ips']}   Unique users: {s['unique_users']}", ""]
    for title, key in (("Most active IPs", "top_ips"), ("Most active users", "top_users"),
                       ("IPs with most failed logins", "top_failed_ips")):
        if s[key]:
            out.append(f"{title}:")
            out += [f"  {name:<20}{n:>5}" for name, n in s[key]]
            out.append("")
    out.append("=" * 60)
    return "\n".join(out)


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Daily security summary")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file to analyze")
    p.add_argument("--demo", action="store_true", help="Run on a built-in sample log (ignores --log)")
    p.add_argument("--top", type=int, default=5, help="How many IPs/users to list (default 5)")
    add_year_argument(p)
    p.add_argument("--output-dir", default="reportes", help="Directory for the report (default: reportes)")
    p.add_argument("--json-output", help="Write the summary to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    if args.demo:
        log.info("Demo mode: using built-in sample log")
        lines = DEMO_LOG.splitlines()
    elif (lines := read_log_lines(args.log, log)) is None:
        return EXIT_ERROR

    summary = summarize(lines, args.year, args.top)
    if summary["total_events"] == 0:
        log.warning("The log has no events.")
        return EXIT_OK

    report = format_report(summary)
    print(report)

    try:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        # "a" on purpose: the file keeps one summary per day as a history
        with open(out_dir / "daily_summary.log", "a", encoding="utf-8") as f:
            f.write(report + "\n\n")
        log.info("Summary appended to %s", out_dir / "daily_summary.log")
        if args.json_output:
            write_json(args.json_output, summary)
            log.info("Summary saved to %s", args.json_output)
    except OSError as e:
        log.error("Could not write output: %s", e)
        return EXIT_ERROR

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())