#!/usr/bin/env python3
"""
Permission change auditor.

Detects permission changes in logs (chmod, chown and cloud IAM/S3 events),
flags dangerous ones (world-writable, setuid/setgid, public buckets, new access
keys) and alerts on bursts of changes by one user within a sliding time window.

MITRE ATT&CK: T1222 / T1222.002 (File and Directory Permissions Modification),
              T1548.001 (Setuid and Setgid), T1098 (Account Manipulation),
              T1098.001 (Additional Cloud Credentials)

            

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger("permissions")

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2
SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "OK": 0}

USER_REGEX = re.compile(r"\b(?:usuario|user)=([\w.@-]+)", re.IGNORECASE)
TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
# Skips options before the mode: short (-R, -v) and long (--recursive, --verbose)
CHMOD_REGEX = re.compile(r"\bchmod\s+(?:--?[\w-]+\s+)*(\S+)", re.IGNORECASE)
CHOWN_REGEX = re.compile(r"\b(?:chown|chgrp|setfacl)\b", re.IGNORECASE)
SYMBOLIC_PART = re.compile(r"^([ugoa]*)([+=-])([rwxXst]*)$")

# Cloud events that open access or create persistence: always risky
CLOUD_RISKY_REGEX = re.compile(
    r"\b(PutBucketAcl|PutObjectAcl|PutBucketPolicy|AttachRolePolicy|AttachUserPolicy|"
    r"PutRolePolicy|PutUserPolicy|DeleteBucketPublicAccessBlock|CreateAccessKey)\b"
)
# Cloud events that change permissions but are often protective: counted, not flagged
CLOUD_REVIEW_REGEX = re.compile(r"\b(PutBucketPublicAccessBlock)\b")

DEMO_LOG = """2026-06-01 10:15:22 user=admin action=chmod 777 /var/www/html
2026-06-01 10:16:05 user=root action=chown www-data:www-data /app
2026-06-01 10:18:40 user=jafet action=CreateAccessKey target=IAMUser
2026-06-01 10:20:12 user=developer action=PutBucketAcl bucket=company-backup
2026-06-01 10:21:00 user=developer action=chmod +s /usr/bin/find
2026-06-01 10:22:00 user=ana action=chmod 644 /srv/a.txt
2026-06-01 10:23:00 user=ana action=chmod 644 /srv/b.txt
2026-06-01 10:24:00 user=ana action=chmod 640 /srv/c.txt
2026-06-01 10:25:00 user=ana action=chown ana /srv/d.txt
"""


# --- Parsing -----------------------------------------------------------------
def is_risky_mode(mode):
    """Return a reason string if a chmod mode is dangerous, otherwise None."""
    if re.fullmatch(r"[0-7]{1,4}", mode):
        # chmod pads short modes with leading zeros: "2" means 0002 (world-writable)
        bits = int(mode, 8)
        if bits & 0o6000:
            return "setuid/setgid bit"
        if bits & 0o002:
            return "world-writable"
        return None
    for part in mode.split(","):
        m = SYMBOLIC_PART.match(part)
        if not m or m.group(2) == "-":
            continue
        who, _, perms = m.groups()
        # With no u/g/o/a, chmod acts like "a" but skips bits set in the umask.
        # The usual umask (022) blocks group/other write, so "+w" only affects the
        # owner; setuid/setgid are never in the umask, so "+s" still sets them.
        if "s" in perms and (not who or "u" in who or "g" in who or "a" in who):
            return "setuid/setgid bit"
        if "w" in perms and ("o" in who or "a" in who):
            return "world-writable"
    return None


def parse_line(line):
    """Return an event dict if the line is a permission change, otherwise None."""
    kind = risk = detail = None
    if m := CLOUD_RISKY_REGEX.search(line):
        kind, detail, risk = "cloud_permission", m.group(1), "cloud access/persistence change"
    elif m := CLOUD_REVIEW_REGEX.search(line):
        kind, detail = "cloud_permission", m.group(1)
    elif m := CHMOD_REGEX.search(line):
        kind, detail, risk = "chmod", m.group(1), is_risky_mode(m.group(1))
    elif CHOWN_REGEX.search(line):
        kind = "ownership_acl"
    if kind is None:
        return None
    u = USER_REGEX.search(line)
    t = TS_REGEX.search(line)
    return {
        "user": u.group(1).lower() if u else "unknown",
        "time": datetime.strptime(f"{t.group(1)} {t.group(2)}", "%Y-%m-%d %H:%M:%S") if t else None,
        "kind": kind, "detail": detail, "risk": risk, "line": line.strip(),
    }


def read_events(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if ev := parse_line(line):
                events.append(ev)
    return events


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


def analyze(events, threshold, window_min, privileged):
    window = timedelta(minutes=window_min)
    by_user = defaultdict(list)
    for ev in events:
        by_user[ev["user"]].append(ev)

    results = []
    for user, evs in by_user.items():
        n_window, start, end = max_in_window([e["time"] for e in evs], window)
        risky = [e for e in evs if e["risk"]]
        is_priv = user in privileged
        if risky and is_priv:
            severity = "CRITICAL"   # privileged account making a risky change
        elif risky:
            severity = "HIGH"
        elif n_window > threshold:
            severity = "MEDIUM"     # burst of otherwise normal changes
        else:
            severity = "OK"
        results.append({
            "user": user, "privileged": is_priv, "severity": severity,
            "total_changes": len(evs), "risky_changes": len(risky),
            "max_in_window": n_window, "burst": n_window > threshold,
            "window_start": start.isoformat() if start else None,
            "window_end": end.isoformat() if end else None,
            "risky_events": [f"{e['kind']} {e['detail']} ({e['risk']})" for e in risky],
        })
    return sorted(results, key=lambda r: (SEVERITY_ORDER[r["severity"]], r["total_changes"]),
                  reverse=True)


# --- Output ------------------------------------------------------------------
def print_summary(results, window_min):
    for r in results:
        level = log.warning if r["severity"] != "OK" else log.info
        level("%-8s %s%s: %d changes (%d risky), max %d in %d min",
              r["severity"], r["user"], " [privileged]" if r["privileged"] else "",
              r["total_changes"], r["risky_changes"], r["max_in_window"], window_min)
        for desc in r["risky_events"]:
            log.warning("           risky: %s", desc)


def write_report(out_dir, events):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / "permission_audit.log"
    # "w" (not "a") so running twice doesn't duplicate events
    with open(report, "w", encoding="utf-8") as f:
        for ev in events:
            flag = f"[RISKY: {ev['risk']}] " if ev["risk"] else ""
            f.write(f"{flag}{ev['line']}\n")
    log.info("Report written to %s", report)


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Permission change auditor")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file")
    p.add_argument("--demo", action="store_true",
                   help="Run on a built-in sample log (ignores --log)")
    p.add_argument("--threshold", type=int, default=3,
                   help="Changes allowed within the window (default 3)")
    p.add_argument("--window", type=int, default=10, help="Window size in minutes (default 10)")
    p.add_argument("--privileged-users", default="root,admin",
                   help="Comma-separated privileged accounts (default: root,admin)")
    p.add_argument("--output-dir", default="reportes",
                   help="Directory for the report (default: reportes)")
    p.add_argument("--json-output", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.demo:
        log.info("Demo mode: using built-in sample log")
        events = [ev for ev in map(parse_line, DEMO_LOG.splitlines()) if ev]
    else:
        src = Path(args.log)
        if not src.is_file():
            log.error("Log file not found: %s", src)   # never invent data
            return EXIT_ERROR
        if src.stat().st_size == 0:
            log.warning("Empty file: %s", src)
            return EXIT_OK
        try:
            events = read_events(src)
        except OSError as e:
            log.error("Could not read %s: %s", src, e)
            return EXIT_ERROR

    if not events:
        log.info("No permission changes detected.")
        return EXIT_OK

    privileged = {u.strip().lower() for u in args.privileged_users.split(",") if u.strip()}
    results = analyze(events, args.threshold, args.window, privileged)
    log.info("Permission changes: %d | users: %d", len(events), len(results))
    print_summary(results, args.window)

    try:
        write_report(args.output_dir, events)
        if args.json_output:
            Path(args.json_output).write_text(json.dumps({
                "threshold": args.threshold, "window_min": args.window,
                "results": results}, indent=2), encoding="utf-8")
            log.info("Results saved to %s", args.json_output)
    except OSError as e:
        log.error("Could not write output: %s", e)
        return EXIT_ERROR

    return EXIT_ALERTS if any(r["severity"] != "OK" for r in results) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())