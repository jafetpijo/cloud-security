#!/usr/bin/env python3
"""
Permission change auditor.

Detects permission changes in logs (chmod, chown and cloud IAM/S3 events),
flags dangerous ones (world-writable, setuid/setgid, public buckets) and
alerts on bursts of changes by one user within a sliding time window.

MITRE ATT&CK: T1222 / T1222.002 (File and Directory Permissions Modification),
              T1548.001 (Setuid and Setgid), T1098 (Account Manipulation)

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

USER_REGEX = re.compile(r"\b(?:usuario|user)=([\w.@-]+)", re.IGNORECASE)
TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
CHMOD_REGEX = re.compile(r"\bchmod\s+(?:-\w+\s+)*(\S+)", re.IGNORECASE)
CHOWN_REGEX = re.compile(r"\b(?:chown|chgrp|setfacl)\b", re.IGNORECASE)
# Cloud events that change who can access a resource (always treated as risky)
CLOUD_REGEX = re.compile(
    r"\b(PutBucketAcl|PutObjectAcl|PutBucketPolicy|AttachRolePolicy|AttachUserPolicy|"
    r"PutRolePolicy|DeleteBucketPublicAccessBlock|PutBucketPublicAccessBlock)\b"
)
SYMBOLIC_PART = re.compile(r"^([ugoa]*)([+=-])([rwxXst]*)$")


def is_risky_mode(mode):
    """Return a reason string if a chmod mode is dangerous, otherwise None."""
    if re.fullmatch(r"[0-7]{3,4}", mode):
        special = int(mode[0]) if len(mode) == 4 else 0
        other = int(mode[-1])
        if special & 0b110:
            return "setuid/setgid bit"
        if other & 0b010:
            return "world-writable"
        return None
    for part in mode.split(","):
        m = SYMBOLIC_PART.match(part)
        if not m or m.group(2) == "-":
            continue
        who, _, perms = m.groups()
        who = who or "a"
        if "s" in perms and ("u" in who or "g" in who or "a" in who):
            return "setuid/setgid bit"
        if "w" in perms and ("o" in who or "a" in who):
            return "world-writable"
    return None


def parse_line(line):
    """Return an event dict if the line is a permission change, otherwise None."""
    kind = risk = detail = None
    m = CLOUD_REGEX.search(line)
    if m:
        kind, detail, risk = "cloud_permission", m.group(1), "cloud access change"
    else:
        m = CHMOD_REGEX.search(line)
        if m:
            kind, detail, risk = "chmod", m.group(1), is_risky_mode(m.group(1))
        elif CHOWN_REGEX.search(line):
            kind, detail = "ownership_acl", None
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
            ev = parse_line(line)
            if ev:
                events.append(ev)
    return events


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
            "max_in_window": n_window,
            "burst": n_window > threshold,
            "window_start": start.isoformat() if start else None,
            "window_end": end.isoformat() if end else None,
            "risky_events": [f"{e['kind']} {e['detail']} ({e['risk']})" for e in risky],
        })
    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "OK": 0}
    return sorted(results, key=lambda r: (order[r["severity"]], r["total_changes"]), reverse=True)


def main():
    p = argparse.ArgumentParser(description="Permission change auditor")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file")
    p.add_argument("--threshold", type=int, default=3, help="Changes allowed within the window (default 3)")
    p.add_argument("--window", type=int, default=10, help="Window size in minutes (default 10)")
    p.add_argument("--privileged-users", default="root,admin",
                   help="Comma-separated privileged accounts (default: root,admin)")
    p.add_argument("--output-dir", default="reportes", help="Directory for the report (default: reportes)")
    p.add_argument("--json-output", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    src = Path(args.log)
    if not src.is_file():
        log.error("'%s' not found", src)
        return 2
    if src.stat().st_size == 0:
        log.warning("Empty file: '%s'", src)
        return 0

    try:
        events = read_events(src)
    except PermissionError:
        log.error("Permission denied reading '%s'", src)
        return 2
    if not events:
        log.info("No permission changes detected.")
        return 0

    privileged = {u.strip().lower() for u in args.privileged_users.split(",") if u.strip()}
    results = analyze(events, args.threshold, args.window, privileged)
    alerts = [r for r in results if r["severity"] != "OK"]

    log.info("Permission changes: %d | users: %d", len(events), len(results))
    for r in results:
        nivel = log.warning if r["severity"] != "OK" else log.info
        nivel("%-8s %s%s: %d changes (%d risky), max %d in %d min",
              r["severity"], r["user"], " [privileged]" if r["privileged"] else "",
              r["total_changes"], r["risky_changes"], r["max_in_window"], args.window)
        for desc in r["risky_events"]:
            log.warning("           risky: %s", desc)

    try:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        report = out_dir / "permission_audit.log"
        # "w" (not "a") so running twice doesn't duplicate events
        with open(report, "w", encoding="utf-8") as f:
            for ev in events:
                flag = f"[RISKY: {ev['risk']}] " if ev["risk"] else ""
                f.write(f"{flag}{ev['line']}\n")
        log.info("Report written to %s", report)
        if args.json_output:
            Path(args.json_output).write_text(json.dumps({
                "threshold": args.threshold, "window_min": args.window,
                "results": results}, indent=2), encoding="utf-8")
            log.info("Results saved to %s", args.json_output)
    except (PermissionError, OSError) as e:
        log.error("Could not write output: %s", e)
        return 2

    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
