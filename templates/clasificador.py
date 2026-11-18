#!/usr/bin/env python3
"""
Security event classifier.

Classifies log lines using a rule table (regex -> category -> severity -> MITRE
ATT&CK technique) and writes the relevant ones to an alerts file.

Exit codes: 0 = nothing at or above --fail-on, 1 = alerts found, 2 = error.
"""
import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

log = logging.getLogger("classifier")

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]  # ascending order

# (category, regex, severity, MITRE technique). First match wins, so keep the
# most severe and most specific rules at the top. Event names use \b...\b so
# "DeleteBucket" does not also match "DeleteBucketPolicy".
RULES = [
    ("defense_evasion", r"\b(?:StopLogging|DeleteTrail|UpdateTrail|DeleteFlowLogs)\b", "CRITICAL", "T1562.008"),
    ("data_destruction", r"\b(?:DeleteBucket|DeleteDBInstance|TerminateInstances)\b", "CRITICAL", "T1485"),
    ("data_exposure", r"\b(?:DeleteBucketPublicAccessBlock|DeleteBucketPolicy|PutBucketAcl|PutBucketPolicy)\b", "HIGH", None),
    ("persistence_access_key", r"\bCreateAccessKey\b", "HIGH", "T1098.001"),
    ("privilege_escalation", r"\b(?:AttachUserPolicy|PutUserPolicy|AttachRolePolicy)\b", "HIGH", "T1098.003"),
    ("critical_level", r"\bCRITICAL\b", "HIGH", None),
    ("failed_authentication", r"failed password|invalid user|authentication failure", "MEDIUM", "T1110"),
    ("root_session", r"session opened for user root", "MEDIUM", None),
    ("access_denied", r"access\s?denied|unauthorized|forbidden|\"\s+(?:401|403)\b|status=(?:401|403)\b",
     "MEDIUM", None),
    ("application_error", r"\bERROR\b", "LOW", None),
]
COMPILED_RULES = [(cat, re.compile(rx, re.IGNORECASE), sev, mitre) for cat, rx, sev, mitre in RULES]

DEMO_LOG = """2026-06-01 10:00:00 eventName=StopLogging user=intruder
2026-06-01 10:00:01 eventName=DeleteBucketPolicy user=dev
2026-06-01 10:00:02 eventName=DeleteBucketPublicAccessBlock user=dev
2026-06-01 10:00:03 eventName=CreateAccessKey user=jafet
2026-06-01 10:00:04 sshd: Failed password for ana from 203.0.113.7
2026-06-01 10:00:05 sudo: session opened for user root by jafet
2026-06-01 10:00:06 "GET /admin HTTP/1.1" 403 512
2026-06-01 10:00:07 "GET /img/401.png HTTP/1.1" 200 403
2026-06-01 10:00:08 app ERROR timeout talking to db
2026-06-01 10:00:09 all good
"""


# --- Classification ----------------------------------------------------------
def classify_line(line):
    """Return (category, severity, mitre) for the first matching rule, or None."""
    for category, regex, severity, mitre in COMPILED_RULES:
        if regex.search(line):
            return category, severity, mitre
    return None


def classify_lines(lines, min_severity, alerts_file=None, normal_file=None):
    """Classify every line. Returns (by_category, by_severity, normal_count, total)."""
    by_category, by_severity = Counter(), Counter()
    normal_count = total = 0
    threshold = SEVERITIES.index(min_severity)

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        total += 1
        result = classify_line(line)
        if result is None:
            normal_count += 1
            if normal_file:
                normal_file.write(line + "\n")
            continue
        category, severity, mitre = result
        by_category[category] += 1
        by_severity[severity] += 1
        if alerts_file and SEVERITIES.index(severity) >= threshold:
            tag = f"[{severity}] [{category}]" + (f" [{mitre}]" if mitre else "")
            # Keep the original line (and its original timestamp) intact
            alerts_file.write(f"{tag} {line}\n")
    return by_category, by_severity, normal_count, total


# --- Output ------------------------------------------------------------------
def print_summary(by_category, by_severity, normal_count, total, fail_on):
    log.info("Total events: %d | classified: %d | unclassified: %d",
             total, total - normal_count, normal_count)
    for sev in reversed(SEVERITIES):
        if by_severity[sev]:
            level = log.warning if SEVERITIES.index(sev) >= SEVERITIES.index(fail_on) else log.info
            level("%-8s %d", sev, by_severity[sev])
    for category, n in by_category.most_common():
        log.info("  %-24s %d", category, n)


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Security event classifier")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file to analyze")
    p.add_argument("--demo", action="store_true",
                   help="Run on a built-in sample log (ignores --log)")
    p.add_argument("--output-dir", default="reportes",
                   help="Directory for output files (default: reportes)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="MEDIUM",
                   help="Lowest severity written to the alerts file (default MEDIUM)")
    p.add_argument("--fail-on", choices=SEVERITIES, default="HIGH",
                   help="Exit with code 1 if any event reaches this severity (default HIGH)")
    p.add_argument("--save-normal", action="store_true",
                   help="Also save unclassified lines to a file")
    p.add_argument("--json-output", help="Write the summary to a JSON file (SIEM-friendly)")
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

    out_dir = Path(args.output_dir)
    alerts_path = out_dir / "alerts.log"
    normal_path = out_dir / "normal_events.log"

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        # "w" (not "a") so running twice doesn't duplicate events. Even an empty
        # log overwrites the file, so old alerts never look like new ones.
        with open(alerts_path, "w", encoding="utf-8") as alerts_file:
            if args.save_normal:
                with open(normal_path, "w", encoding="utf-8") as normal_file:
                    result = classify_lines(lines, args.min_severity, alerts_file, normal_file)
            else:
                result = classify_lines(lines, args.min_severity, alerts_file)

        by_category, by_severity, normal_count, total = result
        if total == 0:
            log.warning("No events to classify (empty log)")
            return EXIT_OK

        print_summary(by_category, by_severity, normal_count, total, args.fail_on)
        log.info("Alerts written to %s", alerts_path)

        if args.json_output:
            Path(args.json_output).write_text(json.dumps({
                "total": total, "unclassified": normal_count,
                "by_severity": dict(by_severity), "by_category": dict(by_category),
            }, indent=2), encoding="utf-8")
            log.info("Summary saved to %s", args.json_output)
    except OSError as e:
        log.error("Could not write output: %s", e)
        return EXIT_ERROR

    fail_idx = SEVERITIES.index(args.fail_on)
    return EXIT_ALERTS if any(by_severity[s] for s in SEVERITIES[fail_idx:]) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())