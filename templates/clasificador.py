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

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]  # ascending order

# (category, regex, severity, MITRE technique). First match wins, so keep the
# most severe rules at the top.
RULES = [
    ("defense_evasion", r"StopLogging|DeleteTrail|UpdateTrail|DeleteFlowLogs", "CRITICAL", "T1562.008"),
    ("data_destruction", r"DeleteBucket|DeleteDBInstance|TerminateInstances", "CRITICAL", "T1485"),
    ("privilege_escalation", r"AttachUserPolicy|PutUserPolicy|CreateAccessKey|session opened for user root", "HIGH", "T1098"),
    ("failed_authentication", r"failed password|invalid user|authentication failure", "HIGH", "T1110"),
    ("critical_level", r"\bCRITICAL\b", "HIGH", None),
    ("access_denied", r"access\s?denied|unauthorized|forbidden|\b(?:401|403)\b", "MEDIUM", None),
    ("application_error", r"\bERROR\b", "LOW", None),
]
COMPILED_RULES = [(cat, re.compile(rx, re.IGNORECASE), sev, mitre) for cat, rx, sev, mitre in RULES]


def classify_line(line):
    """Return (category, severity, mitre) for the first matching rule, or None."""
    for category, regex, severity, mitre in COMPILED_RULES:
        if regex.search(line):
            return category, severity, mitre
    return None


def classify_file(path, min_severity, alerts_file=None, normal_file=None):
    """Classify every line. Returns (by_category, by_severity, normal_count, total)."""
    by_category, by_severity = Counter(), Counter()
    normal_count = total = 0
    threshold = SEVERITIES.index(min_severity)

    with open(path, "r", encoding="utf-8", errors="ignore") as src:
        for raw in src:
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


def main():
    p = argparse.ArgumentParser(description="Security event classifier")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file to analyze")
    p.add_argument("--output-dir", default="reportes", help="Directory for output files (default: reportes)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="MEDIUM",
                   help="Lowest severity written to the alerts file (default MEDIUM)")
    p.add_argument("--fail-on", choices=SEVERITIES, default="HIGH",
                   help="Exit with code 1 if any event reaches this severity (default HIGH)")
    p.add_argument("--save-normal", action="store_true", help="Also save unclassified lines to a file")
    p.add_argument("--json-output", help="Write the summary to a JSON file (SIEM-friendly)")
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

    out_dir = Path(args.output_dir)
    alerts_path = out_dir / "alerts.log"
    normal_path = out_dir / "normal_events.log"

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        # "w" (not "a") so running twice doesn't duplicate events
        with open(alerts_path, "w", encoding="utf-8") as alerts_file:
            if args.save_normal:
                with open(normal_path, "w", encoding="utf-8") as normal_file:
                    result = classify_file(src, args.min_severity, alerts_file, normal_file)
            else:
                result = classify_file(src, args.min_severity, alerts_file)
    except PermissionError as e:
        log.error("Permission denied: %s", e)
        return 2

    by_category, by_severity, normal_count, total = result

    log.info("Total events: %d | classified: %d | unclassified: %d",
             total, total - normal_count, normal_count)
    for sev in reversed(SEVERITIES):
        if by_severity[sev]:
            nivel = log.warning if SEVERITIES.index(sev) >= SEVERITIES.index(args.fail_on) else log.info
            nivel("%-8s %d", sev, by_severity[sev])
    for category, n in by_category.most_common():
        log.info("  %-22s %d", category, n)
    log.info("Alerts written to %s", alerts_path)

    if args.json_output:
        Path(args.json_output).write_text(json.dumps({
            "total": total, "unclassified": normal_count,
            "by_severity": dict(by_severity), "by_category": dict(by_category),
        }, indent=2), encoding="utf-8")
        log.info("Summary saved to %s", args.json_output)

    fail_idx = SEVERITIES.index(args.fail_on)
    return 1 if any(by_severity[s] for s in SEVERITIES[fail_idx:]) else 0


if __name__ == "__main__":
    sys.exit(main())
    
