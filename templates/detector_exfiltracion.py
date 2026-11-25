#!/usr/bin/env python3
"""
Data exfiltration detector (download volume per IP).

Reads access logs, adds up how many bytes each IP downloaded within a sliding
time window, and alerts when an IP goes over its limit. Two limits, as in the
original version: a low one for unknown IPs and a higher one for authorized IPs.

Understands two log styles:
  web     203.0.113.7 - - [17/Nov/2026:10:00:00 -0600] "GET /backup.zip HTTP/1.1" 200 5242880
  app     2026-11-17 10:00:00 download ip=203.0.113.7 bytes=5242880 file=backup.zip
          (also size= or tamaño=, e.g. "DOWNLOAD usuario=juan tamaño=52428800 ip=10.0.0.99")

MITRE ATT&CK: TA0010 (Exfiltration), T1530 (Data from Cloud Storage) for S3-style logs

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import ipaddress
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

from common import (EXIT_ALERTS, EXIT_ERROR, EXIT_OK, ISO_TS_REGEX, read_log_lines,
                    setup_logging, valid_ip, write_json)

log = logging.getLogger("exfiltration")

MB = 1024 * 1024

WEB_REGEX = re.compile(
    r'^(\S+) \S+ \S+ \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})[^\]]*\] "[^"]*" (\d{3}) (\d+|-)')
APP_IP_REGEX = re.compile(r"\bip=([0-9.]+)", re.IGNORECASE)
# bytes=, size=, or the Spanish tamaño= / tamano= used by the app logs
APP_BYTES_REGEX = re.compile(r"\b(?:bytes|size|tama[ñn]o)=(\d+)", re.IGNORECASE)

DEMO_AUTHORIZED = "192.168.1.50,192.168.1.100"
DEMO_LOG = "\n".join(
    # Unknown IP pulls 6 x 5 MB = 30 MB in 5 minutes -> HIGH (limit 20)
    [f'203.0.113.7 - - [17/Nov/2026:10:0{i}:00 -0600] "GET /backup_{i}.zip HTTP/1.1" 200 5242880'
     for i in range(6)]
    # Authorized backup server pulls 25 x 5 MB = 125 MB -> MEDIUM (limit 100)
    + [f"2026-11-17 11:{i:02d}:00 download ip=192.168.1.50 bytes=5242880 file=db_{i}.sql"
       for i in range(25)]
    # Normal users
    + ['198.51.100.20 - - [17/Nov/2026:12:00:00 -0600] "GET /index.html HTTP/1.1" 200 20480',
       '198.51.100.20 - - [17/Nov/2026:12:00:05 -0600] "GET /logo.png HTTP/1.1" 304 -',
       "2026-11-17 12:30:00 download ip=192.168.1.100 bytes=10485760 file=report.pdf"]
)


# --- Parsing -----------------------------------------------------------------
def parse_line(line):
    """Return (ip, timestamp|None, bytes) for a download line, otherwise None."""
    if m := WEB_REGEX.search(line):
        ip, ts_text, status, size = m.groups()
        if size == "-" or not status.startswith("2"):   # only successful transfers
            return None
        ts = datetime.strptime(ts_text, "%d/%b/%Y:%H:%M:%S")
        size = int(size)
    else:
        m_ip, m_bytes = APP_IP_REGEX.search(line), APP_BYTES_REGEX.search(line)
        if not (m_ip and m_bytes):
            return None
        ip, size = m_ip.group(1), int(m_bytes.group(1))
        m_ts = ISO_TS_REGEX.search(line)
        ts = datetime.strptime(f"{m_ts.group(1)} {m_ts.group(2)}", "%Y-%m-%d %H:%M:%S") if m_ts else None
    if (ip := valid_ip(ip)) is None:       # rejects values like 999.1.1.1
        return None
    return ip, ts, size


def read_transfers(lines):
    by_ip = defaultdict(list)
    for line in lines:
        if parsed := parse_line(line):
            ip, ts, size = parsed
            by_ip[ip].append((ts, size))
    return by_ip


# --- Analysis ----------------------------------------------------------------
def max_bytes_in_window(transfers, window):
    """Largest number of bytes downloaded in any interval of length `window`.
    Transfers without a timestamp can't be placed in time, so they count toward
    every window (worst case) rather than being silently ignored."""
    untimed = sum(size for ts, size in transfers if ts is None)
    timed = sorted((ts, size) for ts, size in transfers if ts is not None)
    best, current, left = (0, None, None), 0, 0
    for right, (t, size) in enumerate(timed):
        current += size
        while t - timed[left][0] > window:
            current -= timed[left][1]
            left += 1
        if current > best[0]:
            best = (current, timed[left][0], t)
    return best[0] + untimed, best[1], best[2]


def parse_authorized(entries):
    """IPs or networks ('10.0.0.5', '10.0.0.0/24') -> list of ip_network.
    Comparing addresses, not text, lets a whole subnet be authorized at once.
    Raises ValueError for an invalid entry, so a typo never silently authorizes nothing."""
    return [ipaddress.ip_network(e.strip(), strict=False) for e in entries if e.strip()]


def analyze(by_ip, authorized, limit_unauth_mb, limit_auth_mb, window_min):
    window = timedelta(minutes=window_min)
    networks = parse_authorized(authorized)
    results = []
    for ip, transfers in by_ip.items():
        peak, start, end = max_bytes_in_window(transfers, window)
        is_auth = any(ip.version == net.version and ip in net for net in networks)
        limit_mb = limit_auth_mb if is_auth else limit_unauth_mb
        over = peak > limit_mb * MB
        if over and not is_auth:
            severity = "HIGH"      # was "ALERTA ROJA"
        elif over:
            severity = "MEDIUM"    # was "ALERTA AMARILLA"
        else:
            severity = "OK"
        results.append({
            "ip": str(ip), "authorized": is_auth, "severity": severity,
            "peak_mb": round(peak / MB, 2), "limit_mb": limit_mb,
            "total_mb": round(sum(s for _, s in transfers) / MB, 2),
            "downloads": len(transfers),
            "window_start": start.isoformat() if start else None,
            "window_end": end.isoformat() if end else None,
        })
    order = {"HIGH": 2, "MEDIUM": 1, "OK": 0}
    return sorted(results, key=lambda r: (order[r["severity"]], r["peak_mb"]), reverse=True)


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Data exfiltration detector (download volume per IP)")
    p.add_argument("--log", default="logs/access.log", help="Path to the access log")
    p.add_argument("--demo", action="store_true", help="Run on a built-in sample log (ignores --log)")
    p.add_argument("--authorized-ips", default="192.168.1.50,192.168.1.100",
                   help="Comma-separated IPs or networks (CIDR) allowed to move more data")
    p.add_argument("--limit-unauthorized", type=float, default=20,
                   help="MB allowed per window for other IPs (default 20)")
    p.add_argument("--limit-authorized", type=float, default=100,
                   help="MB allowed per window for authorized IPs (default 100)")
    p.add_argument("--window", type=int, default=60, help="Window size in minutes (default 60)")
    p.add_argument("--json-output", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    if args.demo:
        log.info("Demo mode: using built-in sample log")
        lines, authorized_text = DEMO_LOG.splitlines(), DEMO_AUTHORIZED
    elif (lines := read_log_lines(args.log, log)) is None:
        return EXIT_ERROR
    else:
        authorized_text = args.authorized_ips

    authorized = authorized_text.split(",")
    try:
        parse_authorized(authorized)
    except ValueError as e:
        log.error("Invalid --authorized-ips entry: %s", e)
        return EXIT_ERROR
    by_ip = read_transfers(lines)
    if not by_ip:
        log.info("No downloads found in the log.")
        return EXIT_OK

    results = analyze(by_ip, authorized, args.limit_unauthorized, args.limit_authorized, args.window)
    log.info("IPs with downloads: %d | window: %d min", len(results), args.window)
    for r in results:
        level = log.warning if r["severity"] != "OK" else log.info
        level("%-6s %s%s: %.2f MB in %d min (limit %g MB), %.2f MB total in %d downloads",
              r["severity"], r["ip"], " [authorized]" if r["authorized"] else "",
              r["peak_mb"], args.window, r["limit_mb"], r["total_mb"], r["downloads"])

    if args.json_output:
        try:
            write_json(args.json_output, {"results": results})
            log.info("Results saved to %s", args.json_output)
        except OSError as e:
            log.error("Could not write output: %s", e)
            return EXIT_ERROR

    return EXIT_ALERTS if any(r["severity"] != "OK" for r in results) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())