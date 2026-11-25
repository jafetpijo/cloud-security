"""
Shared helpers for every tool in the kit.

Anything that more than one detector needs lives here, so a fix (a new log
format, a parsing bug) is made once and reaches every tool:
  - exit codes and logging setup
  - reading the log file (never inventing data when it's missing)
  - timestamps: ISO and syslog (with the year inferred, see parse_timestamp)
  - IP and user extraction
  - sliding time window counting
  - JSON output

A new detector usually imports from here and only adds its own rules.
"""
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2

# --- Regex building blocks ---------------------------------------------------
IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
ISO_TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
SYSLOG_TS_REGEX = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})")
# Key=value accounts used by the app logs: user=ana or usuario=ana
KV_USER_REGEX = re.compile(r"\b(?:usuario|user)=([\w.@-]+)", re.IGNORECASE)
# sshd account and source IP: "for ana from 1.2.3.4" / "for invalid user bob from 1.2.3.4"
SSHD_USER_REGEX = re.compile(r"\bfor (?:invalid user )?([\w.@-]+) from\b", re.IGNORECASE)
# Successful SSH login with any method: password, publickey,
# keyboard-interactive/pam (2FA), gssapi-with-mic...
SSHD_ACCEPTED = r"accepted [\w/-]+ for"
# sshd logs every failed password twice in auth.log: once from PAM
# ("pam_unix(sshd:auth): authentication failure") and once from sshd itself
# ("Failed password for ..."), plus a "PAM N more authentication failures"
# summary when the connection closes. Tools that count attempts skip these
# PAM copies so each attempt counts once.
SSHD_PAM_DUPLICATE_REGEX = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure|\bPAM \d+ more authentication failures?",
    re.IGNORECASE,
)


# --- Setup and input ---------------------------------------------------------
def setup_logging(verbose=False):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")


def read_log_lines(path, log):
    """Return the lines of the log, or None (after logging why) if it can't be read.
    A missing log is always an error: the tools never fall back to sample data."""
    src = Path(path)
    if not src.is_file():
        log.error("Log file not found: %s", src)
        return None
    try:
        return src.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as e:
        log.error("Could not read %s: %s", src, e)
        return None


def write_json(path, data):
    """Write `data` as indented JSON (SIEM-friendly). Raises OSError on failure."""
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_year_argument(parser):
    parser.add_argument(
        "--year", type=int, default=None,
        help="Year for syslog timestamps, which don't include one (default: the current "
             "year, or the previous one for dates that would be in the future)")


# --- Timestamps --------------------------------------------------------------
def parse_timestamp(line, year=None, now=None):
    """Return the datetime of a log line, or None.

    ISO timestamps carry their own year. Syslog ones ("Nov 17 10:00:00") don't:
    - with an explicit `year`, that year is used as is;
    - without one, the current year is used, unless that puts the date more
      than a day in the future. Then it must be from last year: a December log
      read in January, or the December part of a log that crosses New Year.
    """
    if m := ISO_TS_REGEX.search(line):
        return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    m = SYSLOG_TS_REGEX.search(line)
    if not m:
        return None
    text = f"{m.group(1)} {m.group(2)} {m.group(3)}"
    if year is not None:
        return _syslog_datetime(year, text)
    now = now or datetime.now()
    ts = _syslog_datetime(now.year, text)
    if ts is not None and ts > now + timedelta(days=1):
        ts = _syslog_datetime(now.year - 1, text)
    return ts


def _syslog_datetime(year, text):
    try:
        return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:        # e.g. "Feb 29" in a year that is not a leap year
        return None


# --- IPs and users -----------------------------------------------------------
def valid_ip(text):
    """Return an ipaddress object, or None for values like 999.1.1.1."""
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def find_user(line):
    """Account named in the line: sshd style first, then user=/usuario=."""
    m = SSHD_USER_REGEX.search(line) or KV_USER_REGEX.search(line)
    return m.group(1).lower() if m else None


def parse_privileged(text):
    """'root, Admin' -> {'root', 'admin'}"""
    return {u.strip().lower() for u in text.split(",") if u.strip()}


# --- Analysis ----------------------------------------------------------------
def max_in_window(times, window):
    """Largest number of events in any interval of length `window` (sliding window).
    Returns (count, window_start, window_end). Events without a time are ignored."""
    times = sorted(t for t in times if t is not None)
    best, left = (0, None, None), 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        n = right - left + 1
        if n > best[0]:
            best = (n, times[left], t)
    return best
