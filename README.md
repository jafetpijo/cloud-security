# Cloud Security Log Analysis Toolkit

Python log analysis toolkit (SIEM-style). Detects brute-force attacks, password
spraying, logins from new IPs, risky permission changes in Linux and AWS, data
exfiltration and data staging, and produces daily summaries.

> Learning project by an aspiring Cloud Security Engineer. Next step: adapt the
> detectors to real AWS CloudTrail logs using boto3.

## Problem Solved

Security teams review thousands of log lines every day. This toolkit automates the
repetitive part: parsing logs, flagging suspicious patterns with a severity level
and a MITRE ATT&CK technique, and saving reports for review.

## Tools

| Script | Detection | Key technique | MITRE ATT&CK |
|--------|-----------|---------------|--------------|
| `resumen_diario.py` | Daily summary | Events by type, log time range, most active IPs and users | – |
| `clasificador.py` | Event classification | Rule table: regex → category → severity → technique | T1562.008, T1485, T1098, T1110 |
| `analizador_fuerza_bruta.py` | Brute force, password spraying | Sliding time window by IP **and** by user; CRITICAL if the attacker logs in afterwards | T1110, T1110.003, T1078 |
| `detector_acceso_ips_nuevas.py` | Logins from new IPs | Baseline of known user/IP pairs, higher severity for privileged accounts | T1078 |
| `auditor_permisos.py` | Risky permission changes | `chmod` mode analysis (world-writable, setuid) + AWS IAM/S3 events + burst detection | T1222, T1548.001, T1098.001 |
| `detector_exfiltracion.py` | Data exfiltration | MB downloaded per IP in a sliding window; external 20 MB, authorized 100 MB | TA0010, T1530 |
| `detector_crecimiento.py` | Data staging / mass deletion | Folder size compared with the previous run | T1074, T1485 |

A typical workflow: read the daily summary first, then run the detectors that
match what stands out.

## Quick Start

Every tool has a `--demo` mode with built-in sample data, so it works right after
cloning, with no log file:

```bash
git clone https://github.com/jafetpijo/cloud-security.git
cd cloud-security
python3 templates/analizador_fuerza_bruta.py --demo
```

```
--- By IP ---
CRITICAL 198.51.100.9 (documentation): 15 failures in 5 min, 15 in total, 1 different users -> LOGGED IN AFTERWARDS
HIGH     192.0.2.66 (documentation): 12 failures in 5 min, 12 in total, 12 different users
...
--- By user ---
CRITICAL admin: 15 failures in 5 min, 15 in total, 1 different ips -> LOGGED IN AFTERWARDS
HIGH     carlos: 12 failures in 5 min, 12 in total, 12 different ips
```

Then point it at a real log:

```bash
python3 templates/resumen_diario.py --log /var/log/auth.log
python3 templates/analizador_fuerza_bruta.py --log /var/log/auth.log
```

More examples:

```bash
# New IPs: build the baseline once from a normal log, then check new logs
python3 templates/detector_acceso_ips_nuevas.py --log normal.log --learn
python3 templates/detector_acceso_ips_nuevas.py --log today.log

# Exfiltration with custom limits
python3 templates/detector_exfiltracion.py --log access.log --authorized-ips 192.168.1.50 --limit-unauthorized 20

# Folder growth: run on a schedule (e.g. cron), alerts on 100+ MB of change since the last run
python3 templates/detector_crecimiento.py --path ./carpetas_empresa --threshold 100
```

Run any tool with `-h` to see all its options.

## Supported Log Formats

| Source | Example |
|---|---|
| Linux `auth.log` (sshd) | `Nov 17 10:00:05 web01 sshd[99]: Failed password for root from 203.0.113.7 port 22` |
| App logs, key=value | `2026-11-17 10:00:00 LOGIN OK user=ana ip=192.168.1.20` |
| App logs, Spanish | `2026-11-01 10:00:00 DOWNLOAD usuario=juan tamaño=52428800 ip=10.0.0.99` |
| Web access logs | `203.0.113.7 - - [17/Nov/2026:10:00:00 -0600] "GET /backup.zip HTTP/1.1" 200 5242880` |
| AWS CloudTrail event names | `PutBucketAcl`, `CreateAccessKey`, `StopLogging`, ... |

## Exit Codes and Severity

Designed to be used in scripts and scheduled jobs:

| Exit code | Meaning |
|---|---|
| `0` | Nothing to report |
| `1` | Alerts found |
| `2` | Error (for example, the log file doesn't exist) |

| Severity | Meaning |
|---|---|
| `CRITICAL` | Likely compromise: an attack followed by a successful login, or a privileged account making a risky change |
| `HIGH` | Clear attack pattern or risky change that needs review |
| `MEDIUM` | Unusual but often legitimate: bursts of normal changes, authorized IPs over their limit |
| `OK` | Normal activity |

## Project Structure

```
cloud-security/
├── logs/          # sample logs (ignored by git)
├── reportes/      # generated reports (ignored by git)
└── templates/
    ├── resumen_diario.py               + test_resumen_diario.py
    ├── clasificador.py                 + test_clasificador_eventos.py
    ├── analizador_fuerza_bruta.py      + test_analizador_fuerza_bruta.py
    ├── detector_acceso_ips_nuevas.py   + test_detector_ips_nuevas.py
    ├── auditor_permisos.py             + test_auditor_permisos.py
    ├── detector_exfiltracion.py        + test_detector_exfiltracion.py
    └── detector_crecimiento.py         + test_detector_crecimiento.py
```

## Tests

Every tool has unit tests (59 in total). Run them from the `templates` folder:

```bash
cd templates
python3 -m unittest -v
```

## Tech Highlights

- Python 3.9+, standard library only (`argparse`, `re`, `logging`, `ipaddress`, `collections`, `datetime`, `pathlib`, `unittest`)
- Sliding time window detection: events within N minutes, not totals over the whole log
- Same structure in every tool: `--demo` mode, consistent exit codes, JSON output for SIEM ingestion
- IP validation with the `ipaddress` module; whole-word regex matching to avoid false positives (`TOKEN` is not `OK`)
- Reports use the timestamp from the log, not the time the script ran
- Never invents data: a missing log is an error, sample data only runs with `--demo`

## Known Limitations

- Built and tested with sample logs, not production traffic
- Detections are heuristics for learning and small environments, not a replacement for a SIEM or EDR
- CloudTrail is supported by event name in text logs; native CloudTrail JSON is not parsed yet
- IPv6 addresses are not extracted yet

## Roadmap

- Read AWS CloudTrail logs with boto3
- Native JSON log support (CloudTrail, VPC Flow Logs)
- IPv6 support

## Author

**Jafet García** | Aspiring Cloud Security Engineer | Python, Linux, Networking | Costa Rica