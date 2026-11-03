# Cloud Security Log Analysis Toolkit

Python log analysis toolkit (SIEM-style) built with a sample server log. Detects brute-force attempts, data exfiltration, logins from new IPs, permission changes, and produces daily summaries.

> Learning project by an aspiring Cloud Security Engineer. Next step: adapt the detectors to real AWS CloudTrail logs using boto3.

## Problem Solved

Security teams review thousands of log lines every day. This toolkit automates the repetitive part: parsing logs, flagging suspicious patterns, and saving timestamped reports for review.

## Project Structure

```
cloud-security/
├── logs/
│   └── servidor_aws.log
├── reportes/
└── templates/
    ├── analizador.py
    ├── clasificador.py
    ├── contador_permisos.py
    ├── detector_acceso_ips_nuevas.py
    ├── detector_empresa_completo.py
    ├── detector_exfiltracion.py
    ├── detector_usuarios.py
    └── resumen_diario.py
```

## Tools

| # | Script | Detection | Key technique |
|---|--------|-----------|---------------|
| 1 | `detector_usuarios.py` | Brute-force logins | Counter + threshold per user |
| 2 | `analizador.py` | Error spikes by IP | Regex IP extraction + sliding time window |
| 3 | `detector_exfiltracion.py` | Data exfiltration (v1) | Flat 100 MB threshold |
| 4 | `detector_empresa_completo.py` | Data exfiltration (v2) | Threshold by source type: external 20 MB, internal 100 MB |
| 5 | `detector_acceso_ips_nuevas.py` | Logins from new IPs | Baseline of known IPs per user |
| 6 | `clasificador.py` | Event classification | Rule table with severity levels |
| 7 | `contador_permisos.py` | Permission change auditing | CHMOD tracking + sliding time window, risky modes flagged |
| 8 | `resumen_diario.py` | Daily summary | Totals and percentages of errors, alerts and OK events |

## Quick Start

```bash
git clone https://github.com/jafetpijo/cloud-security.git
cd cloud-security
python3 templates/detector_usuarios.py
python3 templates/analizador.py --log logs/servidor_aws.log
python3 templates/resumen_diario.py
cat reportes/resumen_diario.log
```

Reports are saved in `reportes/` with a timestamp, in append mode, so the history is kept.

## Tech Highlights

- Python 3, standard library only (`argparse`, `re`, `collections`, `datetime`, `os`)
- Sliding time window detection (events within N minutes)
- File validation and error handling (`FileNotFoundError`, `PermissionError`)
- Timestamped reports in append mode
- Modular functions, one responsibility each
- Configurable paths and thresholds

## Known Limitations

- Built and tested with a sample log, not real production logs
- IP regex does not validate ranges (could use the `ipaddress` module)
- Some filters may produce false positives

## Roadmap

- Read AWS CloudTrail logs with boto3
- JSON log support

## Author

**Jafet García** | Aspiring Cloud Security Engineer | Python, Linux, Networking | Costa Rica