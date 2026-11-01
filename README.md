# Mini-SIEM | Cloud Security Log Automation

Python-based Mini-SIEM with 8 detectors for AWS log analysis. Built from La Fortuna, Costa Rica.

> Detects brute-force, data exfiltration with Zero Trust thresholds (20MB external / 100MB internal), new-IP anomalies with baseline learning, privilege escalation, and daily dashboards.

## 📁 Real Project Structure

cloud-security/
├── templates/
│   ├── analizador.py
│   ├── clasificador.py
│   ├── contador_permisos.py
│   ├── detector_acceso_ips_nuevas.py
│   ├── detector_empresa_copleto.py
│   ├── detector_exfiltracion.py
│   ├── detector_usuarios.py
│   └── resumen_diario.py
└── reportes/

## 🛠️ 8 Detectors

1. detector_usuarios.py - Brute-force login
2. analizador.py - Top attacker IPs (Regex IP)
3. detector_exfiltracion.py - Exfiltration v1 (100MB)
4. detector_empresa_copleto.py ⭐ STAR - Zero Trust (20MB external = RED, 100MB internal = YELLOW)
5. detector_acceso_ips_nuevas.py - New IP anomaly + baseline learning
6. clasificador.py - Critical vs Normal
7. contador_permisos.py - Privilege escalation (CHMOD)
8. resumen_diario.py - Daily dashboard

## 🚀 Quick Start

python3 templates/detector_empresa_copleto.py
python3 templates/detector_acceso_ips_nuevas.py
python3 templates/resumen_diario.py

## 👤 Jafet García | La Fortuna, CR

