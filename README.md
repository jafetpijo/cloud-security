Mini-SIEM | Cloud Security Log Automation & Incident Response

Python-based Mini-SIEM with 8 detectors for AWS log analysis. Built from La Fortuna, Costa Rica. Focused on SOC Analyst / Cloud Security roles.

> Detects brute-force, data exfiltration with Zero Trust thresholds (20MB external / 100MB internal), new-IP anomalies with baseline learning (UEBA), privilege escalation, and daily executive dashboards.

🎯 Problem Solved

SOC teams analyze millions of log lines daily. This suite automates parsing, anomaly detection, and alert generation.

📁 Project Structure
cloud-security/
├── logs/
│   └── servidor_aws.log
├── reportes/
│   ├── analisis_errores_ips.log
│   ├── deteccion_fuerza_bruta.log
│   ├── alerta_exfiltracion.log
│   ├── accesos_anomalos.log
│   ├── auditoria_permisos.log
│   ├── alertas_criticas.log
│   ├── eventos_normales.log
│   └── resumen_diario.log
└── templates/
    ├── analizador_errores_ip.py
    ├── detector_usuarios.py
    ├── detector_exfiltracion.py
    ├── detector_empresa_completo.py
    ├── detector_ips_nuevas.py
    ├── clasificador_eventos.py
    ├── auditoria_permisos.py
    └── resumen_diario.py
🛠️ 8 Detectors
#	Script	Detection	Key Technique
1	`detector_usuarios.py`	Brute-force login	Counter + threshold per user
2	`analizador_errores_ip.py`	Top attacker IPs	Regex IP + percentage breakdown
3	`detector_exfiltracion.py`	Data exfiltration v1	100MB flat threshold
4	`detector_empresa_completo.py` ⭐	Zero Trust exfiltration	20MB external = RED, 100MB internal = YELLOW
5	`detector_ips_nuevas.py`	New IP / Account takeover	Baseline file + learning flag --aprender
6	`clasificador_eventos.py`	Critical vs Normal	Log classification
7	`auditoria_permisos.py`	Privilege escalation	CHMOD tracking, non-admin >3 = critical
8	`resumen_diario.py`	Daily security dashboard	KPIs, % errors/alerts/OK
⭐ STAR: Implements Zero Trust model.

🚀 Quick Start
python3 templates/detector_empresa_completo.py --log logs/servidor_aws.log
python3 templates/detector_ips_nuevas.py --log logs/servidor_aws.log --aprender
python3 templates/resumen_diario.py
cat reportes/resumen_diario.log
🔧 Tech Highlights

- Python 3.8+ (no external deps), argparse, re, Counter
- SOC concepts: SIEM, UEBA, Zero Trust, Privilege Escalation, Data Exfiltration
- Best practices: file validation, PermissionError handling, timestamps, append history, modular functions

📊 Sample Output

📊 BRUTE FORCE DETECTION
📈 Total fails: 47 | Affected users: 3
jafet: 15 attempts (31.9%) 🚨 CRITICAL
admin: 20 attempts (42.6%) 🚨 CRITICAL
📝 Report saved: reportes/deteccion_fuerza_bruta.log
👤 Author

*Jafet García* | Cloud Security Engineer | Python Developer | La Fortuna, Alajuela, CR

---

