#!/usr/bin/env python3
from collections import defaultdict
from datetime import datetime

# 1. PREPARACIÓN
ips_por_usuario = defaultdict(set)
accesos_nuevos = []

# 2. LECTURA Y ANÁLISIS
with open("servidor_aws.log") as archivo:
    for linea in archivo:
        if "LOGIN" in linea.upper() and "OK" in linea.upper():
            # Busca usuario e IP en el log
            if "usuario=" in linea and "ip=" in linea:
                usuario = linea.split("usuario=")[1].split()[0]
                ip = linea.split("ip=")[1].split()[0]
                
                # Si es la primera vez que vemos esta IP para este usuario
                if ip not in ips_por_usuario[usuario]:
                    ips_por_usuario[usuario].add(ip)
                    accesos_nuevos.append((usuario, ip, linea))

# 3. REPORTE
with open("accesos_anomalos.txt", "w") as reporte:
    reporte.write("=== ALERTA: ACCESOS DESDE IPs NUEVAS ===\n\n")
    for usuario, ip, evento in accesos_nuevos:
        reporte.write(f"[ANOMALÍA] Usuario: {usuario} | IP: {ip}\n")

print(f"[+] {len(accesos_nuevos)} accesos anómalos detectados.")
print("[+] Reporte generado: 'accesos_anomalos.txt'")