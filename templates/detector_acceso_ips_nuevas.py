#!/usr/bin/env python3
import os
import re
import argparse
from datetime import datetime

RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"
ARCHIVO_BASELINE = "reportes/ips_conocidas.txt"

def crear_carpeta_reportes():
    os.makedirs(CARPETA_REPORTES, exist_ok=True)

def validar_archivo_logs(ruta):
    if not os.path.exists(ruta):
        print(f"❌ No se encontró '{ruta}'")
        return False
    if os.path.getsize(ruta) == 0:
        print(f"⚠️ Archivo vacío")
        return False
    return True

def cargar_baseline():
    if not os.path.exists(ARCHIVO_BASELINE):
        return set()
    with open(ARCHIVO_BASELINE, "r") as f:
        return set(line.strip() for line in f if line.strip())

def guardar_baseline(ips):
    with open(ARCHIVO_BASELINE, "a") as f:
        for ip in ips:
            f.write(f"{ip}\n")

def leer_accesos_nuevos(ruta_logs):
    accesos_nuevos = []
    ips_nuevas_para_guardar = set()
    
    baseline = cargar_baseline()
    patron = re.compile(r'(?:usuario|user)=([a-zA-Z0-9_.-]+).*?ip=([0-9.]+)', re.I)

    try:
        with open(ruta_logs, "r", errors="ignore") as archivo:
            for linea in archivo:
                if "LOGIN" in linea.upper() and "OK" in linea.upper():
                    m = patron.search(linea)
                    if m:
                        usuario, ip = m.groups()
                        if ip not in baseline:
                            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            accesos_nuevos.append((usuario, ip, ts, linea.strip()))
                            ips_nuevas_para_guardar.add(ip)
                            baseline.add(ip) # para no repetir en mismo archivo
    except FileNotFoundError:
        print(f"❌ No se encontró '{ruta_logs}'")
        return None, None
    return accesos_nuevos, ips_nuevas_para_guardar

def mostrar_dashboard(accesos):
    print("\n" + "="*60)
    print("📊 ACCESOS DESDE IPs NUEVAS")
    print("="*60 + "\n")
    usuarios = {}
    for u, ip, _, _ in accesos:
        usuarios.setdefault(u, []).append(ip)
    
    for u, ips in usuarios.items():
        print(f"👤 {u}")
        for ip in ips:
            print(f"   └─ 🌐 {ip} -> NUEVA 🚨")
    
    print(f"\n⚠️ Total anómalos: {len(accesos)}\n" + "="*60 + "\n")

def generar_reporte(accesos):
    crear_carpeta_reportes()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_out = f"{CARPETA_REPORTES}/accesos_anomalos.log"
    with open(ruta_out, "a") as r:
        r.write(f"\n[{ts}] DETECCIÓN IPs NUEVAS - Total: {len(accesos)}\n")
        for u, ip, t, _ in accesos:
            r.write(f"[{t}] [ANOMALÍA] Usuario: {u} | IP: {ip}\n")
    print(f"📝 Reporte guardado en: {ruta_out}\n")

def ejecutar_deteccion(ruta_logs, aprender=False):
    print("\n🔍 Iniciando detección IPs nuevas...\n")
    if not validar_archivo_logs(ruta_logs):
        return False
    
    accesos, nuevas = leer_accesos_nuevos(ruta_logs)
    if accesos is None:
        return False
    if not accesos:
        print("✅ Sin accesos desde IPs nuevas.\n")
        return True
    
    mostrar_dashboard(accesos)
    generar_reporte(accesos)
    
    if aprender:
        guardar_baseline(nuevas)
        print(f"🧠 Baseline actualizado con {len(nuevas)} IPs nuevas\n")
    else:
        print("💡 Tip: Usa --aprender para agregar estas IPs como conocidas\n")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detector de IPs nuevas")
    parser.add_argument("--log", default=RUTA_LOGS)
    parser.add_argument("--aprender", action="store_true", help="Agregar IPs nuevas al baseline")
    args = parser.parse_args()
    ejecutar_deteccion(args.log, args.aprender)