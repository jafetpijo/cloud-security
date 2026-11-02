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
        print(f"⚠️ Archivo vacío: '{ruta}'")
        return False
    return True

def cargar_baseline():
    if not os.path.exists(ARCHIVO_BASELINE):
        return set()
    try:
        with open(ARCHIVO_BASELINE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except (PermissionError, OSError) as e:
        print(f"❌ Error leyendo baseline: {e}")
        return set()

def guardar_baseline(pares):
    crear_carpeta_reportes()
    try:
        with open(ARCHIVO_BASELINE, "a") as f:
            for item in pares:
                f.write(f"{item}\n")
        return True
    except (PermissionError, OSError) as e:
        print(f"❌ Error guardando baseline: {e}")
        return False

def leer_accesos_nuevos(ruta_logs):
    accesos_nuevos = []
    pares_nuevos = set()

    baseline = cargar_baseline()
    if not baseline:
        print("ℹ️ Baseline vacío: primera corrida, usa --aprender para crear la línea base\n")

    # Two separate patterns, so the order of user/ip in the line does not matter
    patron_usuario = re.compile(r'(?:usuario|user)=([a-zA-Z0-9_.-]+)', re.I)
    patron_ip = re.compile(r'ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})', re.I)

    try:
        with open(ruta_logs, "r", errors="ignore") as archivo:
            for linea in archivo:
                upper = linea.upper()
                # Match "LOGIN OK" / "SUCCESS", not just "OK" (avoids TOKEN, BROKEN)
                if "LOGIN OK" in upper or "LOGIN SUCCESS" in upper or "SUCCESSFUL LOGIN" in upper:
                    m_user = patron_usuario.search(linea)
                    m_ip = patron_ip.search(linea)
                    if m_user and m_ip:
                        usuario = m_user.group(1)
                        ip = m_ip.group(1)
                        clave = f"{usuario},{ip}"
                        if clave not in baseline:
                            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            accesos_nuevos.append((usuario, ip, ts, linea.strip()))
                            pares_nuevos.add(clave)
                            baseline.add(clave)  # avoid repeating within the same file
    except FileNotFoundError:
        print(f"❌ No se encontró '{ruta_logs}'")
        return None, None
    except PermissionError:
        print(f"❌ Sin permisos para leer '{ruta_logs}'")
        return None, None
    return accesos_nuevos, pares_nuevos

def mostrar_dashboard(accesos):
    print("\n" + "=" * 60)
    print("📊 ACCESOS DESDE IPs NUEVAS")
    print("=" * 60 + "\n")
    usuarios = {}
    for u, ip, _, _ in accesos:
        usuarios.setdefault(u, []).append(ip)

    for u, ips in usuarios.items():
        print(f"👤 {u}")
        for ip in ips:
            print(f"   └─ 🌐 {ip} -> NUEVA 🚨")

    print(f"\n⚠️ Total anómalos: {len(accesos)}\n" + "=" * 60 + "\n")

def generar_reporte(accesos):
    crear_carpeta_reportes()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_out = f"{CARPETA_REPORTES}/accesos_anomalos.log"
    try:
        with open(ruta_out, "a") as r:
            r.write(f"\n[{ts}] DETECCIÓN IPs NUEVAS - Total: {len(accesos)}\n")
            for u, ip, t, _ in accesos:
                r.write(f"[{t}] [ANOMALÍA] Usuario: {u} | IP: {ip}\n")
        print(f"📝 Reporte guardado en: {ruta_out}\n")
        return True
    except (PermissionError, OSError) as e:
        print(f"❌ Error al generar reporte: {e}")
        return False

def ejecutar_deteccion(ruta_logs, aprender=False):
    print("\n🔍 Iniciando detección de IPs nuevas...\n")
    if not validar_archivo_logs(ruta_logs):
        return False

    accesos, nuevas = leer_accesos_nuevos(ruta_logs)
    if accesos is None:
        return False
    if not accesos:
        print("✅ Sin accesos desde IPs nuevas.\n")
        return True

    mostrar_dashboard(accesos)
    reporte_ok = generar_reporte(accesos)

    if aprender:
        if guardar_baseline(nuevas):
            print(f"🧠 Baseline actualizado con {len(nuevas)} combinaciones usuario,ip nuevas\n")
    else:
        print("💡 Tip: usa --aprender para agregar estas IPs como conocidas\n")
    return reporte_ok

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detector de IPs nuevas por usuario")
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log a analizar")
    parser.add_argument("--aprender", action="store_true", help="Agregar IPs nuevas al baseline")
    args = parser.parse_args()
    ejecutar_deteccion(args.log, args.aprender)
