#!/usr/bin/env python3
import re
import argparse
import os
from collections import Counter
from datetime import datetime

RUTA_LOGS = "logs/servidor_aws.log"
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CARPETA_REPORTES = "reportes"

def crear_carpeta_reportes():
    os.makedirs(CARPETA_REPORTES, exist_ok=True)

def validar_archivo_logs(ruta):
    if not os.path.exists(ruta):
        print(f"❌ Error: No se encontró '{ruta}'")
        return False
    if os.path.getsize(ruta) == 0:
        print(f"⚠️  Archivo vacío: '{ruta}'")
        return False
    return True

def leer_errores_por_ip(ruta_logs):
    errores_totales = 0
    ips = Counter()
    try:
        with open(ruta_logs, "r") as archivo:
            for linea in archivo:
                if "ERROR" in linea.upper():
                    errores_totales += 1
                    match = IP_REGEX.search(linea)
                    if match:
                        ips[match.group()] += 1
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None, None
    except PermissionError:
        print(f"❌ Error: Sin permisos para leer '{ruta_logs}'")
        return None, None
    return ips, errores_totales

def mostrar_dashboard_consola(ips, errores_totales):
    print("\n" + "=" * 60)
    print("📊 ANÁLISIS DE ERRORES POR IP")
    print("=" * 60 + "\n")
    print(f"📈 Total de errores: {errores_totales}\n")
    print(f"🌐 IPs únicas con errores: {len(ips)}\n")
    print("IPs con más errores:")
    for ip, cantidad in ips.most_common():
        porcentaje = (cantidad / errores_totales * 100) if errores_totales > 0 else 0
        print(f"   {ip}: {cantidad} errores ({porcentaje:.1f}%)")
    print("\n" + "=" * 60 + "\n")

def generar_reporte(ips, errores_totales):
    crear_carpeta_reportes()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(f"{CARPETA_REPORTES}/analisis_errores_ips.log", "a") as reporte:
            reporte.write("=" * 60 + "\n")
            reporte.write(f"[{timestamp}] ANÁLISIS DE ERRORES POR IP\n")
            reporte.write("=" * 60 + "\n\n")
            reporte.write(f"Total de errores: {errores_totales}\n")
            reporte.write(f"IPs únicas: {len(ips)}\n\n")
            reporte.write("IPs con más errores:\n")
            for ip, cantidad in ips.most_common():
                porcentaje = (cantidad / errores_totales * 100) if errores_totales > 0 else 0
                reporte.write(f"  {ip}: {cantidad} errores ({porcentaje:.1f}%)\n")
            reporte.write("\n" + "=" * 60 + "\n\n")
        return True
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}")
        return False

def ejecutar_analisis(ruta_logs=None):
    ruta = ruta_logs or RUTA_LOGS
    print("\n🔍 Iniciando análisis de errores por IP...\n")
    if not validar_archivo_logs(ruta):
        return False
    ips, errores_totales = leer_errores_por_ip(ruta)  # <- AQUÍ ESTABA EL BUG 2
    if ips is None:
        return False
    if errores_totales == 0:
        print("✅ Sin errores detectados.\n")
        return True
    mostrar_dashboard_consola(ips, errores_totales)
    if generar_reporte(ips, errores_totales):
        print(f"📝 Reporte guardado en: {CARPETA_REPORTES}/analisis_errores_ips.log\n")
        return True
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log a analizar")
    args = parser.parse_args()
    ejecutar_analisis(args.log)