#!/usr/bin/env python3
import os
import re
import argparse
from datetime import datetime, timedelta

# ==========================================
# 1. CONFIGURATION
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"
UMBRAL_ERRORES = 5      # errores permitidos dentro de la ventana
VENTANA_MINUTOS = 5     # tamaño del tramo

PATRON_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATRON_FECHA = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
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

def leer_errores(ruta_logs):
    """Devuelve un diccionario: IP -> lista de fechas con error."""
    errores = {}
    try:
        with open(ruta_logs, "r", errors="ignore") as f:
            for linea in f:
                if "ERROR" not in linea.upper():
                    continue
                m_ip = PATRON_IP.search(linea)
                if not m_ip:
                    continue
                ip = m_ip.group()

                fecha = None
                m_fecha = PATRON_FECHA.search(linea)
                if m_fecha:
                    fecha = datetime.strptime(m_fecha.group(1), "%Y-%m-%d %H:%M:%S")

                errores.setdefault(ip, []).append(fecha)
    except FileNotFoundError:
        print(f"❌ No se encontró '{ruta_logs}'")
        return None
    except PermissionError:
        print(f"❌ Sin permisos para leer '{ruta_logs}'")
        return None
    return errores

def max_en_ventana(fechas, minutos):
    """Cuenta el máximo de errores dentro de cualquier tramo de 'minutos'."""
    fechas = sorted(f for f in fechas if f is not None)
    ventana = timedelta(minutes=minutos)
    maximo = 0
    for i in range(len(fechas)):
        conteo = 0
        for j in range(i, len(fechas)):
            if fechas[j] - fechas[i] <= ventana:
                conteo += 1
        if conteo > maximo:
            maximo = conteo
    return maximo

# ==========================================
# 3. ANALYSIS AND DASHBOARD
# ==========================================
def analizar(errores):
    print("\n" + "=" * 60)
    print("📊 ANÁLISIS DE ERRORES POR IP")
    print("=" * 60 + "\n")

    total = sum(len(fechas) for fechas in errores.values())
    print(f"📈 Total de errores: {total}")
    print(f"🌐 IPs con errores: {len(errores)}\n")

    alertas = []
    for ip, fechas in sorted(errores.items(), key=lambda x: len(x[1]), reverse=True):
        cantidad = len(fechas)
        porcentaje = cantidad / total * 100
        maximo = max_en_ventana(fechas, VENTANA_MINUTOS)

        print(f"🌐 {ip}: {cantidad} errores ({porcentaje:.1f}%) | "
              f"máx {maximo} en {VENTANA_MINUTOS} min")

        if maximo > UMBRAL_ERRORES:
            print(f"   🚨 ALERTA: posible ataque ({maximo} > {UMBRAL_ERRORES})")
            alertas.append(f"{ip}: {maximo} errores en {VENTANA_MINUTOS} min")

    print(f"\n🔔 Total de alertas: {len(alertas)}")
    print("=" * 60 + "\n")
    return alertas

def generar_reporte(errores, alertas):
    crear_carpeta_reportes()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_out = f"{CARPETA_REPORTES}/analisis_errores_ips.log"
    total = sum(len(fechas) for fechas in errores.values())
    try:
        with open(ruta_out, "a") as r:
            r.write(f"\n[{ts}] ANÁLISIS DE ERRORES - Total: {total}\n")
            for ip, fechas in sorted(errores.items(), key=lambda x: len(x[1]), reverse=True):
                r.write(f"  {ip}: {len(fechas)} errores\n")
            for alerta in alertas:
                r.write(f"  -> ALERTA: {alerta}\n")
        print(f"📝 Reporte guardado en: {ruta_out}\n")
        return True
    except (PermissionError, OSError) as e:
        print(f"❌ Error al generar reporte: {e}")
        return False

# ==========================================
# 4. EXECUTION
# ==========================================
def ejecutar_analisis(ruta_logs):
    print("\n🔍 Iniciando análisis de errores por IP...\n")
    if not validar_archivo_logs(ruta_logs):
        return False
    errores = leer_errores(ruta_logs)
    if errores is None:
        return False
    if not errores:
        print("✅ Sin errores con IP detectados.\n")
        return True
    alertas = analizar(errores)
    return generar_reporte(errores, alertas)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Análisis de errores por IP")
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log")
    args = parser.parse_args()
    ejecutar_analisis(args.log)