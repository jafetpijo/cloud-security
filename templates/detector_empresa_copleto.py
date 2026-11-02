#!/usr/bin/env python3
import os
import argparse
from datetime import datetime

# ==========================================
# 1. CONFIGURATION
# ==========================================
RUTA_A_MONITOREAR = "./carpetas_empresa"
UMBRAL_NO_AUTORIZADA = 20   # MB limit for external (unauthorized) IPs
UMBRAL_AUTORIZADA = 100     # MB limit for internal (authorized) IPs
IPS_AUTORIZADAS = ["192.168.1.50", "192.168.1.100"]
CARPETA_ALERTAS = "alertas"

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def crear_carpeta_alertas():
    os.makedirs(CARPETA_ALERTAS, exist_ok=True)

def registrar_alerta(ip_usuario, mb_totales, tipo_alerta, ruta):
    crear_carpeta_alertas()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_log = f"{CARPETA_ALERTAS}/alerta_exfiltracion.log"
    try:
        with open(ruta_log, "a") as reporte:
            reporte.write(
                f"[{timestamp}] {tipo_alerta}: IP {ip_usuario} | "
                f"{mb_totales:.2f} MB en '{ruta}'\n"
            )
        return ruta_log
    except (PermissionError, OSError) as e:
        print(f"❌ Error al escribir la alerta: {e}")
        return None

def calcular_volumen_datos(ruta_target):
    bytes_totales = 0
    if not os.path.exists(ruta_target):
        print(f"⚠️ La ruta '{ruta_target}' no existe. Creándola para prueba...")
        os.makedirs(ruta_target, exist_ok=True)
        return 0

    try:
        for raiz, _, archivos in os.walk(ruta_target):
            for archivo in archivos:
                try:
                    ruta_completa = os.path.join(raiz, archivo)
                    bytes_totales += os.path.getsize(ruta_completa)
                except (FileNotFoundError, PermissionError):
                    continue
    except PermissionError as e:
        print(f"❌ Error de permisos en '{ruta_target}': {e}")
        return 0

    return bytes_totales / (1024 * 1024)

# ==========================================
# 3. DETECTOR LOGIC (TWO THRESHOLDS)
# ==========================================
def analizar_seguridad(ip_usuario, ruta_target=RUTA_A_MONITOREAR):
    print("\n--- INICIANDO ESCANEO DE SEGURIDAD ---\n")
    mb_totales = calcular_volumen_datos(ruta_target)
    print(f"IP: {ip_usuario} | Volumen: {mb_totales:.2f} MB\n")

    if ip_usuario in IPS_AUTORIZADAS:
        # Internal IP, but it still has a limit
        if mb_totales > UMBRAL_AUTORIZADA:
            print(f"⚠️ ALERTA AMARILLA: IP autorizada {ip_usuario} con volumen muy alto "
                  f"({mb_totales:.2f} > {UMBRAL_AUTORIZADA} MB)")
            registrar_alerta(ip_usuario, mb_totales, "ALERTA AMARILLA", ruta_target)
            return False
        print("✅ IP autorizada, volumen OK\n")
        return True

    # External IP, stricter limit
    if mb_totales > UMBRAL_NO_AUTORIZADA:
        print(f"🚨 ALERTA ROJA: IP NO autorizada {ip_usuario} superó {UMBRAL_NO_AUTORIZADA} MB "
              f"({mb_totales:.2f} MB)")
        registrar_alerta(ip_usuario, mb_totales, "ALERTA ROJA", ruta_target)
        return False
    print("✅ IP no autorizada pero volumen pequeño, OK\n")
    return True

# ==========================================
# 4. EXECUTION
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detector de exfiltración por umbrales")
    parser.add_argument("--ip", default="10.0.0.99", help="IP a evaluar")
    parser.add_argument("--ruta", default=RUTA_A_MONITOREAR, help="Carpeta a vigilar")
    parser.add_argument("--umbral-externo", type=int, default=UMBRAL_NO_AUTORIZADA,
                        help="Límite en MB para IPs no autorizadas")
    parser.add_argument("--umbral-interno", type=int, default=UMBRAL_AUTORIZADA,
                        help="Límite en MB para IPs autorizadas")
    args = parser.parse_args()

    UMBRAL_NO_AUTORIZADA = args.umbral_externo
    UMBRAL_AUTORIZADA = args.umbral_interno
    analizar_seguridad(args.ip, args.ruta)
