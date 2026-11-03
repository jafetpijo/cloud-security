#!/usr/bin/env python3
import os
import argparse
from datetime import datetime

# ==========================================
# 1. CONFIGURATION
# ==========================================
RUTA_A_MONITOREAR = "./carpetas_empresa"
UMBRAL_MB = 100          # límite en MB
CARPETA_ALERTAS = "alertas"

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def crear_carpeta_alertas():
    os.makedirs(CARPETA_ALERTAS, exist_ok=True)

def calcular_volumen_datos(ruta_target):
    """Devuelve el tamaño en MB, o None si no se pudo calcular."""
    if not os.path.exists(ruta_target):
        print(f"❌ La ruta '{ruta_target}' no existe.")
        return None

    bytes_totales = 0
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
        return None

    return bytes_totales / (1024 * 1024)

def registrar_alerta(mb_totales, ruta):
    crear_carpeta_alertas()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_log = f"{CARPETA_ALERTAS}/alerta_exfiltracion.log"
    try:
        with open(ruta_log, "a") as reporte:
            reporte.write(
                f"[{ts}] ALERTA: {mb_totales:.2f} MB en '{ruta}' "
                f"(límite: {UMBRAL_MB} MB)\n"
            )
        print(f"📝 Alerta registrada en: {ruta_log}\n")
        return True
    except (PermissionError, OSError) as e:
        print(f"❌ Error al escribir la alerta: {e}")
        return False

# ==========================================
# 3. DETECTOR LOGIC
# ==========================================
def analizar_volumen(ruta_target):
    print("\n" + "=" * 60)
    print("🛡️  DETECTOR DE EXFILTRACIÓN")
    print("=" * 60 + "\n")

    mb_totales = calcular_volumen_datos(ruta_target)
    if mb_totales is None:
        print("❌ No se pudo calcular el volumen. Escaneo cancelado.\n")
        return False

    print(f"📁 Ruta: {ruta_target}")
    print(f"📦 Volumen: {mb_totales:.2f} MB")
    print(f"📏 Límite: {UMBRAL_MB} MB\n")

    if mb_totales > UMBRAL_MB:
        print(f"🚨 ALERTA: el volumen supera el límite ({mb_totales:.2f} > {UMBRAL_MB} MB)")
        registrar_alerta(mb_totales, ruta_target)
        print("=" * 60 + "\n")
        return False

    print("✅ Volumen dentro del límite.\n")
    print("=" * 60 + "\n")
    return True

# ==========================================
# 4. EXECUTION
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detector de exfiltración por volumen")
    parser.add_argument("--ruta", default=RUTA_A_MONITOREAR, help="Carpeta a vigilar")
    parser.add_argument("--umbral", type=int, default=UMBRAL_MB, help="Límite en MB")
    args = parser.parse_args()

    UMBRAL_MB = args.umbral
    analizar_volumen(args.ruta)