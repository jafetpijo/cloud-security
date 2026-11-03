#!/usr/bin/env python3
import os
import re
import argparse
from datetime import datetime

# ==========================================
# 1. CONFIGURATION
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"

# Reglas: (categoría, patrón, severidad). Gana la primera que coincida,
# por eso las más graves van arriba.
REGLAS = [
    ("borrado_de_datos",      r"DeleteBucket|TerminateInstances|DeleteDBInstance", "CRITICA"),
    ("escalada_privilegios",  r"AttachUserPolicy|CreateAccessKey|session opened for user root", "ALTA"),
    ("login_fallido",         r"failed password|invalid user|authentication failure", "ALTA"),
    ("nivel_critico",         r"CRITICAL", "ALTA"),
    ("acceso_denegado",       r"access denied|unauthorized|forbidden|401|403", "MEDIA"),
    ("error_aplicacion",      r"ERROR", "BAJA"),
]

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

def clasificar_linea(linea):
    """Devuelve (categoría, severidad) de la primera regla que coincida, o None."""
    for categoria, patron, severidad in REGLAS:
        if re.search(patron, linea, re.IGNORECASE):
            return categoria, severidad
    return None

def clasificar_archivo(ruta_logs):
    """Lee el log y separa los eventos clasificados de los normales."""
    clasificados = []   # lista de (severidad, categoría, línea)
    normales = []
    try:
        with open(ruta_logs, "r", errors="ignore") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                resultado = clasificar_linea(linea)
                if resultado:
                    categoria, severidad = resultado
                    clasificados.append((severidad, categoria, linea))
                else:
                    normales.append(linea)
    except FileNotFoundError:
        print(f"❌ No se encontró '{ruta_logs}'")
        return None, None
    except PermissionError:
        print(f"❌ Sin permisos para leer '{ruta_logs}'")
        return None, None
    return clasificados, normales

# ==========================================
# 3. ANALYSIS AND DASHBOARD
# ==========================================
def mostrar_dashboard(clasificados, normales):
    print("\n" + "=" * 60)
    print("📊 CLASIFICACIÓN DE EVENTOS")
    print("=" * 60 + "\n")

    total = len(clasificados) + len(normales)
    print(f"📈 Total de eventos: {total}")
    print(f"🔔 Clasificados: {len(clasificados)} | ✅ Normales: {len(normales)}\n")

    # Contar por severidad
    conteo = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0}
    por_categoria = {}
    for severidad, categoria, _ in clasificados:
        conteo[severidad] += 1
        por_categoria[categoria] = por_categoria.get(categoria, 0) + 1

    print("Por severidad:")
    for severidad in ["CRITICA", "ALTA", "MEDIA", "BAJA"]:
        if conteo[severidad] > 0:
            icono = "🚨" if severidad in ("CRITICA", "ALTA") else "⚠️"
            print(f"   {icono} {severidad}: {conteo[severidad]}")

    print("\nPor categoría:")
    for categoria, cantidad in sorted(por_categoria.items(), key=lambda x: x[1], reverse=True):
        print(f"   {categoria}: {cantidad}")

    print("\n" + "=" * 60 + "\n")
    return conteo

def generar_reporte(clasificados, normales):
    crear_carpeta_reportes()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    archivo_alertas = f"{CARPETA_REPORTES}/alertas_criticas.log"
    archivo_normales = f"{CARPETA_REPORTES}/eventos_normales.log"
    try:
        with open(archivo_alertas, "a") as alertas:
            alertas.write(f"\n[{ts}] CLASIFICACIÓN - Alertas: {len(clasificados)}\n")
            for severidad, categoria, linea in clasificados:
                alertas.write(f"  [{severidad}] [{categoria}] {linea}\n")

        with open(archivo_normales, "a") as normal:
            normal.write(f"\n[{ts}] EVENTOS NORMALES: {len(normales)}\n")
            for linea in normales:
                normal.write(f"  {linea}\n")

        print(f"📝 Alertas guardadas en: {archivo_alertas}")
        print(f"📝 Normales guardados en: {archivo_normales}\n")
        return True
    except (PermissionError, OSError) as e:
        print(f"❌ Error al generar reporte: {e}")
        return False

# ==========================================
# 4. EXECUTION
# ==========================================
def ejecutar_clasificacion(ruta_logs):
    print("\n🔍 Iniciando clasificación de eventos...\n")
    if not validar_archivo_logs(ruta_logs):
        return False
    clasificados, normales = clasificar_archivo(ruta_logs)
    if clasificados is None:
        return False
    if not clasificados and not normales:
        print("✅ Archivo sin eventos.\n")
        return True
    mostrar_dashboard(clasificados, normales)
    return generar_reporte(clasificados, normales)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clasificador de eventos de seguridad")
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log")
    args = parser.parse_args()
    ejecutar_clasificacion(args.log)