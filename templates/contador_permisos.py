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
USUARIOS_ADMIN = ["admin", "root"]
PERMISOS_PELIGROSOS = ["777", "666"]   # cualquiera puede escribir
UMBRAL_CAMBIOS = 3                     # cambios permitidos dentro de la ventana
VENTANA_MINUTOS = 10                   # tamaño del tramo

# Patterns to search in each line
PATRON_USUARIO = re.compile(r"(?:usuario|user)=(\w+)", re.I)
PATRON_FECHA = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
PATRON_CHMOD = re.compile(r"chmod\s+(\d{3})", re.I)

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

def leer_cambios(ruta_logs):
    """Devuelve un diccionario: usuario -> lista de cambios (fecha, permiso)."""
    cambios = {}
    try:
        with open(ruta_logs, "r", errors="ignore") as f:
            for linea in f:
                m_chmod = PATRON_CHMOD.search(linea)
                if not m_chmod:
                    continue
                m_user = PATRON_USUARIO.search(linea)
                m_fecha = PATRON_FECHA.search(linea)

                usuario = m_user.group(1).lower() if m_user else "desconocido"
                permiso = m_chmod.group(1)
                fecha = None
                if m_fecha:
                    fecha = datetime.strptime(m_fecha.group(1), "%Y-%m-%d %H:%M:%S")

                cambios.setdefault(usuario, []).append((fecha, permiso))
    except FileNotFoundError:
        print(f"❌ No se encontró '{ruta_logs}'")
        return None
    except PermissionError:
        print(f"❌ Sin permisos para leer '{ruta_logs}'")
        return None
    return cambios

def max_en_ventana(fechas, minutos):
    """Cuenta el máximo de cambios dentro de cualquier tramo de 'minutos'."""
    fechas = sorted(f for f in fechas if f is not None)
    ventana = timedelta(minutes=minutos)
    maximo = 0
    for i in range(len(fechas)):
        # cuenta cuántos cambios caben desde fechas[i] hasta fechas[i] + ventana
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
def analizar(cambios):
    print("\n" + "=" * 60)
    print("📊 AUDITORÍA DE CAMBIOS DE PERMISOS")
    print("=" * 60 + "\n")
    alertas = []

    for usuario, lista in cambios.items():
        fechas = [fecha for fecha, _ in lista]
        peligrosos = [permiso for _, permiso in lista if permiso in PERMISOS_PELIGROSOS]
        maximo = max_en_ventana(fechas, VENTANA_MINUTOS)
        es_admin = usuario in USUARIOS_ADMIN

        etiqueta = " [admin]" if es_admin else ""
        print(f"👤 {usuario}{etiqueta}: {len(lista)} cambios | "
              f"máx {maximo} en {VENTANA_MINUTOS} min")

        if peligrosos:
            print(f"   🚨 Permisos peligrosos: {', '.join(peligrosos)}")
            alertas.append(f"{usuario}: permisos peligrosos {peligrosos}")
        if maximo > UMBRAL_CAMBIOS:
            print(f"   ⚠️ Demasiados cambios en poco tiempo ({maximo} > {UMBRAL_CAMBIOS})")
            alertas.append(f"{usuario}: {maximo} cambios en {VENTANA_MINUTOS} min")

    print(f"\n🔔 Total de alertas: {len(alertas)}")
    print("=" * 60 + "\n")
    return alertas

def generar_reporte(alertas):
    crear_carpeta_reportes()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_out = f"{CARPETA_REPORTES}/auditoria_permisos.log"
    try:
        with open(ruta_out, "a") as r:
            r.write(f"\n[{ts}] AUDITORÍA DE PERMISOS - Alertas: {len(alertas)}\n")
            for alerta in alertas:
                r.write(f"  -> {alerta}\n")
        print(f"📝 Reporte guardado en: {ruta_out}\n")
        return True
    except (PermissionError, OSError) as e:
        print(f"❌ Error al generar reporte: {e}")
        return False

# ==========================================
# 4. EXECUTION
# ==========================================
def ejecutar_auditoria(ruta_logs):
    print("\n🔍 Iniciando auditoría de permisos...\n")
    if not validar_archivo_logs(ruta_logs):
        return False
    cambios = leer_cambios(ruta_logs)
    if cambios is None:
        return False
    if not cambios:
        print("✅ Sin cambios de permisos detectados.\n")
        return True
    alertas = analizar(cambios)
    return generar_reporte(alertas)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditoría de cambios de permisos")
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log")
    args = parser.parse_args()
    ejecutar_auditoria(args.log)