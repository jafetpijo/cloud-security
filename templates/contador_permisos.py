#!/usr/bin/env python3
import os
import re
import argparse
from collections import Counter
from datetime import datetime

RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"

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

def leer_cambios_permisos(ruta_logs):
    cambios = Counter()
    eventos = []
    patron_usuario = re.compile(r'(?:usuario|user)=([a-zA-Z0-9_.-]+)', re.I)
    
    try:
        with open(ruta_logs, "r", errors="ignore") as f:
            for linea in f:
                if "CHMOD" in linea.upper() or "PERMISSION" in linea.upper():
                    eventos.append(linea.strip())
                    m = patron_usuario.search(linea)
                    if m:
                        cambios[m.group(1)] += 1
                    else:
                        cambios["desconocido"] += 1
    except FileNotFoundError:
        print(f"❌ No se encontró '{ruta_logs}'")
        return None, None
    return cambios, eventos

def mostrar_dashboard(cambios, eventos):
    print("\n" + "="*60)
    print("📊 AUDITORÍA: CAMBIOS DE PERMISOS")
    print("="*60 + "\n")
    total = sum(cambios.values())
    print(f"📈 Total de cambios: {total}\n")
    print("👥 Por usuario:")
    for user, cant in cambios.most_common():
        pct = (cant/total*100) if total else 0
        flag = " 🚨" if user != "admin" and user != "root" and cant > 3 else ""
        print(f"   {user}: {cant} ({pct:.1f}%){flag}")
    print(f"\n📋 Eventos capturados: {len(eventos)}")
    print("="*60 + "\n")

def generar_reporte(cambios, eventos):
    crear_carpeta_reportes()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ruta_out = f"{CARPETA_REPORTES}/auditoria_permisos.log"
    with open(ruta_out, "a") as r:
        r.write(f"\n[{ts}] AUDITORÍA PERMISOS - Total: {sum(cambios.values())}\n")
        for u, c in cambios.most_common():
            r.write(f"  {u}: {c}\n")
        for ev in eventos:
            r.write(f"  -> {ev}\n")
    print(f"📝 Reporte guardado en: {ruta_out}\n")
    return True

def ejecutar_auditoria(ruta_logs):
    print("\n🔍 Iniciando auditoría de permisos...\n")
    if not validar_archivo_logs(ruta_logs):
        return False
    cambios, eventos = leer_cambios_permisos(ruta_logs)
    if cambios is None:
        return False
    if not cambios:
        print("✅ Sin cambios de permisos detectados.\n")
        return True
    mostrar_dashboard(cambios, eventos)
    generar_reporte(cambios, eventos)
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditoría de cambios de permisos")
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log")
    args = parser.parse_args()
    ejecutar_auditoria(args.log)