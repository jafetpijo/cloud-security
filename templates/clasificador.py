#!/usr/bin/env python3
import os
import argparse
from datetime import datetime

RUTA_LOGS = "logs/servidor_aws.log"
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

def clasificar_eventos(ruta_logs):
    crear_carpeta_reportes()
    
    archivo_criticos = f"{CARPETA_REPORTES}/alertas_criticas.log"
    archivo_normales = f"{CARPETA_REPORTES}/eventos_normales.log"
    
    contadores = {"criticos": 0, "normales": 0, "errores_lectura": 0}
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(ruta_logs, "r") as origen, \
             open(archivo_criticos, "a") as alertas, \
             open(archivo_normales, "a") as normales:
            
            alertas.write(f"\n[{timestamp}] === CLASIFICACIÓN DE EVENTOS CRÍTICOS ===\n")
            normales.write(f"\n[{timestamp}] === CLASIFICACIÓN DE EVENTOS NORMALES ===\n")
            
            for linea in origen:
                try:
                    linea_limpia = linea.strip()
                    if not linea_limpia:
                        continue
                    if "ERROR" in linea_limpia.upper() or "CRITICAL" in linea_limpia.upper():
                        alertas.write(f"[{timestamp}] 🚨 {linea_limpia}\n")
                        contadores["criticos"] += 1
                    else:
                        normales.write(f"[{timestamp}] {linea_limpia}\n")
                        contadores["normales"] += 1
                except Exception:
                    contadores["errores_lectura"] += 1
        
        return contadores, archivo_criticos, archivo_normales
    
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None, None, None
    except PermissionError:
        print("❌ Error: Sin permisos de lectura o escritura")
        return None, None, None

def mostrar_dashboard_consola(contadores):
    print("\n" + "=" * 60)
    print("📊 CLASIFICACIÓN DE EVENTOS")
    print("=" * 60 + "\n")
    total = contadores["criticos"] + contadores["normales"]
    print(f"📈 Total de eventos: {total}\n")
    if total > 0:
        pc = (contadores["criticos"] / total * 100)
        pn = (contadores["normales"] / total * 100)
        print(f"🚨 Eventos críticos:  {contadores['criticos']} ({pc:.1f}%)")
        print(f"✅ Eventos normales:  {contadores['normales']} ({pn:.1f}%)")
    else:
        print("🚨 Eventos críticos:  0")
        print("✅ Eventos normales:  0")
    if contadores["errores_lectura"] > 0:
        print(f"⚠️  Errores de lectura: {contadores['errores_lectura']}")
    print("\n" + "=" * 60 + "\n")

def ejecutar_clasificacion(ruta_logs=None):
    ruta = ruta_logs or RUTA_LOGS
    print("\n🔍 Iniciando clasificación de eventos...\n")
    if not validar_archivo_logs(ruta):
        return False
    contadores, f_crit, f_norm = clasificar_eventos(ruta)
    if contadores is None:
        return False
    mostrar_dashboard_consola(contadores)
    print(f"📝 Archivos generados:")
    print(f"   🚨 {f_crit}")
    print(f"   ✅ {f_norm}\n")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clasificador de eventos críticos")
    parser.add_argument("--log", default=RUTA_LOGS, help="Ruta del log a analizar")
    args = parser.parse_args()
    ejecutar_clasificacion(args.log)
