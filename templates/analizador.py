#!/usr/bin/env python3
import os
from collections import Counter
from datetime import datetime

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"


# ==========================================
# 2. FUNCIONES AUXILIARES
# ==========================================
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
                    try:
                        if "IP:" in linea:
                            ip = linea.split("IP:")[1].split()[0]
                            ips[ip] += 1
                    except (IndexError, ValueError):
                        pass
    
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


# ==========================================
# 3. FLUJO PRINCIPAL
# ==========================================
def ejecutar_analisis():
    print("\n🔍 Iniciando análisis de errores por IP...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    ips, errores_totales = leer_errores_por_ip(RUTA_LOGS)
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


# ==========================================
# 4. EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    ejecutar_analisis()
