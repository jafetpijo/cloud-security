#!/usr/bin/env python3
from datetime import datetime

# 1. CONTADORES
estadisticas = {
    "total_eventos": 0,
    "errores": 0,
    "alertas": 0,
    "accesos_exitosos": 0
}

# 2. LECTURA Y ANÁLISIS
try:
    with open("logs/servidor_aws.log") as archivo:
        for linea in archivo:
            estadisticas["total_eventos"] += 1
            
            if "ERROR" in linea.upper():
                estadisticas["errores"] += 1
            elif "ALERT" in linea.upper():
                estadisticas["alertas"] += 1
            elif "OK" in linea.upper():
                estadisticas["accesos_exitosos"] += 1
except FileNotFoundError:
    print("[!] Error: No se encontró el archivo de log en 'logs/servidor_aws.log'")

# 3. REPORTE DIARIO
fecha_hoy = datetime.now().strftime("%Y-%m-%d")
ruta_reporte = f"reportes/resumen_diario_{fecha_hoy}.txt"

with open(ruta_reporte, "w") as reporte:
    reporte.write(f"=== RESUMEN DE SEGURIDAD {fecha_hoy} ===\n\n")
    reporte.write(f"Total de eventos: {estadisticas['total_eventos']}\n")
    reporte.write(f"Errores: {estadisticas['errores']}\n")
    reporte.write(f"Alertas: {estadisticas['alertas']}\n")
    reporte.write(f"Accesos exitosos: {estadisticas['accesos_exitosos']}\n")

print("[+] Resumen diario generado.")
print(f"[+] Archivo generado: '{ruta_reporte}'")