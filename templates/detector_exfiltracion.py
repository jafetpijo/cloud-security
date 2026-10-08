#!/usr/bin/env python3
import os
from datetime import datetime

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"
UMBRAL_MB = 100
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


def leer_descargas(ruta_logs):
    descargas_por_usuario = {}
    
    try:
        with open(ruta_logs, "r") as archivo:
            for linea in archivo:
                if "DOWNLOAD" in linea.upper():
                    try:
                        usuario = linea.split("usuario=")[1].split()[0]
                        tamaño_str = linea.split("tamaño=")[1].split()[0]
                        tamaño_mb = int(tamaño_str) / (1024 * 1024)
                        
                        if usuario not in descargas_por_usuario:
                            descargas_por_usuario[usuario] = 0
                        descargas_por_usuario[usuario] += tamaño_mb
                    
                    except (IndexError, ValueError):
                        pass
    
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None
    except PermissionError:
        print(f"❌ Error: Sin permisos para leer '{ruta_logs}'")
        return None
    
    return descargas_por_usuario


def generar_alerta(descargas_por_usuario, umbral):
    crear_carpeta_reportes()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(f"{CARPETA_REPORTES}/alerta_exfiltracion.log", "a") as reporte:
            reporte.write("=" * 60 + "\n")
            reporte.write(f"[{timestamp}] ANÁLISIS DE EXFILTRACIÓN\n")
            reporte.write("=" * 60 + "\n\n")
            
            hay_alertas = False
            for usuario, total_mb in descargas_por_usuario.items():
                if total_mb > umbral:
                    hay_alertas = True
                    reporte.write(f"🚨 [CRÍTICO] {usuario}: {total_mb:.2f}MB (límite: {umbral}MB)\n")
                else:
                    reporte.write(f"✅ {usuario}: {total_mb:.2f}MB (OK)\n")
            
            reporte.write("\n" + "=" * 60 + "\n\n")
        
        return hay_alertas
    
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}")
        return None


def mostrar_resumen_consola(descargas_por_usuario, umbral):
    print("\n" + "=" * 60)
    print("📊 ANÁLISIS DE DESCARGAS SOSPECHOSAS")
    print("=" * 60 + "\n")
    
    for usuario, total_mb in sorted(descargas_por_usuario.items()):
        if total_mb > umbral:
            print(f"🚨 {usuario}: {total_mb:.2f}MB (CRÍTICO)")
        else:
            print(f"✅ {usuario}: {total_mb:.2f}MB")
    
    print("\n" + "=" * 60 + "\n")


def ejecutar_analisis():
    print("\n🔍 Iniciando análisis de descargas...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    descargas_por_usuario = leer_descargas(RUTA_LOGS)
    if descargas_por_usuario is None:
        return False
    
    mostrar_resumen_consola(descargas_por_usuario, UMBRAL_MB)
    
    hay_alertas = generar_alerta(descargas_por_usuario, UMBRAL_MB)
    
    if hay_alertas:
        print(f"⚠️  Se detectaron descargas sospechosas.")
        print(f"📝 Reporte guardado en: {CARPETA_REPORTES}/alerta_exfiltracion.log\n")
    else:
        print(f"✅ Todas las descargas están dentro del límite.\n")
    
    return True


if __name__ == "__main__":
    ejecutar_analisis()
