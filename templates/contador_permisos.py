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


def leer_cambios_permisos(ruta_logs):
    cambios_permisos = Counter()
    archivos_modificados = []
    
    try:
        with open(ruta_logs, "r") as archivo:
            for linea in archivo:
                if "CHMOD" in linea.upper() or "PERMISSION_CHANGE" in linea.upper():
                    archivos_modificados.append(linea.strip())
                    try:
                        if "usuario=" in linea:
                            usuario = linea.split("usuario=")[1].split()[0]
                            cambios_permisos[usuario] += 1
                    except (IndexError, ValueError):
                        pass
    
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None, None
    except PermissionError:
        print(f"❌ Error: Sin permisos para leer '{ruta_logs}'")
        return None, None
    
    return cambios_permisos, archivos_modificados


def mostrar_dashboard_consola(cambios_permisos, archivos_modificados):
    print("\n" + "=" * 60)
    print("📊 AUDITORÍA: CAMBIOS DE PERMISOS")
    print("=" * 60 + "\n")
    
    total = sum(cambios_permisos.values())
    print(f"📈 Total de cambios: {total}\n")
    
    print("👥 Cambios por usuario:")
    for usuario, cantidad in cambios_permisos.most_common():
        porcentaje = (cantidad / total * 100) if total > 0 else 0
        print(f"   {usuario}: {cantidad} cambios ({porcentaje:.1f}%)")
    
    print(f"\n📋 Eventos: {len(archivos_modificados)}")
    print("=" * 60 + "\n")


def generar_reporte(cambios_permisos, archivos_modificados):
    crear_carpeta_reportes()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(f"{CARPETA_REPORTES}/auditoria_permisos.log", "a") as reporte:
            reporte.write("=" * 60 + "\n")
            reporte.write(f"[{timestamp}] AUDITORÍA: CAMBIOS DE PERMISOS\n")
            reporte.write("=" * 60 + "\n\n")
            
            total = sum(cambios_permisos.values())
            reporte.write(f"Total de cambios: {total}\n\n")
            
            reporte.write("Cambios por usuario:\n")
            for usuario, cantidad in cambios_permisos.most_common():
                porcentaje = (cantidad / total * 100) if total > 0 else 0
                reporte.write(f"  {usuario}: {cantidad} cambios ({porcentaje:.1f}%)\n")
            
            reporte.write("\nDetalles de eventos:\n")
            for evento in archivos_modificados:
                reporte.write(f"  {evento}\n")
            
            reporte.write("\n" + "=" * 60 + "\n\n")
        
        return True
    
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}")
        return False


# ==========================================
# 3. FLUJO PRINCIPAL
# ==========================================
def ejecutar_auditoria():
    print("\n🔍 Iniciando auditoría de cambios de permisos...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    cambios_permisos, archivos_modificados = leer_cambios_permisos(RUTA_LOGS)
    if cambios_permisos is None:
        return False
    
    if len(cambios_permisos) == 0:
        print("✅ Sin cambios de permisos detectados.\n")
        return True
    
    mostrar_dashboard_consola(cambios_permisos, archivos_modificados)
    
    if generar_reporte(cambios_permisos, archivos_modificados):
        print(f"📝 Reporte guardado en: {CARPETA_REPORTES}/auditoria_permisos.log\n")
        return True
    
    return False


# ==========================================
# 4. EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    ejecutar_auditoria()
