#!/usr/bin/env python3
import os
from collections import Counter
from datetime import datetime

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"
UMBRAL = 3  # Máximo de intentos permitidos


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


def leer_intentos_fallidos(ruta_logs):
    intentos_usuario = Counter()
    total_fallos = 0
    
    try:
        with open(ruta_logs, "r") as archivo:
            for linea in archivo:
                if "INCORRECTA" in linea.upper() or "DENIED" in linea.upper():
                    total_fallos += 1
                    try:
                        if "usuario=" in linea:
                            usuario = linea.split("usuario=")[1].split()[0]
                            intentos_usuario[usuario] += 1
                    except (IndexError, ValueError):
                        pass
    
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None, None
    except PermissionError:
        print(f"❌ Error: Sin permisos para leer '{ruta_logs}'")
        return None, None
    
    return intentos_usuario, total_fallos


def mostrar_dashboard_consola(intentos_usuario, total_fallos):
    print("\n" + "=" * 60)
    print("📊 DETECCIÓN DE FUERZA BRUTA")
    print("=" * 60 + "\n")
    
    print(f"📈 Total de fallos: {total_fallos}\n")
    print(f"👥 Usuarios afectados: {len(intentos_usuario)}\n")
    
    print("Intentos fallidos por usuario:")
    for usuario, cantidad in intentos_usuario.most_common():
        porcentaje = (cantidad / total_fallos * 100) if total_fallos > 0 else 0
        estado = "🚨 CRÍTICO" if cantidad >= UMBRAL else "⚠️  Observar"
        print(f"   {usuario}: {cantidad} intentos ({porcentaje:.1f}%) {estado}")
    
    print("\n" + "=" * 60 + "\n")


def generar_reporte(intentos_usuario, total_fallos):
    crear_carpeta_reportes()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(f"{CARPETA_REPORTES}/deteccion_fuerza_bruta.log", "a") as reporte:
            reporte.write("=" * 60 + "\n")
            reporte.write(f"[{timestamp}] DETECCIÓN DE FUERZA BRUTA\n")
            reporte.write("=" * 60 + "\n\n")
            
            reporte.write(f"Total de fallos: {total_fallos}\n")
            reporte.write(f"Usuarios afectados: {len(intentos_usuario)}\n\n")
            
            reporte.write("Usuarios con actividad sospechosa:\n")
            for usuario, cantidad in intentos_usuario.most_common():
                if cantidad >= UMBRAL:
                    porcentaje = (cantidad / total_fallos * 100) if total_fallos > 0 else 0
                    reporte.write(f"  🚨 [CRÍTICO] {usuario}: {cantidad} intentos ({porcentaje:.1f}%)\n")
            
            reporte.write("\nTodos los usuarios monitoreados:\n")
            for usuario, cantidad in intentos_usuario.most_common():
                porcentaje = (cantidad / total_fallos * 100) if total_fallos > 0 else 0
                reporte.write(f"  {usuario}: {cantidad} intentos ({porcentaje:.1f}%)\n")
            
            reporte.write("\n" + "=" * 60 + "\n\n")
        
        return True
    
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}")
        return False


# ==========================================
# 3. FLUJO PRINCIPAL
# ==========================================
def ejecutar_deteccion():
    print("\n🔍 Iniciando detección de intentos de fuerza bruta...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    intentos_usuario, total_fallos = leer_intentos_fallidos(RUTA_LOGS)
    if intentos_usuario is None:
        return False
    
    if total_fallos == 0:
        print("✅ Sin intentos fallidos detectados.\n")
        return True
    
    mostrar_dashboard_consola(intentos_usuario, total_fallos)
    
    if generar_reporte(intentos_usuario, total_fallos):
        print(f"📝 Reporte guardado en: {CARPETA_REPORTES}/deteccion_fuerza_bruta.log\n")
        return True
    
    return False


# ==========================================
# 4. EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    ejecutar_deteccion()
