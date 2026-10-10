#!/usr/bin/env python3
import os
from datetime import datetime
from collections import Counter

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
        print(f"❌ Error: No se encontró el archivo de logs en '{ruta}'")
        return False
    
    if os.path.getsize(ruta) == 0:
        print(f"⚠️  Advertencia: El archivo '{ruta}' está vacío.")
        return False
    
    return True


def leer_y_analizar_logs(ruta_logs):
    estadisticas = {
        "total_eventos": 0,
        "errores": 0,
        "alertas": 0,
        "accesos_exitosos": 0,
        "ips_unicas": set(),
        "usuarios_unicos": set(),
        "eventos_por_tipo": Counter(),
    }
    
    try:
        with open(ruta_logs, "r") as archivo:
            for linea in archivo:
                linea = linea.strip()
                if not linea:
                    continue
                
                estadisticas["total_eventos"] += 1
                
                if "ERROR" in linea.upper():
                    estadisticas["errores"] += 1
                    estadisticas["eventos_por_tipo"]["ERROR"] += 1
                elif "ALERT" in linea.upper():
                    estadisticas["alertas"] += 1
                    estadisticas["eventos_por_tipo"]["ALERT"] += 1
                elif "OK" in linea.upper():
                    estadisticas["accesos_exitosos"] += 1
                    estadisticas["eventos_por_tipo"]["OK"] += 1
                else:
                    estadisticas["eventos_por_tipo"]["OTRO"] += 1
                
                if "IP:" in linea:
                    try:
                        ip = linea.split("IP:")[1].split()[0]
                        estadisticas["ips_unicas"].add(ip)
                    except IndexError:
                        pass
                
                if "Usuario:" in linea:
                    try:
                        usuario = linea.split("Usuario:")[1].split()[0]
                        estadisticas["usuarios_unicos"].add(usuario)
                    except IndexError:
                        pass
        
        return estadisticas
    
    except PermissionError:
        print(f"❌ Error: No tienes permisos para leer '{ruta_logs}'")
        return None
    except Exception as e:
        print(f"❌ Error al leer logs: {e}")
        return None


def calcular_porcentajes(estadisticas):
    total = estadisticas["total_eventos"]
    if total == 0:
        return {}
    
    return {
        "errores": (estadisticas["errores"] / total) * 100,
        "alertas": (estadisticas["alertas"] / total) * 100,
        "accesos_exitosos": (estadisticas["accesos_exitosos"] / total) * 100,
    }


def mostrar_dashboard(estadisticas, porcentajes):
    print("\n" + "=" * 60)
    print("📊 RESUMEN DIARIO DE SEGURIDAD")
    print("=" * 60 + "\n")
    
    print(f"⏰ Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"📈 EVENTOS TOTALES: {estadisticas['total_eventos']}\n")
    
    print("Desglose por tipo:")
    print(f"  ❌ Errores:          {estadisticas['errores']:>4} ({porcentajes.get('errores', 0):>5.1f}%)")
    print(f"  ⚠️  Alertas:          {estadisticas['alertas']:>4} ({porcentajes.get('alertas', 0):>5.1f}%)")
    print(f"  ✅ Accesos exitosos: {estadisticas['accesos_exitosos']:>4} ({porcentajes.get('accesos_exitosos', 0):>5.1f}%)")
    print(f"  📌 Otros:            {estadisticas['eventos_por_tipo']['OTRO']:>4}\n")
    
    print(f"👥 Usuarios únicos: {len(estadisticas['usuarios_unicos'])}")
    print(f"🌐 IPs únicas: {len(estadisticas['ips_unicas'])}\n")
    
    print("=" * 60 + "\n")


def generar_reporte(estadisticas, porcentajes):
    crear_carpeta_reportes()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(f"{CARPETA_REPORTES}/resumen_diario.log", "a") as reporte:
            reporte.write("=" * 60 + "\n")
            reporte.write(f"[{timestamp}] RESUMEN DIARIO DE SEGURIDAD\n")
            reporte.write("=" * 60 + "\n\n")
            
            reporte.write(f"EVENTOS TOTALES: {estadisticas['total_eventos']}\n\n")
            
            reporte.write("Desglose:\n")
            reporte.write(f"  Errores: {estadisticas['errores']} ({porcentajes.get('errores', 0):.1f}%)\n")
            reporte.write(f"  Alertas: {estadisticas['alertas']} ({porcentajes.get('alertas', 0):.1f}%)\n")
            reporte.write(f"  Accesos exitosos: {estadisticas['accesos_exitosos']} ({porcentajes.get('accesos_exitosos', 0):.1f}%)\n")
            reporte.write(f"  Otros: {estadisticas['eventos_por_tipo']['OTRO']}\n\n")
            
            reporte.write(f"Usuarios únicos: {len(estadisticas['usuarios_unicos'])}\n")
            reporte.write(f"IPs únicas: {len(estadisticas['ips_unicas'])}\n\n")
            
            if estadisticas['ips_unicas']:
                reporte.write("IPs detectadas:\n")
                for ip in sorted(estadisticas['ips_unicas']):
                    reporte.write(f"  - {ip}\n")
                reporte.write("\n")
            
            if estadisticas['usuarios_unicos']:
                reporte.write("Usuarios detectados:\n")
                for usuario in sorted(estadisticas['usuarios_unicos']):
                    reporte.write(f"  - {usuario}\n")
            
            reporte.write("\n" + "=" * 60 + "\n\n")
        
        print(f"✅ Reporte guardado en: {CARPETA_REPORTES}/resumen_diario.log\n")
        return True
    
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}\n")
        return False


def ejecutar_resumen():
    print("\n🔍 Iniciando análisis de logs...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    print(f"📂 Leyendo: {RUTA_LOGS}")
    estadisticas = leer_y_analizar_logs(RUTA_LOGS)
    
    if estadisticas is None:
        return False
    
    porcentajes = calcular_porcentajes(estadisticas)
    
    mostrar_dashboard(estadisticas, porcentajes)
    
    generar_reporte(estadisticas, porcentajes)
    
    return True


if __name__ == "__main__":
    ejecutar_resumen()
