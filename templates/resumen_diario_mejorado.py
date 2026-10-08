#!/usr/bin/env python3
import os
from datetime import datetime
from collections import Counter

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"  # Archivo de logs a analizar
RUTA_REPORTE = "reportes/resumen_diario_{fecha_hoy}.txt"  # Template de reporte
CARPETA_REPORTES = "reportes"  # Carpeta donde guardar


# ==========================================
# 2. FUNCIONES AUXILIARES
# ==========================================
def crear_carpeta_reportes():
    """Crea la carpeta de reportes si no existe."""
    os.makedirs(CARPETA_REPORTES, exist_ok=True)


def validar_archivo_logs(ruta):
    """Verifica si el archivo de logs existe."""
    if not os.path.exists(ruta):
        print(f"❌ Error: No se encontró el archivo de logs en '{ruta}'")
        print(f"   Crea el archivo o cambia la ruta en la configuración.")
        return False
    
    if os.path.getsize(ruta) == 0:
        print(f"⚠️  Advertencia: El archivo '{ruta}' está vacío.")
        return False
    
    return True


def leer_y_analizar_logs(ruta_logs):
    """Lee el archivo de logs y extrae estadísticas."""
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
                
                # Contar tipos de eventos
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
                
                # Extraer IPs (formato: "IP: xxx.xxx.xxx.xxx")
                if "IP:" in linea:
                    try:
                        ip = linea.split("IP:")[1].split()[0]
                        estadisticas["ips_unicas"].add(ip)
                    except IndexError:
                        pass
                
                # Extraer usuarios (formato: "Usuario: nombre")
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
    """Calcula porcentajes de cada tipo de evento."""
    total = estadisticas["total_eventos"]
    if total == 0:
        return {}
    
    return {
        "errores": (estadisticas["errores"] / total) * 100,
        "alertas": (estadisticas["alertas"] / total) * 100,
        "accesos_exitosos": (estadisticas["accesos_exitosos"] / total) * 100,
    }


def mostrar_dashboard(estadisticas, porcentajes):
    """Muestra un dashboard bonito en la consola."""
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


def generar_reporte(estadisticas, porcentajes, ruta_reporte):
    """Genera y guarda un reporte en archivo."""
    crear_carpeta_reportes()
    
    fecha_hoy = datetime.now().strftime("%Y-%m-%d")
    ruta_final = ruta_reporte.format(fecha_hoy=fecha_hoy)
    
    try:
        with open(ruta_final, "w") as reporte:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            reporte.write("=" * 60 + "\n")
            reporte.write("RESUMEN DIARIO DE SEGURIDAD\n")
            reporte.write("=" * 60 + "\n\n")
            
            reporte.write(f"Fecha: {timestamp}\n\n")
            
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
            
            reporte.write("\n" + "=" * 60 + "\n")
        
        print(f"✅ Reporte guardado en: {ruta_final}\n")
        return True
    
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}\n")
        return False


# ==========================================
# 3. FLUJO PRINCIPAL
# ==========================================
def ejecutar_resumen():
    """Ejecuta el análisis completo."""
    print("\n🔍 Iniciando análisis de logs...\n")
    
    # Paso 1: Validar archivo
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    # Paso 2: Analizar logs
    print(f"📂 Leyendo: {RUTA_LOGS}")
    estadisticas = leer_y_analizar_logs(RUTA_LOGS)
    
    if estadisticas is None:
        return False
    
    # Paso 3: Calcular porcentajes
    porcentajes = calcular_porcentajes(estadisticas)
    
    # Paso 4: Mostrar dashboard
    mostrar_dashboard(estadisticas, porcentajes)
    
    # Paso 5: Generar reporte
    generar_reporte(estadisticas, porcentajes, RUTA_REPORTE)
    
    return True


# ==========================================
# 4. EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    ejecutar_resumen()