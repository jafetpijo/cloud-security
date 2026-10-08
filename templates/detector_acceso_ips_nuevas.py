#!/usr/bin/env python3
import os
from collections import defaultdict
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


def leer_accesos_nuevos(ruta_logs):
    ips_por_usuario = defaultdict(set)
    accesos_nuevos = []
    
    try:
        with open(ruta_logs, "r") as archivo:
            for linea in archivo:
                if "LOGIN" in linea.upper() and "OK" in linea.upper():
                    try:
                        if "usuario=" in linea and "ip=" in linea:
                            usuario = linea.split("usuario=")[1].split()[0]
                            ip = linea.split("ip=")[1].split()[0]
                            
                            if ip not in ips_por_usuario[usuario]:
                                ips_por_usuario[usuario].add(ip)
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                accesos_nuevos.append((usuario, ip, timestamp, linea))
                    
                    except (IndexError, ValueError):
                        pass
    
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None
    except PermissionError:
        print(f"❌ Error: Sin permisos para leer '{ruta_logs}'")
        return None
    
    return accesos_nuevos


def mostrar_dashboard_consola(accesos_nuevos):
    print("\n" + "=" * 60)
    print("📊 ACCESOS DESDE IPs NUEVAS")
    print("=" * 60 + "\n")
    
    usuarios_afectados = {}
    for usuario, ip, timestamp, _ in accesos_nuevos:
        if usuario not in usuarios_afectados:
            usuarios_afectados[usuario] = []
        usuarios_afectados[usuario].append(ip)
    
    for usuario, ips in sorted(usuarios_afectados.items()):
        print(f"👤 {usuario}")
        for ip in ips:
            print(f"   └─ 🌐 {ip}")
    
    print(f"\n⚠️  Total de accesos anómalos: {len(accesos_nuevos)}\n")
    print("=" * 60 + "\n")


def generar_reporte(accesos_nuevos):
    crear_carpeta_reportes()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(f"{CARPETA_REPORTES}/accesos_anomalos.log", "a") as reporte:
            reporte.write("=" * 60 + "\n")
            reporte.write(f"[{timestamp}] DETECCIÓN DE ACCESOS DESDE IPs NUEVAS\n")
            reporte.write("=" * 60 + "\n\n")
            
            for usuario, ip, ts, evento in accesos_nuevos:
                reporte.write(f"[{ts}] [ANOMALÍA] Usuario: {usuario} | IP: {ip}\n")
            
            reporte.write("\n" + "=" * 60 + "\n\n")
        
        return True
    
    except Exception as e:
        print(f"❌ Error al generar reporte: {e}")
        return False


# ==========================================
# 3. FLUJO PRINCIPAL
# ==========================================
def ejecutar_deteccion():
    print("\n🔍 Iniciando detección de accesos desde IPs nuevas...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    accesos_nuevos = leer_accesos_nuevos(RUTA_LOGS)
    if accesos_nuevos is None:
        return False
    
    if len(accesos_nuevos) == 0:
        print("✅ Sin accesos anómalos detectados.\n")
        return True
    
    mostrar_dashboard_consola(accesos_nuevos)
    
    if generar_reporte(accesos_nuevos):
        print(f"📝 Reporte guardado en: {CARPETA_REPORTES}/accesos_anomalos.log\n")
        return True
    
    return False


# ==========================================
# 4. EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    ejecutar_deteccion()
