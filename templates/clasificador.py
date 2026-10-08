#!/usr/bin/env python3
import os
from datetime import datetime

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
RUTA_LOGS = "logs/servidor_aws.log"
CARPETA_REPORTES = "reportes"
ARCHIVO_CRITICOS = f"{CARPETA_REPORTES}/alertas_criticas.log"
ARCHIVO_NORMALES = f"{CARPETA_REPORTES}/eventos_normales.log"


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


def clasificar_eventos(ruta_logs):
    crear_carpeta_reportes()
    
    contadores = {
        "criticos": 0,
        "normales": 0,
        "errores_lectura": 0
    }
    
    try:
        with open(ruta_logs, "r") as archivo_origen, \
             open(ARCHIVO_CRITICOS, "a") as archivo_alertas, \
             open(ARCHIVO_NORMALES, "a") as archivo_normal:
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Encabezado para los logs
            archivo_alertas.write(f"\n[{timestamp}] === CLASIFICACIÓN DE EVENTOS CRÍTICOS ===\n")
            archivo_normal.write(f"\n[{timestamp}] === CLASIFICACIÓN DE EVENTOS NORMALES ===\n")
            
            for linea in archivo_origen:
                try:
                    linea = linea.strip()
                    if not linea:
                        continue
                    
                    if "ERROR" in linea.upper() or "CRITICAL" in linea.upper():
                        archivo_alertas.write(f"[{timestamp}] 🚨 {linea}\n")
                        contadores["criticos"] += 1
                    else:
                        archivo_normal.write(f"[{timestamp}] {linea}\n")
                        contadores["normales"] += 1
                
                except Exception as e:
                    contadores["errores_lectura"] += 1
        
        return contadores
    
    except FileNotFoundError:
        print(f"❌ Error: No se encontró '{ruta_logs}'")
        return None
    except PermissionError:
        print(f"❌ Error: Sin permisos para leer '{ruta_logs}'")
        return None


def mostrar_dashboard_consola(contadores):
    print("\n" + "=" * 60)
    print("📊 CLASIFICACIÓN DE EVENTOS")
    print("=" * 60 + "\n")
    
    total = contadores["criticos"] + contadores["normales"]
    
    print(f"📈 Total de eventos: {total}\n")
    
    if total > 0:
        porcentaje_criticos = (contadores["criticos"] / total * 100)
        porcentaje_normales = (contadores["normales"] / total * 100)
        
        print(f"🚨 Eventos críticos:  {contadores['criticos']} ({porcentaje_criticos:.1f}%)")
        print(f"✅ Eventos normales:  {contadores['normales']} ({porcentaje_normales:.1f}%)")
    else:
        print(f"🚨 Eventos críticos:  0")
        print(f"✅ Eventos normales:  0")
    
    if contadores["errores_lectura"] > 0:
        print(f"⚠️  Errores de lectura: {contadores['errores_lectura']}")
    
    print("\n" + "=" * 60 + "\n")


# ==========================================
# 3. FLUJO PRINCIPAL
# ==========================================
def ejecutar_clasificacion():
    print("\n🔍 Iniciando clasificación de eventos...\n")
    
    if not validar_archivo_logs(RUTA_LOGS):
        return False
    
    contadores = clasificar_eventos(RUTA_LOGS)
    if contadores is None:
        return False
    
    mostrar_dashboard_consola(contadores)
    
    print(f"📝 Archivos generados:")
    print(f"   ✅ {ARCHIVO_CRITICOS}")
    print(f"   ✅ {ARCHIVO_NORMALES}\n")
    
    return True


# ==========================================
# 4. EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    ejecutar_clasificacion()
