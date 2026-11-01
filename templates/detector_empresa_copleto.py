import os
from datetime import datetime

# ==========================================
# 1. CONFIGURACIÓN - ACÁ CAMBIAS LOS LÍMITES
# ==========================================
RUTA_A_MONITOREAR = "./carpetas_empresa"
UMBRAL_NO_AUTORIZADA = 20   # Si es de afuera, solo 20 MB
UMBRAL_AUTORIZADA = 100     # Si es de adentro, máximo 100 MB (ya no es ilimitado)
IPS_AUTORIZADAS = ["192.168.1.50", "192.168.1.100"]
CARPETA_ALERTAS = "alertas"

# ==========================================
# 2. FUNCIONES AUXILIARES
# ==========================================
def crear_carpeta_alertas():
    os.makedirs(CARPETA_ALERTAS, exist_ok=True)

def registrar_alerta(ip_usuario, mb_totales, tipo_alerta):
    crear_carpeta_alertas()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(f"{CARPETA_ALERTAS}/alerta_exfiltracion.log", "a") as reporte:
        reporte.write(
            f"[{timestamp}] {tipo_alerta}: IP {ip_usuario} movio {mb_totales:.2f} MB\n"
        )

def calcular_volumen_datos(ruta_target):
    bytes_totales = 0
    if not os.path.exists(ruta_target):
        os.makedirs(ruta_target, exist_ok=True)
        return 0
    for raiz, directorios, archivos in os.walk(ruta_target):
        for archivo in archivos:
            try:
                ruta_completa = os.path.join(raiz, archivo)
                bytes_totales += os.path.getsize(ruta_completa)
            except:
                pass
    return bytes_totales / (1024 * 1024)

# ==========================================
# 3. LÓGICA DEL DETECTOR - AHORA CON 2 LÍMITES
# ==========================================
def analizar_seguridad(ip_usuario, ruta_target=RUTA_A_MONITOREAR):
    print("\n--- INICIANDO ESCANEO ---\n")
    mb_totales = calcular_volumen_datos(ruta_target)
    print(f"IP: {ip_usuario} | Volumen: {mb_totales:.2f} MB\n")

    if ip_usuario in IPS_AUTORIZADAS:
        # Es de adentro, pero tampoco puede llevarse todo
        if mb_totales > UMBRAL_AUTORIZADA:
            print(f"⚠️ ALERTA AMARILLA: IP autorizada {ip_usuario} pero volumen muy alto ({mb_totales:.2f} > {UMBRAL_AUTORIZADA})")
            registrar_alerta(ip_usuario, mb_totales, "ALERTA AMARILLA")
            return False
        else:
            print(f"✅ IP autorizada, volumen OK")
            return True
    else:
        # Es de afuera, límite más estricto
        if mb_totales > UMBRAL_NO_AUTORIZADA:
            print(f"🚨 ALERTA ROJA: IP NO autorizada {ip_usuario} supero {UMBRAL_NO_AUTORIZADA} MB")
            registrar_alerta(ip_usuario, mb_totales, "ALERTA ROJA")
            return False
        else:
            print(f"✅ IP no autorizada pero volumen pequeño, OK")
            return True

# ==========================================
# 4. PRUEBA
# ==========================================
if __name__ == "__main__":
    analizar_seguridad("192.168.1.50")
    analizar_seguridad("10.0.0.99")