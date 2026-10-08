import os

from datetime import datetime



# ==========================================

# 1. CONFIGURACIÓN (CAMBIAR SEGÚN LA EMPRESA)

# ==========================================

RUTA_A_MONITOREAR = "./carpetas_empresa" # La carpeta que vas a vigilar

UMBRAL_MB = 20 # Límite máximo permitido en Megabytes

IPS_AUTORIZADAS = [

"192.168.1.50",

"192.168.1.100",

] # Direcciones IP seguras

CARPETA_ALERTAS = "alertas" # Donde guardar los reportes





# ==========================================

# 2. FUNCIONES AUXILIARES

# ==========================================

def crear_carpeta_alertas():

"""Crea la carpeta de alertas si no existe."""

os.makedirs(CARPETA_ALERTAS, exist_ok=True)





def registrar_alerta(ip_usuario, megabytes_totales):

"""Registra una alerta en el archivo de log (append, no sobrescribe)."""

crear_carpeta_alertas()

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


with open(f"{CARPETA_ALERTAS}/alerta_exfiltracion.log", "a") as reporte:

reporte.write(

f"[{timestamp}] 🚨 ALERTA: IP {ip_usuario} intentó mover "

f"{megabytes_totales:.2f} MB (límite: {UMBRAL_MB} MB)\n"

)





def calcular_volumen_datos(ruta_target):

"""Calcula el tamaño total en MB de una carpeta."""

bytes_totales = 0


if not os.path.exists(ruta_target):

print(f"⚠️ Advertencia: La ruta '{ruta_target}' no existe.")

return 0


try:

for raiz, directorios, archivos in os.walk(ruta_target):

for archivo in archivos:

try:

ruta_completa = os.path.join(raiz, archivo)

bytes_totales += os.path.getsize(ruta_completa)

except (FileNotFoundError, PermissionError):

# Archivo eliminado o sin permisos: continuar

pass

except PermissionError as e:

print(f"❌ Error de permisos al acceder a '{ruta_target}': {e}")

return 0


megabytes_totales = bytes_totales / (1024 * 1024)

return megabytes_totales





# ==========================================

# 3. LÓGICA DEL DETECTOR

# ==========================================

def analizar_seguridad(ip_usuario, ruta_target=RUTA_A_MONITOREAR):

"""Detecta intentos de exfiltración de datos."""

print("\n--- INICIANDO ESCANEO DE SEGURIDAD ---\n")


# Paso A: Verificar si la IP es segura

if ip_usuario in IPS_AUTORIZADAS:

print(f"✅ IP Autorizada ({ip_usuario}). Acceso concedido.\n")

return True


print(f"⚠️ Atención: Conexión desde IP no registrada ({ip_usuario}).\n")


# Paso B: Calcular el volumen total de datos

megabytes_totales = calcular_volumen_datos(ruta_target)

print(f"📊 Volumen de datos detectado: {megabytes_totales:.2f} MB\n")


# Paso C: Evaluar contra el Umbral

if megabytes_totales > UMBRAL_MB:

print(f"🚨 ¡ALERTA ROJA! Se superó el umbral de {UMBRAL_MB} MB.")

print(f" Posible exfiltración bloqueada.\n")


# Registrar la alerta en el log

registrar_alerta(ip_usuario, megabytes_totales)

print("📝 Alerta registrada en 'alertas/alerta_exfiltracion.log'\n")


return False

else:

print("✅ Volumen dentro del límite permitido.\n")

return True





# ==========================================

# 4. PRUEBA DEL SCRIPT (EJECUCIÓN)

# ==========================================

if __name__ == "__main__":

# Simulación de pruebas:


print("=" * 50)

print("PRUEBA 1: IP Autorizada")

print("=" * 50)

analizar_seguridad("192.168.1.50")


print("\n" + "=" * 50)

print("PRUEBA 2: IP No Autorizada")

print("=" * 50)

analizar_seguridad("10.0.0.99")