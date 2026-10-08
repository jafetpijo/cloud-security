descargas_por_usuario = {}
UMBRAL_MB = 100  # Alerta si descarga más de 100MB en una sesión

# 2. LECTURA Y ANÁLISIS
try:
    with open("logs/servidor_aws.log") as archivo:
        for linea in archivo:
            if "DOWNLOAD" in linea.upper():
                # Extrae usuario y tamaño
                if "usuario=" in linea and "tamaño=" in linea:
                    usuario = linea.split("usuario=")[1].split()[0]
                    tamaño_str = linea.split("tamaño=")[1].split()[0]
                    tamaño_mb = int(tamaño_str) / (1024 * 1024)  # Convierte a MB
                    
                    if usuario not in descargas_por_usuario:
                        descargas_por_usuario[usuario] = 0
                    descargas_por_usuario[usuario] += tamaño_mb
except FileNotFoundError:
    print("[!] Error: No se encontró el archivo de log en 'logs/servidor_aws.log'")

# 3. ALERTA
with open("reportes/alerta_exfiltracion.txt", "w") as reporte:
    reporte.write("=== ALERTA: POSIBLE EXFILTRACIÓN DE DATOS ===\n\n")
    for usuario, total_mb in descargas_por_usuario.items():
        if total_mb > UMBRAL_MB:
            reporte.write(f"[CRÍTICO] {usuario} descargó {total_mb:.2f}MB\n")

print("[+] Análisis de descargas completado.")
print("[+] Reporte generado: 'reportes/alerta_exfiltracion.txt'")