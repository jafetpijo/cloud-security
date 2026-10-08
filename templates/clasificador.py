


#!/usr/bin/env python3

# 1. LECTURA Y CLASIFICACIÓN
with open("servidor_aws.log", "r") as archivo_origen, \
     open("alertas_criticas.log", "w") as archivo_alertas, \
     open("eventos_normales.log", "w") as archivo_normal:

    for linea in archivo_origen:
        # Clasificar según el nivel de severidad
        if "ERROR" in linea.upper() or "CRITICAL" in linea.upper():
            archivo_alertas.write(f"[CRÍTICO] {linea}")
        else:
            archivo_normal.write(linea)

print("[+] Clasificación de registros finalizada con éxito.")
print("[+] Archivos creados: 'alertas_criticas.log' y 'eventos_normales.log'")