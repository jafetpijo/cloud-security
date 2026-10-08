#!/usr/bin/env python3
from collections import Counter

# 1. PREPARACIÓN
cambios_permisos = Counter()
archivos_modificados = []

# 2. LECTURA Y ANÁLISIS
try:
    with open("logs/servidor_aws.log") as archivo:
        for linea in archivo:
            if "CHMOD" in linea.upper() or "PERMISSION_CHANGE" in linea.upper():
                archivos_modificados.append(linea.strip())
                # Busca quién hizo el cambio
                if "usuario=" in linea:
                    usuario = linea.split("usuario=")[1].split()[0]
                    cambios_permisos[usuario] += 1
except FileNotFoundError:
    print("[!] Error: No se encontró el archivo de log en 'logs/servidor_aws.log'")

# 3. REPORTE
with open("reportes/auditoria_permisos.txt", "w") as reporte:
    reporte.write("=== REPORTE DE AUDITORÍA: CAMBIOS DE PERMISOS ===\n\n")
    reporte.write(f"Total de cambios: {sum(cambios_permisos.values())}\n\n")
    reporte.write("Cambios por usuario:\n")
    for usuario, cantidad in cambios_permisos.most_common():
        reporte.write(f"  {usuario}: {cantidad} cambios\n")
    reporte.write("\nDetalles:\n")
    for evento in archivos_modificados:
        reporte.write(f"  {evento}\n")

print("[+] Auditoría de permisos completada.")
print("[+] Reporte generado: 'reportes/auditoria_permisos.txt'")