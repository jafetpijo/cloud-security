

#!/usr/bin/env python3
from collections import Counter

# 1. PREPARACIÓN
intentos_usuario = Counter()
total_fallos = 0

# 2. LECTURA Y FILTRADO (Modifica la palabra clave si tu log usa otra)
with open("servidor_aws.log") as archivo:
    for linea in archivo:
        if "INCORRECTA" in linea.upper() or "DENIED" in linea.upper():
            total_fallos += 1
            partes = linea.split()
            # Busca la palabra "usuario" y toma el nombre que le sigue
            if "usuario" in partes:
                usuario = partes[partes.index("usuario") + 1]
                intentos_usuario[usuario] += 1

# 3. GENERACIÓN DE ALERTA Y REPORTE
UMBRAL = 3  # Máximo de intentos permitidos

with open("reporte_usuarios_sospechosos.txt", "w") as reporte:
    reporte.write("=== ALERTA DE SEGURIDAD: USUARIOS SOSPECHOSOS ===\n\n")
    for usuario, cantidad in intentos_usuario.most_common():
        if cantidad >= UMBRAL:
            mensaje = f"[ALERTA] El usuario '{usuario}' registró {cantidad} fallos de autenticación."
            reporte.write(f"{mensaje}\n")

print(f"[+] Análisis completado. Total fallos: {total_fallos}")
print("[+] Reporte generado: 'reporte_usuarios_sospechosos.txt'")