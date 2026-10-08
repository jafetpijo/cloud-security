#!/usr/bin/envpython3

from collections import Counter

errores = 0
ips = Counter()

with open("servidor_aws.log") as archivo:
    for linea in archivo:
        if "ERROR" in linea.upper():
            errores += 1
            partes = linea.split()
            if "desde" in partes and "IP" in partes:
                ip_encontrada = partes[partes.index("IP") + 1]
                ips[ip_encontrada] +=1

print(f"Total de errores: {errores}")
print("Ips con mas errores")
for ip, cantidad in ips.most_common():
    print(f" {ip}: {cantidad}")        