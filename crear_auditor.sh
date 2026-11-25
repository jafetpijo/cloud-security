#!/bin/bash
# Crea un grupo y un usuario auditor, y deja un archivo de logs legible solo
# por ese grupo (permisos 640: dueño lee/escribe, grupo lee, otros nada).
#
# Uso:
#   ./crear_auditor.sh [archivo_de_log]
#   GRUPO=soc USUARIO=analista ./crear_auditor.sh /var/log/app.log
#
# Se puede ejecutar varias veces: lo que ya existe no se vuelve a crear.

# Detenerse ante cualquier error, variable no definida o fallo en un pipe,
# para no informar "creado exitosamente" cuando algo falló.
set -euo pipefail

# 1. Variables (se pueden cambiar sin editar el script)
GRUPO="${GRUPO:-security-team}"
USUARIO="${USUARIO:-auditor}"
LOG_FILE="${1:-servidor_aws.log}"

echo "=== Iniciando automatización de seguridad ==="

# 2. Crear el grupo si no existe
if ! getent group "$GRUPO" > /dev/null; then
    sudo groupadd "$GRUPO"
    echo "[+] Grupo '$GRUPO' creado exitosamente."
else
    echo "[!] El grupo '$GRUPO' ya existe."
fi

# 3. Crear el usuario si no existe
if ! id -u "$USUARIO" > /dev/null 2>&1; then
    sudo useradd -m "$USUARIO"
    echo "[+] Usuario '$USUARIO' creado exitosamente."
else
    echo "[!] El usuario '$USUARIO' ya existe."
fi

# 4. Asignar el usuario al grupo sin borrar sus otros grupos (-aG)
sudo usermod -aG "$GRUPO" "$USUARIO"
echo "[+] Usuario '$USUARIO' asignado al grupo '$GRUPO'."

# 5. Proteger el archivo de logs
if [ -f "$LOG_FILE" ]; then
    sudo chgrp "$GRUPO" "$LOG_FILE"
    sudo chmod 640 "$LOG_FILE"
    echo "[+] Permisos 640 aplicados a '$LOG_FILE'."
else
    echo "[X] El archivo '$LOG_FILE' no existe." >&2
    exit 1
fi

echo "=== Proceso finalizado ==="
