#!/bin/bash

# 1. Definir variables
GRUPO="security-team"
USUARIO="auditor"
LOG_FILE="servidor_aws.log"

echo "=== Iniciando automatización de seguridad ==="

# 2. Crear el grupo si no existe
if ! getent group $GRUPO > /dev/null; then
    sudo groupadd $GRUPO
    echo "[+] Grupo '$GRUPO' creado exitosamente."
else
    echo "[!] El grupo '$GRUPO' ya existe."
fi

# 3. Crear el usuario si no existe
if ! id -u $USUARIO > /dev/null 2>&1; then
    sudo useradd -m $USUARIO
    echo "[+] Usuario '$USUARIO' creado exitosamente."
else
    echo "[!] El usuario '$USUARIO' ya existe."
fi

# 4. Asignar el usuario al grupo sin borrar sus accesos (-aG)
sudo usermod -aG $GRUPO $USUARIO
echo "[+] Usuario '$USUARIO' asignado al grupo '$GRUPO'."

# 5. Proteger el archivo de logs
if [ -f "$LOG_FILE" ]; then
    sudo chgrp $GRUPO $LOG_FILE
    sudo chmod 640 $LOG_FILE
    echo "[+] Permisos 640 aplicados a '$LOG_FILE'."
else
    echo "[X] El archivo '$LOG_FILE' no existe en este directorio."
fi

echo "=== Proceso finalizado ==="

