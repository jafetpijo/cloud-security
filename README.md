# Cloud Security Log Automation & Incident Response

Suite de herramientas automatizadas en **Python** para auditoría de logs, detección de anomalías e incidentes de seguridad en entornos cloud y servidores.

## 📋 Descripción

Este proyecto implementa un conjunto de detectores de seguridad que analizan logs de servidores en tiempo real, identifican patrones sospechosos y generan alertas automáticas. Cada herramienta está diseñada para cubrir casos de uso específicos de operaciones de seguridad (SOC/SIEM básico).

**Casos de uso:**
- 🔍 Detección de intentos de fuerza bruta
- 🌐 Identificación de accesos desde IPs nuevas
- 📥 Alerta por descargas masivas (exfiltración de datos)
- 🔐 Auditoría de cambios de permisos de archivo
- 📊 Dashboard diario de eventos de seguridad

## 📁 Estructura del Proyecto

cloud-security/
├── templates/ # Scripts Python (detectores)
│ ├── analizador.py # Análisis de errores por IP
│ ├── clasificador.py # Separación de eventos críticos vs normales
│ ├── contador_permisos.py # Auditoría de cambios chmod
│ ├── detector_acceso_ips_nuevas.py # Detección de IPs no registradas
│ ├── detector_exfiltracion.py # Alerta por descarga de datos
│ ├── detector_usuarios.py # Detección de fuerza bruta
│ └── resumen_diario.py # Dashboard diario con porcentajes
├── logs/ # Archivos de entrada (logs)
├── reportes/ # Alertas e informes generados
└── README.md # Este archivo


## 🛠️ Herramientas Incluidas

### 1. **analizador.py** – Análisis de Errores por IP
Identifica de qué direcciones IP provienen más errores en los logs.

```bash
python3 templates/analizador.py
```

**Salida:** `reportes/analisis_errores_ips.log`

---

### 2. **clasificador.py** – Clasificación de Eventos
Separa eventos críticos (ERROR, CRITICAL) de eventos normales en archivos independientes.

```bash
python3 templates/clasificador.py
```

**Salida:** 
- `reportes/alertas_criticas.log`
- `reportes/eventos_normales.log`

---

### 3. **contador_permisos.py** – Auditoría de Permisos
Rastrea y contabiliza cambios de permisos (chmod) por usuario.

```bash
python3 templates/contador_permisos.py
```

**Salida:** `reportes/auditoria_permisos.log`

---

### 4. **detector_acceso_ips_nuevas.py** – Detección de IPs Nuevas
Detecta cuando un usuario inicia sesión desde una dirección IP no registrada previamente.

```bash
python3 templates/detector_acceso_ips_nuevas.py
```

**Salida:** `reportes/accesos_anomalos.log`

---

### 5. **detector_exfiltracion.py** – Detección de Exfiltración
Emite alertas cuando un usuario descarga más data de la permitida (umbral: 100MB).

```bash
python3 templates/detector_exfiltracion.py
```

**Salida:** `reportes/alerta_exfiltracion.log`

---

### 6. **detector_usuarios.py** – Detección de Fuerza Bruta
Identifica intentos fallidos de autenticación y alerta sobre posibles ataques de fuerza bruta.

```bash
python3 templates/detector_usuarios.py
```

**Salida:** `reportes/deteccion_fuerza_bruta.log`

---

### 7. **resumen_diario.py** – Dashboard Diario
Genera un resumen diario con métricas clave: total de eventos, porcentajes de errores, alertas y accesos exitosos.

```bash
python3 templates/resumen_diario.py
```

**Salida:** `reportes/resumen_diario.log`

---

## 🚀 Cómo Usar

### Requisitos
- Python 3.6+
- Archivos de logs en formato texto (ejemplo: `logs/servidor_aws.log`)

### Ejecución
Desde la carpeta raíz del proyecto, ejecuta cualquiera de los detectores:

```bash
cd ~/cloud-security

# Ejecutar un detector individual
python3 templates/detector_exfiltracion.py

# Ejecutar varios en secuencia
python3 templates/detector_usuarios.py
python3 templates/detector_acceso_ips_nuevas.py
python3 templates/resumen_diario.py
```

### Ver los Reportes Generados
```bash
# Ver alertas de fuerza bruta
cat reportes/deteccion_fuerza_bruta.log

# Ver eventos clasificados
cat reportes/alertas_criticas.log

# Ver resumen del día
cat reportes/resumen_diario.log
```

---

## 🔧 Características Técnicas

Todos los scripts incluyen:

✅ **Validación de archivos** – Verifica que logs existan y no estén vacíos
✅ **Manejo de excepciones** – Captura errores de permisos y formato
✅ **Timestamps** – Registra fecha/hora exacta de ejecución
✅ **Append logs** – Mantiene histórico (no sobrescribe)
✅ **Funciones modulares** – Código reutilizable y testeable
✅ **Dashboards en consola** – Feedback visual inmediato
✅ **Porcentajes** – Análisis cuantitativos

---

## 📊 Ejemplo de Salida
============================================================
📊 DETECCIÓN DE FUERZA BRUTA

📈 Total de fallos: 47

👥 Usuarios afectados: 3

Intentos fallidos por usuario:
jafet: 15 intentos (31.9%) 🚨 CRÍTICO
admin: 20 intentos (42.6%) 🚨 CRÍTICO
guest: 12 intentos (25.5%) ⚠️ Observar

📝 Reporte guardado en: reportes/deteccion_fuerza_bruta.log


---

## 🎯 Roadmap Futuro

- [ ] Integración con Slack/Email para alertas en tiempo real
- [ ] Dashboard web (Flask/FastAPI)
- [ ] Soporte para múltiples formatos de logs (JSON, syslog)
- [ ] Machine learning para detección de anomalías
- [ ] API REST para consultas de reportes

---

## 📝 Licencia

Este proyecto es de código abierto. Úsalo libremente en tus estudios o proyectos personales.

---

## 👤 Autor

**Jafet García**  
Cloud Security Engineer | Python Developer  
[GitHub](https://github.com/jafet@jio) | [LinkedIn](https://linkedin.com/in/jafet)

---

## ⭐ Si te fue útil, no olvides darle una estrella en GitHub!
