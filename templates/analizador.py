#!/usr/bin/env python3
"""
Failed-login analyzer by IP (brute force / scanning detection).

Counts authentication errors per IP and raises an alert when an IP exceeds
N errors within a sliding time window (e.g. 10 errors in 5 minutes).

MITRE ATT&CK: T1110 (Brute Force)

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import ipaddress
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger("analizador")

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
# Patterns that indicate a failed access attempt (not an application failure)
AUTH_REGEX = re.compile(
    r"failed password|invalid user|authentication failure|access\s?denied|"
    r"unauthorized|forbidden|\b(?:401|403)\b",
    re.IGNORECASE,
)
ERROR_REGEX = re.compile(r"\bERROR\b", re.IGNORECASE)


def parsear_linea(linea, solo_auth):
    """Return (ip, timestamp|None) if the line is a relevant error, otherwise None."""
    patron = ERROR_REGEX if not solo_auth else AUTH_REGEX
    if not patron.search(linea):
        return None
    # First valid IP in the line (rejects values like 999.999.999.999)
    ip = None
    for candidato in IP_REGEX.findall(linea):
        try:
            ip = ipaddress.ip_address(candidato)
            break
        except ValueError:
            continue
    m = TS_REGEX.search(linea)
    ts = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S") if m else None
    return ip, ts


def leer_errores(ruta, solo_auth):
    """Return (events_by_ip, total_errors, errors_without_ip, errors_without_timestamp)."""
    por_ip = defaultdict(list)
    total = sin_ip = sin_fecha = 0
    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            r = parsear_linea(linea, solo_auth)
            if r is None:
                continue
            total += 1
            ip, ts = r
            if ip is None:
                sin_ip += 1
                continue
            if ts is None:
                sin_fecha += 1
            por_ip[ip].append(ts)
    return por_ip, total, sin_ip, sin_fecha


def max_en_ventana(tiempos, ventana):
    """Maximum number of events in any interval of length `ventana` (sliding window)."""
    tiempos = sorted(t for t in tiempos if t is not None)
    mejor, izq = (0, None, None), 0
    for der, t in enumerate(tiempos):
        while t - tiempos[izq] > ventana:
            izq += 1
        n = der - izq + 1
        if n > mejor[0]:
            mejor = (n, tiempos[izq], t)
    return mejor


def analizar(por_ip, umbral, ventana_min):
    ventana = timedelta(minutes=ventana_min)
    resultados = []
    for ip, tiempos in por_ip.items():
        n_ventana, ini, fin = max_en_ventana(tiempos, ventana)
        resultados.append({
            "ip": str(ip),
            "tipo": "public" if ip.is_global else "private",
            "errores_totales": len(tiempos),
            "max_en_ventana": n_ventana,
            "inicio": ini.isoformat() if ini else None,
            "fin": fin.isoformat() if fin else None,
            "alerta": n_ventana > umbral,
        })
    return sorted(resultados, key=lambda r: (r["max_en_ventana"], r["errores_totales"]), reverse=True)


def main():
    p = argparse.ArgumentParser(description="Failed-login analyzer by IP")
    p.add_argument("--log", default="logs/servidor_aws.log", help="Path to the log file to analyze")
    p.add_argument("--umbral", type=int, default=10, help="Errors allowed within the window (default 10)")
    p.add_argument("--ventana", type=int, default=5, help="Window size in minutes (default 5)")
    p.add_argument("--todos", action="store_true", help="Count any ERROR line, not just authentication failures")
    p.add_argument("--top", type=int, default=10, help="Show only the top N IPs (default 10)")
    p.add_argument("--salida-json", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    ruta = Path(args.log)
    if not ruta.is_file():
        log.error("'%s' not found", ruta)
        return 2
    if ruta.stat().st_size == 0:
        log.warning("Empty file: '%s'", ruta)
        return 0

    try:
        por_ip, total, sin_ip, sin_fecha = leer_errores(ruta, solo_auth=not args.todos)
    except PermissionError:
        log.error("Permission denied reading '%s'", ruta)
        return 2

    if total == 0:
        log.info("No relevant errors found.")
        return 0

    resultados = analizar(por_ip, args.umbral, args.ventana)
    alertas = [r for r in resultados if r["alerta"]]

    log.info("Total errors: %d | unique IPs: %d | without IP: %d | without timestamp: %d",
             total, len(resultados), sin_ip, sin_fecha)
    for r in resultados[:args.top]:
        nivel = log.warning if r["alerta"] else log.info
        nivel("%s %s (%s): %d errors in %d min, %d in total",
              "CRITICAL" if r["alerta"] else "OK", r["ip"], r["tipo"],
              r["max_en_ventana"], args.ventana, r["errores_totales"])

    if args.salida_json:
        Path(args.salida_json).write_text(json.dumps({
            "umbral": args.umbral, "ventana_min": args.ventana,
            "errores_totales": total, "errores_sin_ip": sin_ip,
            "resultados": resultados}, indent=2), encoding="utf-8")
        log.info("Results saved to %s", args.salida_json)

    return 1 if alertas else 0


if __name__ == "__main__":
    sys.exit(main())
    
