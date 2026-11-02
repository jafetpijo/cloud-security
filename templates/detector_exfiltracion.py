#!/usr/bin/env python3
"""
AWS data exfiltration detector (CloudTrail + S3 data events).

Flags users who download more than X MB within a sliding time window
(e.g. 100 MB in 60 minutes).

MITRE ATT&CK: T1537 (Transfer Data to Cloud Account), T1567 (Exfiltration Over Web Service)

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import gzip
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("exfiltracion")

# S3 events that represent data leaving the bucket
EVENTOS_DESCARGA = {"GetObject", "CopyObject"}


def cargar_registros(ruta):
    """Read a .json file, a .json.gz file, or a directory of them. Returns a list of events."""
    ruta = Path(ruta)
    if not ruta.exists():
        raise FileNotFoundError(f"'{ruta}' not found")
    archivos = [ruta] if ruta.is_file() else sorted(
        list(ruta.rglob("*.json")) + list(ruta.rglob("*.json.gz"))
    )
    registros = []
    for archivo in archivos:
        try:
            abrir = gzip.open if archivo.suffix == ".gz" else open
            with abrir(archivo, "rt", encoding="utf-8") as f:
                registros.extend(json.load(f).get("Records", []))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Skipping %s: %s", archivo, e)
    return registros


def extraer_descargas(registros):
    """Return {user: [(datetime, bytes), ...]} for successful download events only."""
    por_usuario = defaultdict(list)
    for r in registros:
        if r.get("eventName") not in EVENTOS_DESCARGA or r.get("errorCode"):
            continue
        try:
            ts = datetime.strptime(r["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            ident = r["userIdentity"]
            usuario = ident.get("userName") or ident.get("arn") or ident.get("principalId", "unknown")
            # In S3 data events the transfer size is in additionalEventData
            nbytes = int((r.get("additionalEventData") or {}).get("bytesTransferredOut", 0))
        except (KeyError, ValueError, TypeError):
            continue
        if nbytes > 0:
            por_usuario[usuario].append((ts, nbytes))
    return por_usuario


def max_en_ventana(eventos, ventana):
    """Sliding window: maximum bytes downloaded in any interval of length `ventana`.
    Returns (bytes, window_start, window_end)."""
    eventos = sorted(eventos)
    mejor = (0, None, None)
    suma, izq = 0, 0
    for der, (ts_der, b) in enumerate(eventos):
        suma += b
        while ts_der - eventos[izq][0] > ventana:
            suma -= eventos[izq][1]
            izq += 1
        if suma > mejor[0]:
            mejor = (suma, eventos[izq][0], ts_der)
    return mejor


def analizar(por_usuario, umbral_mb, ventana_min):
    ventana = timedelta(minutes=ventana_min)
    resultados = []
    for usuario, eventos in por_usuario.items():
        total, ini, fin = max_en_ventana(eventos, ventana)
        mb = total / (1024 * 1024)
        resultados.append({
            "usuario": usuario,
            "mb_en_ventana": round(mb, 2),
            "inicio": ini.isoformat() if ini else None,
            "fin": fin.isoformat() if fin else None,
            "eventos": len(eventos),
            "alerta": mb > umbral_mb,
        })
    return sorted(resultados, key=lambda x: x["mb_en_ventana"], reverse=True)


def main():
    p = argparse.ArgumentParser(description="Exfiltration detector - CloudTrail S3 data events")
    p.add_argument("--ruta-logs", required=True, help="CloudTrail .json/.json.gz file or directory")
    p.add_argument("--umbral", type=float, default=100, help="Threshold in MB (default 100)")
    p.add_argument("--ventana", type=int, default=60, help="Window size in minutes (default 60)")
    p.add_argument("--salida-json", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    try:
        registros = cargar_registros(args.ruta_logs)
    except FileNotFoundError as e:
        log.error(e)
        return 2

    por_usuario = extraer_descargas(registros)
    if not por_usuario:
        log.info("No downloads with size information found in %d records.", len(registros))
        return 0

    resultados = analizar(por_usuario, args.umbral, args.ventana)
    alertas = [r for r in resultados if r["alerta"]]

    for r in resultados:
        nivel = log.warning if r["alerta"] else log.info
        nivel("%s %s: %.2f MB in %d min (%s -> %s)",
              "CRITICAL" if r["alerta"] else "OK",
              r["usuario"], r["mb_en_ventana"], args.ventana, r["inicio"], r["fin"])

    if args.salida_json:
        Path(args.salida_json).write_text(
            json.dumps({"umbral_mb": args.umbral, "ventana_min": args.ventana,
                        "resultados": resultados}, indent=2), encoding="utf-8")
        log.info("Results saved to %s", args.salida_json)

    return 1 if alertas else 0


if __name__ == "__main__":
    sys.exit(main())
    
