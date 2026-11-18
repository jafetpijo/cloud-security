#!/usr/bin/env python3
"""
Folder growth detector (data staging).

Measures the size of one or more folders, compares it with the size saved on
the previous run, and alerts when a folder grew (or shrank) by more than a
threshold. Before stealing data, attackers often copy everything into one
folder to compress it and send it in one go; a sudden jump in size is a sign.

On each alert it also lists the biggest files changed since the last check,
which is where an investigation usually starts.

MITRE ATT&CK: T1074 (Data Staged), T1485 (Data Destruction) for large drops

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error.
"""
import argparse
import json
import logging
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger("growth")

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2
MB = 1024 * 1024


# --- Measuring ---------------------------------------------------------------
def scan_folder(path, since=None, top=5):
    """Return (total_bytes, biggest files changed after `since`).
    Symlinks are skipped to avoid loops and double counting."""
    total = 0
    changed = []
    for root, _, files in os.walk(path, followlinks=False):
        for name in files:
            full = os.path.join(root, name)
            try:
                if os.path.islink(full):
                    continue
                st = os.stat(full)
            except OSError:          # file deleted meanwhile or no permission
                continue
            total += st.st_size
            if since is not None and st.st_mtime > since:
                changed.append((st.st_size, full))
    changed.sort(reverse=True)
    return total, [{"file": f, "mb": round(s / MB, 2)} for s, f in changed[:top]]


# --- State (sizes from the previous run) -------------------------------------
def load_state(path):
    path = Path(path)
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


# --- Analysis ----------------------------------------------------------------
def check_folders(folders, state, threshold_mb, now):
    """Compare each folder with its previous size. Returns (results, new_state)."""
    results, new_state = [], dict(state)
    for folder in folders:
        key = str(Path(folder).resolve())
        previous = state.get(key)
        since = previous["checked_at"] if previous else None
        size, changed_files = scan_folder(folder, since)
        new_state[key] = {"bytes": size, "checked_at": now}

        if previous is None:
            results.append({"folder": folder, "severity": "NEW", "size_mb": round(size / MB, 2),
                            "change_mb": None, "changed_files": []})
            continue
        change = size - previous["bytes"]
        if change > threshold_mb * MB:
            severity = "HIGH"        # sudden growth: possible data staging
        elif -change > threshold_mb * MB:
            severity = "MEDIUM"      # sudden drop: mass deletion?
        else:
            severity = "OK"
        results.append({
            "folder": folder, "severity": severity, "size_mb": round(size / MB, 2),
            "change_mb": round(change / MB, 2),
            "changed_files": changed_files if severity != "OK" else [],
        })
    return results, new_state


def print_summary(results, threshold_mb):
    for r in results:
        if r["severity"] == "NEW":
            log.info("NEW    %s: %.2f MB (first check, saved as reference)", r["folder"], r["size_mb"])
            continue
        level = log.warning if r["severity"] != "OK" else log.info
        level("%-6s %s: %.2f MB (%+.2f MB since last check, threshold %g MB)",
              r["severity"], r["folder"], r["size_mb"], r["change_mb"], threshold_mb)
        for f in r["changed_files"]:
            log.warning("         changed: %s (%.2f MB)", f["file"], f["mb"])


# --- Demo --------------------------------------------------------------------
def run_demo(threshold_mb):
    """Simulate two checks in a temporary folder; never touches real files."""
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "carpetas_empresa"
        folder.mkdir()
        (folder / "report.pdf").write_bytes(b"x" * 2 * MB)
        log.info("Demo, check 1: normal folder")
        results, state = check_folders([str(folder)], {}, threshold_mb, datetime.now().timestamp())
        print_summary(results, threshold_mb)

        log.info("Demo, check 2: someone copied a big archive into it")
        (folder / "tmp").mkdir()
        (folder / "tmp" / "all_clients.zip").write_bytes(b"x" * (int(threshold_mb) + 5) * MB)
        results, _ = check_folders([str(folder)], state, threshold_mb, datetime.now().timestamp())
        print_summary(results, threshold_mb)
        return results


# --- Main --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Folder growth detector (data staging)")
    p.add_argument("--path", nargs="+", default=["./carpetas_empresa"],
                   help="One or more folders to watch")
    p.add_argument("--demo", action="store_true",
                   help="Simulate two checks in a temporary folder (ignores --path)")
    p.add_argument("--threshold", type=float, default=100,
                   help="MB of growth (or drop) allowed between checks (default 100)")
    p.add_argument("--state", default="reportes/folder_sizes.json",
                   help="File that stores the sizes from the previous run")
    p.add_argument("--json-output", help="Write results to a JSON file (SIEM-friendly)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.demo:
        results = run_demo(args.threshold)
    else:
        missing = [f for f in args.path if not Path(f).is_dir()]
        if missing:
            log.error("Folder not found: %s", ", ".join(missing))   # never invent data
            return EXIT_ERROR
        try:
            state = load_state(args.state)
            results, new_state = check_folders(args.path, state, args.threshold,
                                                datetime.now().timestamp())
            print_summary(results, args.threshold)
            save_state(args.state, new_state)
        except (OSError, json.JSONDecodeError) as e:
            log.error("Could not read or save state: %s", e)
            return EXIT_ERROR

    if args.json_output:
        try:
            Path(args.json_output).write_text(json.dumps({"results": results}, indent=2),
                                              encoding="utf-8")
            log.info("Results saved to %s", args.json_output)
        except OSError as e:
            log.error("Could not write output: %s", e)
            return EXIT_ERROR

    return EXIT_ALERTS if any(r["severity"] in ("HIGH", "MEDIUM") for r in results) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())