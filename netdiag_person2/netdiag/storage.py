"""CSV logging of past runs: one row per diagnosis, fixed columns."""
import csv
from datetime import datetime
from pathlib import Path

import pandas as pd

LAYERS = ["wifi", "dns", "tcp", "tls", "http"]
COLUMNS = (["timestamp", "status", "headline", "total_ms"]
           + [f"{l}_ms" for l in LAYERS] + [f"{l}_ok" for l in LAYERS])


def append_run(results, verdict, path):
    by_layer = {r["layer"]: r for r in results}
    total = sum(r["time_ms"] for r in results if r.get("time_ms"))
    row = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           "status": verdict.get("status", ""),
           "headline": verdict.get("headline", ""),
           "total_ms": round(total, 1)}
    for l in LAYERS:
        r = by_layer.get(l)
        row[f"{l}_ms"] = r["time_ms"] if r and r.get("time_ms") is not None else ""
        row[f"{l}_ok"] = int(bool(r and r["ok"])) if r else ""

    path = Path(path)
    new_file = not path.exists() or path.stat().st_size == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow(row)


def load_history(path):
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame(columns=COLUMNS)
    return pd.read_csv(path)


def clear_history(path):
    Path(path).unlink(missing_ok=True)
