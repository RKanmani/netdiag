"""Small helpers shared by the dashboard and the mock verdict."""

STATE_LABEL = {"ok": "OK", "slow": "Slow", "bad": "Very slow",
               "fail": "Failed", "skipped": "Skipped"}
COLORS = {"ok": "#2e9e5b", "slow": "#e8a317", "bad": "#d64545",
          "fail": "#d64545", "skipped": "#9aa0a6"}
ICONS = {"ok": "🟢", "slow": "🟡", "bad": "🔴", "fail": "🔴", "skipped": "⚪"}


def classify(r, cfg):
    """Turn one probe result into ok / slow / bad / fail / skipped using config thresholds."""
    if r.get("error") and str(r["error"]).startswith("skipped"):
        return "skipped"
    if not r["ok"]:
        return "fail"
    t = cfg["thresholds"].get(r["layer"], {})
    ms = r.get("time_ms")
    if ms is not None:
        if "bad_ms" in t and ms >= t["bad_ms"]:
            return "bad"
        if "warn_ms" in t and ms >= t["warn_ms"]:
            return "slow"
    return "ok"
