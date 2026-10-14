"""Turns probe results into a plain-English verdict.

decide(results, cfg)   -> used by app.py (list of result dicts from runner.run_all)
diagnose(probes, ...)  -> used by dashboard.py / run_diagnosis (dict of probes)
"""
from app_helpers import classify

LAYERS = ["wifi", "dns", "tcp", "tls", "http"]

DEFAULT_THRESHOLDS = {
    "wifi": {"warn_ms": 30, "bad_ms": 100, "loss_warn_pct": 5, "jitter_warn_ms": 30},
    "dns": {"warn_ms": 100, "bad_ms": 300},
    "tcp": {"warn_ms": 100, "bad_ms": 300},
    "tls": {"warn_ms": 200, "bad_ms": 500},
    "http": {"warn_ms": 500, "bad_ms": 1500},
}

SLOW = {
    "wifi": ("WiFi problem", "Your router or WiFi link is slow. Move closer or restart the router."),
    "dns": ("DNS is slow, the connection is fine", "Name lookups are slow. Try a different DNS server such as 8.8.8.8 or 1.1.1.1."),
    "tcp": ("Connection is slow", "Reaching the server takes too long. This is usually a network or ISP problem."),
    "tls": ("Secure handshake is slow", "The TLS handshake is slow. This is usually a network or server problem."),
    "http": ("The website itself is slow", "Your network is fine, but the server is slow to respond."),
}
FAIL = {
    "wifi": ("Cannot reach your router", "Check that you are connected to WiFi and restart the router."),
    "dns": ("DNS lookup failed", "Names cannot be resolved. Try a different DNS server such as 8.8.8.8 or 1.1.1.1."),
    "tcp": ("Cannot connect to the server", "The server is unreachable. This is usually a network, firewall or ISP problem."),
    "tls": ("Secure connection failed", "The TLS handshake or certificate check failed."),
    "http": ("The website returned an error", "The connection works, but the server did not answer correctly."),
}


def _issue(layer, r, state, cfg):
    t = cfg.get("thresholds", {})
    extra = r.get("extra") or {}

    if state == "fail":
        head, expl = FAIL[layer]
        if r.get("error"):
            expl = f"{expl} ({r['error']})"
        return "bad", head, expl
    if state in ("bad", "slow"):
        head, expl = SLOW[layer]
        return ("bad" if state == "bad" else "warn"), head, expl

    if layer == "wifi":
        w = t.get("wifi", {})
        loss, jitter = extra.get("loss_pct"), extra.get("jitter_ms")
        if loss is not None and loss >= w.get("loss_warn_pct", 5):
            return "warn", "WiFi is dropping packets", f"{loss:.0f}% of pings to your router were lost. Move closer or restart the router."
        if jitter is not None and jitter >= w.get("jitter_warn_ms", 30):
            return "warn", "WiFi is unstable", f"Router response time varies by {jitter:.0f} ms. Move closer or restart the router."
    if layer == "tls":
        days = extra.get("cert_days_left")
        if days is not None and days < cfg.get("cert_warn_days", 14):
            return "warn", "Certificate expires soon", f"The site's certificate expires in {days} days."
    return None


def decide(results, cfg):
    by = {r["layer"]: r for r in results}
    states = {l: classify(by[l], cfg) for l in LAYERS if l in by}

    # Many routers ignore ping. If everything after WiFi works, that is not a problem.
    later = [s for l, s in states.items() if l != "wifi" and s != "skipped"]
    wifi_ping_blocked = states.get("wifi") == "fail" and later and all(s in ("ok", "slow", "bad") for s in later)

    for l in LAYERS:
        if l not in by or states[l] == "skipped":
            continue
        if l == "wifi" and wifi_ping_blocked:
            continue
        found = _issue(l, by[l], states[l], cfg)
        if found:
            status, head, expl = found
            return {"status": status, "headline": head, "explanation": expl, "layer": l}

    expl = "All layers responded within normal limits."
    if wifi_ping_blocked:
        expl += " Your router does not answer ping, so the WiFi layer could not be measured."
    return {"status": "ok", "headline": "Everything looks healthy", "explanation": expl, "layer": None}


def diagnose(results, thresholds=None):
    """results: {"wifi": {...}, "ping": {...}, "dns": {...}, ...} (dict-of-probes format)."""
    configured = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    wifi = configured["wifi"]
    loss_warn = wifi.get("loss_warn_pct", 5)
    jitter_warn = wifi.get("jitter_warn_ms", 30)
    failed, slow = [], []

    for layer, data in results.items():
        if not isinstance(data, dict):
            continue

        status = str(data.get("status", "")).lower()
        loss = data.get("packet_loss_percent")
        jitter = data.get("jitter_ms")

        if (status in ("failed", "failure", "error", "unreachable")
                or data.get("ok") is False
                or data.get("reachable") is False
                or data.get("error")
                or (isinstance(loss, (int, float)) and loss >= 100)):
            failed.append(layer)
            continue

        time_ms = data.get("time_ms")
        if time_ms is None:
            time_ms = data.get("rtt_ms")
        limits = configured.get(layer, {}) if layer != "ping" else {}
        if isinstance(time_ms, (int, float)) and time_ms >= limits.get("warn_ms", float("inf")):
            slow.append(layer)
        if isinstance(loss, (int, float)) and loss >= loss_warn:
            slow.append(layer)
        if isinstance(jitter, (int, float)) and jitter >= jitter_warn:
            slow.append(layer)

    failed = list(dict.fromkeys(failed))
    slow = [l for l in dict.fromkeys(slow) if l not in failed]

    if failed:
        status, problem = "failed", failed[0]
        headline = f"Network check failed: {problem}"
        explanation = f"The {problem} probe failed. Check that layer's connection and configuration."
    elif slow:
        status, problem = "slow", slow[0]
        headline = f"Network performance is slow: {problem}"
        explanation = f"The {problem} probe exceeded its warning threshold."
    else:
        status, problem = "healthy", None
        headline = "Network connection is healthy"
        explanation = "No probe failures or configured threshold violations were detected."

    return {"status": status, "problematic_layer": problem, "headline": headline,
            "explanation": explanation, "failed_checks": failed, "slow_checks": slow,
            "thresholds": configured}


def generate_verdict(results, thresholds=None):
    return diagnose(results, thresholds)


def get_verdict(results, thresholds=None):
    return diagnose(results, thresholds)