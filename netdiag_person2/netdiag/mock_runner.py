"""Fake runner + verdict so the dashboard works before the real ones exist.

INTERFACE the real files must follow:
  runner.run_all(config)        -> list of result dicts, in order wifi, dns, tcp, tls, http
  verdict.decide(results, cfg)  -> {"status": "ok|warn|bad", "headline": str,
                                    "explanation": str, "layer": str|None}
Result dict: {"layer", "ok", "time_ms", "detail", "error"}  (+ optional "extra")
A layer skipped because an earlier one failed uses error="skipped: ...".
"""
import random
import time

ORDER = ["wifi", "dns", "tcp", "tls", "http"]
BASE = {"wifi": 8, "dns": 35, "tcp": 25, "tls": 60, "http": 140}
SCENARIOS = ["healthy", "slow_dns", "wifi_problem", "site_down", "slow_http"]


def run_all(config, scenario="healthy"):
    time.sleep(1.5)
    results, failed = [], False
    for layer in ORDER:
        ms = BASE[layer] * random.uniform(0.7, 1.4)
        ok, err = True, None
        if scenario == "slow_dns" and layer == "dns":
            ms = random.uniform(450, 700)
        if scenario == "wifi_problem" and layer == "wifi":
            ms = random.uniform(180, 300)
        if scenario == "slow_http" and layer == "http":
            ms = random.uniform(2000, 3000)
        if scenario == "site_down" and layer == "dns":
            ok, err = False, "NXDOMAIN"
        if failed:
            results.append({"layer": layer, "ok": False, "time_ms": None,
                            "detail": "not tested", "error": "skipped: earlier layer failed"})
            continue
        if not ok:
            failed = True
            results.append({"layer": layer, "ok": False, "time_ms": None,
                            "detail": "name does not exist", "error": err})
        else:
            results.append({"layer": layer, "ok": True, "time_ms": round(ms, 1),
                            "detail": f"mock {layer} result", "error": None})
    return results


MESSAGES = {
    "wifi": ("WiFi problem", "Your router or WiFi link is slow or unreachable. Move closer or restart the router."),
    "dns": ("DNS is slow, the connection is fine", "Name lookups are slow. Try a different DNS server such as 8.8.8.8 or 1.1.1.1."),
    "tcp": ("Connection is slow", "Reaching the server takes too long. This is usually a network or ISP problem."),
    "tls": ("Secure handshake is slow", "The TLS handshake is slow or the certificate has a problem."),
    "http": ("The website itself is slow", "Your network is fine, but the server is slow to respond."),
}


def decide(results, config):
    from app_helpers import classify
    for r in results:
        state = classify(r, config)
        if state in ("fail", "bad", "slow"):
            head, expl = MESSAGES[r["layer"]]
            return {"status": "bad" if state in ("fail", "bad") else "warn",
                    "headline": head, "explanation": expl, "layer": r["layer"]}
    return {"status": "ok", "headline": "Everything looks healthy",
            "explanation": "All layers responded within normal limits.", "layer": None}
