
DEFAULT_THRESHOLDS = {
    "wifi": {"warn_ms": 30, "bad_ms": 100, "loss_warn_pct": 5, "jitter_warn_ms": 30},
    "dns": {"warn_ms": 100, "bad_ms": 300},
    "tcp": {"warn_ms": 100, "bad_ms": 300},
    "tls": {"warn_ms": 200, "bad_ms": 500},
    "http": {"warn_ms": 500, "bad_ms": 1500},
}


def diagnose(results, thresholds=None):
    configured = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    failed = []
    slow = []

    for layer, data in results.items():
        if not isinstance(data, dict):
            continue

        status = str(data.get("status", "")).lower()
        ok = data.get("ok")
        error = data.get("error")
        time_ms = data.get("time_ms")

        if status in ("failed", "failure", "error", "unreachable") or ok is False:
            failed.append(layer)
            continue

        if data.get("reachable") is False:
            failed.append(layer)
            continue

        if error:
            failed.append(layer)
            continue

        limits = configured.get(layer, {})
        if isinstance(limits, dict) and isinstance(time_ms, (int, float)):
            if time_ms > limits.get("bad_ms", float("inf")):
                failed.append(layer)
                continue
            if time_ms > limits.get("warn_ms", float("inf")):
                slow.append(layer)

        loss = data.get("packet_loss_percent")
        jitter = data.get("jitter_ms")

        if isinstance(loss, (int, float)) and loss >= 100:
            failed.append(layer)
        elif isinstance(loss, (int, float)) and loss >= 5:
            slow.append(layer)

        if isinstance(jitter, (int, float)) and jitter > 30:
            slow.append(layer)

    failed = list(dict.fromkeys(failed))
    slow = [layer for layer in dict.fromkeys(slow) if layer not in failed]

    if failed:
        status = "failed"
        problem = failed[0]
        headline = f"Network check failed: {problem}"
        explanation = f"The {problem} probe failed. Check that layer's connection and configuration."
    elif slow:
        status = "slow"
        problem = slow[0]
        headline = f"Network performance is slow: {problem}"
        explanation = f"The {problem} probe exceeded its warning threshold."
    else:
        status = "healthy"
        problem = None
        headline = "Network connection is healthy"
        explanation = "No probe failures or configured threshold violations were detected."

    return {
        "status": status,
        "problematic_layer": problem,
        "headline": headline,
        "explanation": explanation,
        "failed_checks": failed,
        "slow_checks": slow,
        "thresholds": configured,
    }


def generate_verdict(results, thresholds=None):
    return diagnose(results, thresholds)


def get_verdict(results, thresholds=None):
    return diagnose(results, thresholds)
