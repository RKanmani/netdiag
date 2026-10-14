"""Runs all probes.

run_all(config)        -> list of result dicts in order wifi, dns, tcp, tls, http (used by app.py)
run_diagnosis(config)  -> dict of raw probes + verdict (used by dashboard.py)
"""
import json
import os
import re
import subprocess

from ping import run_ping_probe
from probes.dns import probe_dns
from probes.tcp import probe_tcp
from probes.tls import probe_tls
from probes.http_probe import probe_http

from verdict import diagnose

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_config(config=None):
    if isinstance(config, dict):
        return config

    path = config or os.path.join(BASE_DIR, "config.json")

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}


def get_gateway():
    def run(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout

    try:
        if os.name == "nt":
            in_block = False
            for line in run(["ipconfig"]).splitlines():
                if "Default Gateway" in line:
                    in_block = True
                elif in_block and not line.startswith((" ", "\t")):
                    in_block = False
                if in_block:
                    m = IPV4.search(line.split(":", 1)[-1])
                    if m and m.group() != "0.0.0.0":
                        return m.group()
            return None

        for line in run(["ip", "route", "show", "default"]).splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:                                    # macOS
        for line in run(["route", "-n", "get", "default"]).splitlines():
            if "gateway:" in line:
                return line.split(":", 1)[1].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


def _result(layer, ok, time_ms=None, detail="", error=None, extra=None):
    return {"layer": layer, "ok": ok, "time_ms": time_ms, "detail": detail,
            "error": error, "extra": extra or {}}


def _skipped(layer, why):
    return _result(layer, False, detail="not tested", error=f"skipped: {why}")


def _wifi_result(ping, gateway):
    ok = bool(ping.get("reachable"))
    loss, jitter, rtt = ping.get("packet_loss_percent"), ping.get("jitter_ms"), ping.get("rtt_ms")
    extra = {"gateway": gateway, "loss_pct": loss, "jitter_ms": jitter}
    if not ok:
        return _result("wifi", False, detail=f"router {gateway} did not answer ping",
                       error=ping.get("error") or "unreachable", extra=extra)
    return _result("wifi", True, rtt,
                   f"router {gateway}: avg {rtt} ms, {loss:.0f}% loss, jitter {jitter} ms", extra=extra)


def run_all(config=None, host=None):
    settings = load_config(config)
    target = host or settings.get("test_domain", "www.google.com")
    timeouts = settings.get("timeouts", {})

    gateway = settings.get("gateway", "auto")
    if not gateway or gateway == "auto":
        gateway = get_gateway()

    results = []

    if gateway:
        ping = run_ping_probe(host=gateway, count=4, timeout=timeouts.get("ping", 2))
        results.append(_wifi_result(ping, gateway))
    else:
        results.append(_result("wifi", False, detail="could not detect the default gateway",
                               error="no gateway"))

    dns = probe_dns(target, server=settings.get("dns_server", "auto"),
                    timeout=timeouts.get("dns", 3))
    results.append(dns)

    # DNS failing does not stop TCP: the system resolver may still work.
    ip = (dns.get("extra") or {}).get("ip") or target
    tcp = probe_tcp(ip, port=443, timeout=timeouts.get("tcp", 3))
    results.append(tcp)

    if not tcp["ok"]:
        results.append(_skipped("tls", "TCP connection failed"))
        results.append(_skipped("http", "TCP connection failed"))
        return results

    tls = probe_tls(target, port=443, timeout=timeouts.get("tls", 5),
                    cert_warn_days=settings.get("cert_warn_days", 14))
    results.append(tls)

    if not tls["ok"]:
        results.append(_skipped("http", "TLS handshake failed"))
        return results

    results.append(probe_http(target, port=443, timeout=timeouts.get("http", 8), use_https=True))
    return results


def run_diagnosis(config=None, host=None):
    settings = load_config(config)
    target = host or settings.get("test_domain", "www.google.com")

    timeouts = settings.get("timeouts", {})
    thresholds = settings.get("thresholds", {})

    gateway = settings.get("gateway", "auto")
    if not gateway or gateway == "auto":
        gateway = get_gateway()

    results = {
        "target": target,
        "probes": {}
    }

    if gateway:
        results["probes"]["wifi"] = run_ping_probe(
            host=gateway,
            count=4,
            timeout=timeouts.get("ping", 2)
        )
    else:
        results["probes"]["wifi"] = {
            "status": "failed",
            "error": "Could not detect the default gateway"
        }

    results["probes"]["ping"] = run_ping_probe(
        host=target,
        count=4,
        timeout=timeouts.get("ping", 2)
    )

    steps = [
        ("dns", lambda: probe_dns(target, server=settings.get("dns_server", "auto"),
                                  timeout=timeouts.get("dns", 3))),
        ("tcp", lambda: probe_tcp(target, port=443, timeout=timeouts.get("tcp", 3))),
        ("tls", lambda: probe_tls(target, port=443, timeout=timeouts.get("tls", 5),
                                  cert_warn_days=settings.get("cert_warn_days", 14))),
        ("http", lambda: probe_http(target, port=443, timeout=timeouts.get("http", 8),
                                    use_https=True)),
    ]
    for name, fn in steps:
        try:
            results["probes"][name] = fn()
        except Exception as exc:
            results["probes"][name] = {"status": "failed", "error": str(exc)}

    results["verdict"] = diagnose(results["probes"], thresholds=thresholds)

    results["status"] = results["verdict"]["status"]
    results["headline"] = results["verdict"]["headline"]
    results["explanation"] = results["verdict"]["explanation"]
    results["problematic_layer"] = results["verdict"]["problematic_layer"]

    return results


def run_all_probes(config=None, host=None):
    return run_diagnosis(config=config, host=host)


def run(config=None, host=None):
    return run_diagnosis(config=config, host=host)


if __name__ == "__main__":
    print(json.dumps(run_diagnosis(), indent=2))