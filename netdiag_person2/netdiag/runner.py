
import json
import os
import socket

from probes.ping import run_ping_probe
from probes.dns import probe_dns
from probes.tcp import probe_tcp
from probes.tls import probe_tls
from probes.http_probe import probe_http

from verdict import diagnose

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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
    try:
        if os.name == "nt":
            import subprocess
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=3
            )
            for line in result.stdout.splitlines():
                if "Default Gateway" in line and ":" in line:
                    value = line.split(":", 1)[1].strip()
                    if value and value != "0.0.0.0":
                        return value
        else:
            import subprocess
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=3
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


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

    try:
        results["probes"]["dns"] = probe_dns(
            target,
            server=settings.get("dns_server", "auto"),
            timeout=timeouts.get("dns", 3)
        )
    except Exception as exc:
        results["probes"]["dns"] = {
            "status": "failed",
            "error": str(exc)
        }

    try:
        results["probes"]["tcp"] = probe_tcp(
            target,
            port=443,
            timeout=timeouts.get("tcp", 3)
        )
    except Exception as exc:
        results["probes"]["tcp"] = {
            "status": "failed",
            "error": str(exc)
        }

    try:
        results["probes"]["tls"] = probe_tls(
            target,
            port=443,
            timeout=timeouts.get("tls", 5),
            cert_warn_days=settings.get("cert_warn_days", 14)
        )
    except Exception as exc:
        results["probes"]["tls"] = {
            "status": "failed",
            "error": str(exc)
        }

    try:
        results["probes"]["http"] = probe_http(
            target,
            port=443,
            timeout=timeouts.get("http", 8),
            use_https=True
        )
    except Exception as exc:
        results["probes"]["http"] = {
            "status": "failed",
            "error": str(exc)
        }

    results["verdict"] = diagnose(
        results["probes"],
        thresholds=thresholds
    )

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
