import platform
import re
import statistics
import subprocess


def ping_host(host, count=4, timeout=2):
    count = max(1, int(count))
    timeout = max(1, float(timeout))

    if platform.system().lower() == "windows":
        command = [
            "ping", "-n", str(count),
            "-w", str(int(timeout * 1000)), str(host)
        ]
    else:
        command = [
            "ping", "-c", str(count),
            "-W", str(max(1, int(timeout))), str(host)
        ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=count * timeout + 5,
            errors="replace"
        )
        output = result.stdout + "\n" + result.stderr

    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "status": "failed",
            "reachable": False,
            "rtt_ms": None,
            "jitter_ms": None,
            "packet_loss_percent": 100.0,
            "sent": count,
            "received": 0,
            "error": "Ping command timed out"
        }

    except OSError as exc:
        return {
            "host": host,
            "status": "failed",
            "reachable": False,
            "rtt_ms": None,
            "jitter_ms": None,
            "packet_loss_percent": 100.0,
            "sent": count,
            "received": 0,
            "error": str(exc)
        }

    times = [
        float(value)
        for value in re.findall(
            r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms",
            output,
            re.IGNORECASE
        )
    ]

    if platform.system().lower() == "windows":
        sent_match = re.search(r"Sent\s*=\s*(\d+)", output, re.I)
        received_match = re.search(r"Received\s*=\s*(\d+)", output, re.I)

        sent = int(sent_match.group(1)) if sent_match else count
        received = int(received_match.group(1)) if received_match else len(times)
        if not times and "unreachable" in output.lower():
            received = 0
    else:
        sent_match = re.search(r"(\d+)\s+packets transmitted", output, re.I)
        received_match = re.search(r"(\d+)\s+(?:packets )?received", output, re.I)

        sent = int(sent_match.group(1)) if sent_match else count
        received = int(received_match.group(1)) if received_match else len(times)

    received = min(received, sent)
    packet_loss = ((sent - received) / sent) * 100 if sent else 100.0

    average_rtt = statistics.mean(times) if times else None

    jitter = (
        statistics.mean(
            abs(times[i] - times[i - 1])
            for i in range(1, len(times))
        )
        if len(times) > 1 else 0.0 if times else None
    )

    reachable = received > 0

    return {
        "host": host,
        "status": "failed" if not reachable else (
            "slow" if packet_loss > 0 else "healthy"
        ),
        "reachable": reachable,
        "rtt_ms": round(average_rtt, 2) if average_rtt is not None else None,
        "min_rtt_ms": round(min(times), 2) if times else None,
        "max_rtt_ms": round(max(times), 2) if times else None,
        "jitter_ms": round(jitter, 2) if jitter is not None else None,
        "packet_loss_percent": round(packet_loss, 2),
        "sent": sent,
        "received": received,
        "error": None if reachable else "Host unreachable or ICMP blocked"
    }


def run_ping_probe(host="8.8.8.8", count=4, timeout=2):
    return ping_host(host, count, timeout)


def run(host="8.8.8.8", count=4, timeout=2):
    return run_ping_probe(host, count, timeout)


if __name__ == "__main__":
    import json
    print(json.dumps(run_ping_probe(), indent=2))