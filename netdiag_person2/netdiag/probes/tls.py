"""TLS probe: times the TLS handshake and reads the certificate expiry date.

The TCP connection is made first and NOT timed, so time_ms is the handshake only
(ClientHello -> ServerHello -> certificate -> keys -> Finished).
"""
import socket
import ssl
import time
from datetime import datetime, timezone


def probe_tls(host, port=443, timeout=5, cert_warn_days=14):
    result = {"layer": "tls", "ok": False, "time_ms": None,
              "detail": "", "error": None, "extra": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            start = time.perf_counter()
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                ms = (time.perf_counter() - start) * 1000
                cert = tls.getpeercert()
                version = tls.version()

        expires = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days

        detail = f"{version}, certificate expires in {days_left} days ({expires:%Y-%m-%d})"
        if days_left < cert_warn_days:
            detail += " - EXPIRING SOON"

        result.update(ok=True, time_ms=round(ms, 1), detail=detail,
                      extra={"cert_days_left": days_left, "tls_version": version})

    except ssl.SSLCertVerificationError as e:
        result.update(detail=f"certificate problem for {host}", error=str(e))
    except ssl.SSLError as e:
        result.update(detail=f"TLS handshake failed with {host}", error=str(e))
    except TimeoutError:
        result.update(detail=f"TLS handshake to {host} timed out", error="timeout")
    except Exception as e:
        result.update(detail=f"could not run TLS test on {host}", error=str(e))
    return result


if __name__ == "__main__":
    print(probe_tls("www.google.com"))
