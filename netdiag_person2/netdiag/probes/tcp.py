"""TCP probe: times connect() = three-way handshake (about 1 RTT).
Pass the IP from the DNS probe so DNS time is not mixed in."""
import socket
import time


def probe_tcp(host, port=443, timeout=3):
    result = {"layer": "tcp", "ok": False, "time_ms": None,
              "detail": "", "error": None, "extra": {}}
    sock = None
    try:
        family, stype, proto, _, addr = socket.getaddrinfo(
            host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)[0]
        sock = socket.socket(family, stype, proto)
        sock.settimeout(timeout)

        start = time.perf_counter()
        sock.connect(addr)
        ms = (time.perf_counter() - start) * 1000

        result.update(ok=True, time_ms=round(ms, 1),
                      detail=f"connected to {addr[0]}:{port} in {ms:.0f} ms",
                      extra={"ip": addr[0], "port": port})
    except socket.gaierror as e:
        result.update(detail=f"could not resolve {host}", error=str(e))
    except TimeoutError:
        result.update(detail=f"connection to {host}:{port} timed out after {timeout}s",
                      error="timeout")
    except ConnectionRefusedError:
        result.update(detail=f"{host}:{port} refused the connection",
                      error="connection refused")
    except OSError as e:
        result.update(detail=f"could not connect to {host}:{port}", error=str(e))
    except Exception as e:
        result.update(detail="could not run TCP test", error=str(e))
    finally:
        if sock:
            sock.close()
    return result


if __name__ == "__main__":
    print(probe_tcp("8.8.8.8"))