"""HTTP probe: time to first byte (TTFB) and status code.

The connection (TCP + TLS) is set up first and NOT timed, so time_ms is the
time from sending the request to receiving the first response headers.
"""
import http.client
import ssl
import time


def probe_http(host, port=443, timeout=8, use_https=True):
    result = {"layer": "http", "ok": False, "time_ms": None,
              "detail": "", "error": None, "extra": {}}
    conn = None
    try:
        if use_https:
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
        conn.connect()

        start = time.perf_counter()
        conn.request("GET", "/", headers={"Host": host,
                                          "User-Agent": "netdiag/1.0",
                                          "Connection": "close"})
        resp = conn.getresponse()                      # headers received = first byte
        ttfb = (time.perf_counter() - start) * 1000
        resp.read()
        total = (time.perf_counter() - start) * 1000

        ok = resp.status < 400                          # 2xx and 3xx count as fine
        result.update(ok=ok, time_ms=round(ttfb, 1),
                      detail=f"HTTP {resp.status} {resp.reason}, TTFB {ttfb:.0f} ms, full page {total:.0f} ms",
                      extra={"status": resp.status, "total_ms": round(total, 1)})
        if not ok:
            result["error"] = f"HTTP status {resp.status}"
    except TimeoutError:
        result.update(detail=f"HTTP request to {host} timed out", error="timeout")
    except Exception as e:
        result.update(detail=f"HTTP request to {host} failed", error=str(e))
    finally:
        if conn:
            conn.close()
    return result


if __name__ == "__main__":
    print(probe_http("www.google.com"))
