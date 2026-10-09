"""DNS probe: hand-built A query over UDP port 53. time_ms = send -> valid reply."""
import os
import re
import secrets
import socket
import struct
import subprocess
import time
import ipaddress
from pathlib import Path

RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def system_dns():
    try:
        if os.name == "nt":
            out = subprocess.run(["ipconfig", "/all"], capture_output=True,
                                 text=True, timeout=5).stdout
            found = []
            for block in re.split(r"\n(?=\S)", out):
                if "Media disconnected" in block:
                    continue
                m = re.search(r"DNS Servers[ .]*:[ \t]*(.*(?:\n[ \t]+[0-9a-fA-F:.%]+[ \t]*(?=\n|$))*)", block)
                if not m:
                    continue
                for a in re.findall(r"[0-9a-fA-F:.]+(?:%\d+)?", m.group(1)):
                    try:
                        ip = ipaddress.ip_address(a.split("%")[0])
                    except ValueError:
                        continue
                    if ip.is_loopback or a.lower().startswith("fec0:"):
                        continue
                    found.append(a)
                if found:
                    break
            v4 = [a for a in found if "." in a]
            return (v4 or found or [None])[0]
        out = Path("/etc/resolv.conf").read_text()
        for a in re.findall(r"^nameserver\s+(\S+)", out, re.M):
            if a == "127.0.0.53" or not a.startswith("127."):
                return a
        return None
    except Exception:
        return None


def build_query(domain, qid):
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.rstrip(".").encode("idna").split(b"."):
        if not 0 < len(label) < 64:
            raise ValueError("invalid domain name")
        question += bytes([len(label)]) + label
    return header + question + b"\x00" + struct.pack("!HH", 1, 1)


def skip_name(data, off):
    while True:
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += n + 1


def parse_response(data, qid):
    """None if the packet is not our reply, else (rcode, truncated, ips)."""
    if len(data) < 12:
        return None
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != qid or not flags & 0x8000:
        return None
    off = 12
    for _ in range(qd):
        off = skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = skip_name(data, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return flags & 0xF, bool(flags & 0x200), ips


def probe_dns(domain, server="auto", timeout=3):
    result = {"layer": "dns", "ok": False, "time_ms": None,
              "detail": "", "error": None, "extra": {}}
    sock = None
    try:
        if server in (None, "", "auto"):
            server = system_dns()
            if not server:
                result.update(detail="could not find the system DNS server",
                              error="no dns server")
                return result
        result["extra"]["server"] = server

        qid = secrets.randbelow(65536)
        try:
            query = build_query(domain, qid)
        except (ValueError, UnicodeError):
            result.update(detail=f"'{domain}' is not a valid domain name",
                          error="invalid domain")
            return result

        family, _, _, _, addr = socket.getaddrinfo(
            server, 53, type=socket.SOCK_DGRAM)[0]
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.connect(addr)

        start = time.perf_counter()
        deadline = start + timeout
        sock.send(query)
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError
            sock.settimeout(remaining)
            data = sock.recv(4096)
            ms = (time.perf_counter() - start) * 1000
            parsed = parse_response(data, qid)
            if parsed:
                break
        rcode, truncated, ips = parsed

        if rcode == 3:
            result.update(detail=f"{domain} does not exist (queried {server})",
                          error="NXDOMAIN")
        elif rcode != 0:
            result.update(detail=f"DNS server {server} returned an error",
                          error=RCODES.get(rcode, f"rcode {rcode}"))
        elif not ips:
            result.update(detail=f"no IPv4 address returned for {domain}",
                          error="truncated response" if truncated else "NODATA")
        else:
            result.update(ok=True, time_ms=round(ms, 1),
                          detail=f"{domain} -> {ips[0]} via {server} in {ms:.0f} ms",
                          extra={"ip": ips[0], "ips": ips, "server": server})
    except TimeoutError:
        result.update(detail=f"DNS server {server} did not answer within {timeout}s",
                      error="timeout")
    except ConnectionRefusedError:
        result.update(detail=f"DNS server {server} refused the connection (port 53 closed)",
                      error="connection refused")
    except (struct.error, IndexError) as e:
        result.update(detail="DNS reply could not be understood", error=f"malformed: {e}")
    except OSError as e:
        result.update(detail=f"could not reach DNS server {server}", error=str(e))
    except Exception as e:
        result.update(detail="could not run DNS test", error=str(e))
    finally:
        if sock:
            sock.close()
    return result


if __name__ == "__main__":
    print(probe_dns("www.google.com"))