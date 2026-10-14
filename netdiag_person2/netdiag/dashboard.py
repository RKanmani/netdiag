import html
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runner import run_diagnosis

HOST = "127.0.0.1"
PORT = 8765

LAYERS = [
    ("wifi", "Wi-Fi Gateway", "wifi"),
    ("ping", "Internet Ping", "activity"),
    ("dns", "DNS Lookup", "globe"),
    ("tcp", "TCP Connection", "git-branch"),
    ("tls", "TLS Security", "shield-check"),
    ("http", "HTTPS Response", "browser"),
]


def safe(value):
    return html.escape(str(value if value is not None else "—"))


def get_status(data):
    status = str(data.get("status", "")).lower()

    if status in ("failed", "failure", "error", "unreachable"):
        return "failed"

    if data.get("ok") is False or data.get("reachable") is False:
        return "failed"

    if data.get("error"):
        return "failed"

    if status in ("slow", "warning", "warn"):
        return "slow"

    if (data.get("packet_loss_percent") or 0) >= 5:
        return "slow"

    return "healthy"


def get_latency(data):
    value = data.get("time_ms")
    if value is None:
        value = data.get("rtt_ms")

    try:
        return f"{float(value):.1f} ms"
    except (TypeError, ValueError):
        return "N/A"


def make_card(key, title, data):
    status = get_status(data)
    latency = get_latency(data)

    status_label = {
        "healthy": "HEALTHY",
        "slow": "SLOW",
        "failed": "FAILED",
    }[status]

    detail = data.get("detail") or data.get("error") or ""

    if key == "wifi":
        loss = data.get("packet_loss_percent")
        if loss is not None:
            detail = f"Gateway packet loss: {loss}%"

    if key == "ping":
        loss = data.get("packet_loss_percent")
        if loss is not None:
            detail = f"Packet loss: {loss}%"

    if key == "tls":
        extra = data.get("extra", {})
        if isinstance(extra, dict):
            days = extra.get("cert_days_left")
            if days is not None:
                detail = f"Certificate expires in {days} days"

    if key == "http":
        extra = data.get("extra", {})
        if isinstance(extra, dict):
            code = extra.get("status")
            if code is not None:
                detail = f"HTTP status code: {code}"

    icon = {
        "wifi": "⌁",
        "ping": "◉",
        "dns": "◇",
        "tcp": "⇄",
        "tls": "⬡",
        "http": "↗",
    }.get(key, "●")

    return f"""
    <article class="probe {status}">
      <div class="probe-top">
        <div class="probe-icon">{icon}</div>
        <span class="pill {status}"><span class="dot"></span>{status_label}</span>
      </div>
      <div class="probe-name">{safe(title)}</div>
      <div class="latency">{safe(latency)}</div>
      <div class="probe-detail">{safe(detail or "Check completed")}</div>
      <div class="mini-line"><span></span></div>
    </article>
    """


def build_page():
    try:
        report = run_diagnosis()
        probes = report.get("probes", {})
        verdict = report.get("verdict", {})
        overall = report.get("status", verdict.get("status", "healthy"))
        headline = report.get("headline", verdict.get("headline", "Network check complete"))
        explanation = report.get(
            "explanation",
            verdict.get("explanation", "Review the diagnostic results below.")
        )
        target = report.get("target", "Configured target")
    except Exception as exc:
        probes = {}
        overall = "failed"
        headline = "Diagnostic run failed"
        explanation = str(exc)
        target = "Unavailable"

    if overall not in ("healthy", "slow", "failed"):
        overall = "failed"

    cards = "".join(
        make_card(key, title, probes.get(key, {}))
        for key, title, _ in LAYERS
    )

    score = {
        "healthy": 100,
        "slow": 65,
        "failed": 25,
    }.get(overall, 0)

    label = {
        "healthy": "ALL SYSTEMS GO",
        "slow": "ATTENTION NEEDED",
        "failed": "ISSUE DETECTED",
    }[overall]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>NetDiag | Network Health Center</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #080d18;
  --panel: #111a2b;
  --border: #24324a;
  --muted: #8fa2bd;
  --text: #edf5ff;
  --cyan: #50d9f5;
  --green: #42e6a4;
  --amber: #ffc66d;
  --red: #ff6d86;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; min-height: 100vh; color: var(--text);
  background:
    radial-gradient(ellipse at 12% 0%, #12304a 0, transparent 35%),
    radial-gradient(ellipse at 100% 35%, #192344 0, transparent 32%),
    var(--bg);
  font-family: Inter, "Segoe UI", Arial, sans-serif;
}}
main {{ max-width: 1180px; margin: auto; padding: 30px 24px 48px; }}
header {{ display:flex; align-items:center; justify-content:space-between; gap:20px; flex-wrap:wrap; margin-bottom:28px; }}
.brand {{ display:flex; gap:13px; align-items:center; }}
.logo {{
  display:grid; place-items:center; width:48px; height:48px; border-radius:15px;
  color:var(--cyan); font-size:27px; font-weight:800;
  background:#102a3b; border:1px solid #24506a;
  box-shadow:0 0 24px #37c8f522;
}}
h1 {{ font-size:22px; margin:0; letter-spacing:2px; }}
.subtitle {{ color:var(--muted); font-size:12px; margin-top:5px; letter-spacing:1.5px; }}
.actions {{ display:flex; gap:12px; align-items:center; }}
.live {{ color:var(--green); font-size:12px; letter-spacing:1px; }}
.live:before {{ content:""; display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--green); margin-right:8px; box-shadow:0 0 12px var(--green); }}
button {{
  background:linear-gradient(135deg,#43d8ee,#56aaff); color:#07121f;
  border:0; border-radius:10px; padding:12px 17px; font-weight:800;
  cursor:pointer; box-shadow:0 6px 24px #38bfe522;
}}
.hero {{
  display:grid; grid-template-columns:220px 1fr; gap:28px; align-items:center;
  padding:30px; border:1px solid var(--border); border-radius:22px;
  background:linear-gradient(120deg,#111d30ee,#0c1525ee);
  box-shadow:0 20px 65px #0003; position:relative; overflow:hidden;
}}
.hero:after {{
  content:""; position:absolute; right:-60px; top:-100px; width:300px; height:300px;
  border:1px solid #50d9f51a; border-radius:50%;
  box-shadow:0 0 0 35px #50d9f508,0 0 0 70px #50d9f505;
  pointer-events:none;
}}
.gauge {{
  width:185px; height:185px; border-radius:50%; display:grid; place-items:center;
  background:conic-gradient(var(--green) {score * 3.6}deg,#24344b 0);
  padding:8px; box-shadow:0 0 32px #42e6a422;
}}
.gauge-inner {{
  width:100%; height:100%; border-radius:50%; background:#101a2b;
  display:flex; flex-direction:column; align-items:center; justify-content:center;
}}
.score {{ font-size:48px; line-height:1.1; font-weight:800; letter-spacing:-2px; }}
.outof {{ color:var(--muted); font-size:12px; }}
.eyebrow {{ color:var(--cyan); font-size:11px; letter-spacing:2px; font-weight:800; }}
.hero h2 {{ font-size:clamp(22px,3vw,34px); margin:10px 0; }}
.hero p {{ color:var(--muted); line-height:1.6; margin:0; max-width:560px; }}
.target {{ display:inline-block; margin-top:17px; padding:8px 11px; border:1px solid var(--border); border-radius:8px; color:#c4d7ef; font-size:12px; }}
.section-head {{ display:flex; justify-content:space-between; align-items:end; gap:12px; margin:30px 0 15px; }}
.section-head h3 {{ margin:0; font-size:17px; }}
.section-head span {{ color:var(--muted); font-size:12px; }}
.grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:15px; }}
.probe {{ border:1px solid var(--border); background:linear-gradient(145deg,#121d30,#0d1524); border-radius:17px; padding:19px; min-width:0; transition:transform .2s,border-color .2s; }}
.probe:hover {{ transform:translateY(-3px); border-color:#4b7193; }}
.probe-top {{ display:flex; justify-content:space-between; align-items:center; gap:8px; }}
.probe-icon {{ display:grid; place-items:center; width:42px; height:42px; border-radius:12px; background:#172b40; color:var(--cyan); font-size:24px; }}
.pill {{ display:inline-flex; align-items:center; gap:6px; font-size:10px; letter-spacing:.7px; font-weight:800; padding:6px 8px; border-radius:20px; }}
.dot {{ width:6px; height:6px; border-radius:50%; background:currentColor; }}
.healthy .pill {{ color:var(--green); background:#123329; }}
.slow .pill {{ color:var(--amber); background:#382b18; }}
.failed .pill {{ color:var(--red); background:#3a1d2a; }}
.probe-name {{ color:#c0cee1; font-size:13px; margin-top:19px; }}
.latency {{ font-size:31px; font-weight:750; letter-spacing:-1px; margin:6px 0; }}
.probe-detail {{ color:var(--muted); font-size:12px; min-height:18px; overflow-wrap:anywhere; }}
.mini-line {{ height:3px; margin-top:18px; border-radius:8px; background:#243149; overflow:hidden; }}
.mini-line span {{ display:block; width:70%; height:100%; border-radius:8px; background:var(--green); }}
.probe.slow .mini-line span {{ background:var(--amber); width:48%; }}
.probe.failed .mini-line span {{ background:var(--red); width:20%; }}
.insight {{ margin-top:22px; padding:19px 21px; border-radius:15px; border:1px solid var(--border); background:#0e1727; display:flex; gap:15px; align-items:flex-start; }}
.insight-icon {{ color:var(--cyan); font-size:22px; }}
.insight h3 {{ margin:0 0 6px; font-size:13px; letter-spacing:1px; }}
.insight p {{ color:var(--muted); margin:0; font-size:13px; line-height:1.6; }}
footer {{ display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px; color:#657b99; font-size:11px; margin-top:22px; }}
@media(max-width:760px) {{
  main {{ padding:20px 14px; }}
  .hero {{ grid-template-columns:1fr; padding:23px; }}
  .gauge {{ width:150px; height:150px; }}
  .score {{ font-size:38px; }}
  .grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
}}
@media(max-width:470px) {{ .grid {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<main>
<header>
  <div class="brand">
    <div class="logo">N<span style="color:white">.</span></div>
    <div><h1>NETDIAG</h1><div class="subtitle">NETWORK HEALTH CENTER</div></div>
  </div>
  <div class="actions"><span class="live">DIAGNOSTICS READY</span><button onclick="location.reload()">↻ Run checks</button></div>
</header>

<section class="hero">
  <div class="gauge"><div class="gauge-inner">
    <div class="score">{score}</div><div class="outof">OUT OF 100</div>
  </div></div>
  <div>
    <div class="eyebrow">{safe(label)}</div>
    <h2>{safe(headline)}</h2>
    <p>{safe(explanation)}</p>
    <div class="target">⌁ Target: {safe(target)}</div>
  </div>
</section>

<div class="section-head"><h3>Diagnostic layers</h3><span>6 checks · Real probe results</span></div>
<section class="grid">{cards}</section>

<section class="insight">
  <div class="insight-icon">✳</div>
  <div><h3>DIAGNOSTIC INSIGHT</h3>
  <p>{safe(explanation)} The dashboard refreshes automatically every 60 seconds. Click “Run checks” to run a new diagnosis.</p></div>
</section>

<footer><span>NETDIAG · Network diagnostics</span><span>Local dashboard · 127.0.0.1:{PORT}</span></footer>
</main>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return

        page = build_page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, format_string, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    url = f"http://{HOST}:{PORT}"
    print(f"NetDiag dashboard running at {url}")
    print("Keep this terminal open. Press Ctrl+C to stop.")

    threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NetDiag dashboard...")
        server.server_close()