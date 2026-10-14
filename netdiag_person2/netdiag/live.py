"""Live mode: re-runs the diagnosis on a timer and plots a rolling graph per layer."""
from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from app_helpers import ICONS, STATE_LABEL, classify

LAYERS = ["wifi", "dns", "tcp", "tls", "http"]
LABELS = {"wifi": "WiFi / Router", "dns": "DNS", "tcp": "TCP", "tls": "TLS", "http": "HTTP"}
LINE = {"wifi": "#1f77b4", "dns": "#9467bd", "tcp": "#ff7f0e", "tls": "#17becf", "http": "#8c564b"}
KEY = "live_buf"


def _row(results):
    by = {r["layer"]: r for r in results}
    row = {"time": datetime.now()}
    for l in LAYERS:
        r = by.get(l)
        ok = r and r.get("ok") and r.get("time_ms") is not None
        row[l] = r["time_ms"] if ok else None
    return row


def _show(buf, cfg):
    results, v = buf["last"]
    msg = f"**{v['headline']}**  \n{v['explanation']}"
    {"ok": st.success, "warn": st.warning, "bad": st.error}.get(v["status"], st.info)(msg)

    cols = st.columns(len(results))
    for col, r in zip(cols, results):
        state = classify(r, cfg)
        ms = f"{r['time_ms']:.0f} ms" if r.get("time_ms") is not None else "-"
        col.metric(f"{ICONS[state]} {LABELS[r['layer']]}", ms, STATE_LABEL[state],
                   delta_color="off")

    rows = buf["rows"]
    fig = go.Figure()
    for l in LAYERS:
        fig.add_trace(go.Scatter(x=[r["time"] for r in rows], y=[r[l] for r in rows],
                                 mode="lines+markers", name=LABELS[l],
                                 line=dict(color=LINE[l]), connectgaps=False))
    fig.update_layout(title=f"Live: last {len(rows)} runs (gaps = layer failed or skipped)",
                      yaxis_title="ms", height=360, margin=dict(l=10, r=10, t=50, b=10))
    st.plotly_chart(fig, width="stretch")


def render_live(run_fn, cfg, interval=15, max_points=60):
    """run_fn() must return (results, verdict)."""
    buf = st.session_state.setdefault(KEY, {"rows": [], "last": None})
    if st.button("Clear live data"):
        buf["rows"].clear()
        buf["last"] = None

    @st.fragment(run_every=interval)
    def tick():
        try:
            with st.spinner("Running live test..."):
                results, verdict = run_fn()
        except Exception as e:
            st.error(f"Live run failed: {e}")
            return
        buf["rows"].append(_row(results))
        del buf["rows"][:-max_points]
        buf["last"] = (results, verdict)
        _show(buf, cfg)

    tick()