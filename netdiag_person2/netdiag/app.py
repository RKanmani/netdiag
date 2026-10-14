"""Streamlit dashboard. Run with:  streamlit run app.py"""
import json
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

import live
import mock_runner
import storage
from app_helpers import COLORS, ICONS, STATE_LABEL, classify

try:                                   # use the real runner/verdict once they exist
    import runner as real_runner
    import verdict as real_verdict
    HAVE_REAL, IMPORT_ERROR = True, ""
except ImportError as exc:
    HAVE_REAL, IMPORT_ERROR = False, str(exc)

BASE = Path(__file__).parent
LABELS = {"wifi": "WiFi / Router", "dns": "DNS", "tcp": "TCP", "tls": "TLS", "http": "HTTP"}

st.set_page_config(page_title="Network Diagnostic Tool", page_icon="🌐", layout="wide")
cfg = json.loads((BASE / "config.json").read_text())
hist_path = BASE / cfg["history_file"]


def waterfall(results):
    """One bar per layer, each starting where the previous one ended."""
    fig = go.Figure()
    start = 0.0
    for r in results:
        state = classify(r, cfg)
        dur = r.get("time_ms") or 0
        fig.add_trace(go.Bar(
            y=[LABELS[r["layer"]]], x=[max(dur, 0.5)], base=[start], orientation="h",
            marker_color=COLORS[state],
            text=[f"{dur:.0f} ms" if dur else STATE_LABEL[state]], textposition="auto",
            hovertext=[r["detail"]], hoverinfo="text", showlegend=False))
        start += dur
    fig.update_layout(title="Where the time went (ms)", height=320,
                      xaxis_title="Cumulative time (ms)", barmode="overlay",
                      yaxis=dict(autorange="reversed"), margin=dict(l=10, r=10, t=50, b=10))
    return fig


def show_verdict(v):
    text = f"**{v['headline']}**  \n{v['explanation']}"
    {"ok": st.success, "warn": st.warning, "bad": st.error}.get(v["status"], st.info)(text)


def show_cards(results):
    cols = st.columns(len(results))
    for col, r in zip(cols, results):
        state = classify(r, cfg)
        with col.container(border=True):
            st.markdown(f"**{ICONS[state]} {LABELS[r['layer']]}**")
            st.metric("Time", f"{r['time_ms']:.0f} ms" if r.get("time_ms") is not None else "-",
                      STATE_LABEL[state], delta_color="off")
            st.caption(r["detail"] if not r.get("error") or state != "fail"
                       else f"{r['detail']} ({r['error']})")


# ---------- sidebar ----------
st.sidebar.header("Settings")
use_mock = st.sidebar.checkbox("Use mock data", value=not HAVE_REAL, disabled=not HAVE_REAL)
scenario = st.sidebar.selectbox("Mock scenario", mock_runner.SCENARIOS) if use_mock else None
if not HAVE_REAL:
    st.sidebar.caption(f"Real runner unavailable, using mock data: {IMPORT_ERROR}")
live_interval = st.sidebar.slider("Live interval (s)", 5, 60, 15)
st.sidebar.caption(f"Test domain: {cfg['test_domain']}  \nDNS server: {cfg['dns_server']}")


def run_once():
    if use_mock:
        r = mock_runner.run_all(cfg, scenario)
        return r, mock_runner.decide(r, cfg)
    r = real_runner.run_all(cfg)
    return r, real_verdict.decide(r, cfg)


# ---------- main ----------
st.title("🌐 Why is my internet slow?")
st.write("Click **Run Diagnosis** to test WiFi, DNS, TCP, TLS and HTTP in order.")

if st.button("▶ Run Diagnosis", type="primary"):
    with st.spinner("Testing each layer..."):
        results, verdict = run_once()
    storage.append_run(results, verdict, hist_path)
    st.session_state["last"] = (results, verdict)

if "last" in st.session_state:
    results, verdict = st.session_state["last"]
    show_verdict(verdict)
    show_cards(results)
    st.plotly_chart(waterfall(results), width="stretch")

st.divider()
st.subheader("Live mode")
if st.toggle("Run diagnosis automatically"):
    live.render_live(run_once, cfg, live_interval)

st.divider()
st.subheader("History of past runs")
df = storage.load_history(hist_path)
if df.empty:
    st.caption("No runs yet.")
else:
    st.dataframe(df.iloc[::-1])
    if len(df) > 1:
        fig = go.Figure(go.Scatter(x=df["timestamp"], y=df["total_ms"], mode="lines+markers"))
        fig.update_layout(title="Total time per run (ms)", height=280,
                          margin=dict(l=10, r=10, t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    c1, c2 = st.columns(2)
    c1.download_button("Download history.csv", df.to_csv(index=False), "history.csv")
    if c2.button("Clear history"):
        storage.clear_history(hist_path)
        st.rerun()