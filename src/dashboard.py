# EN: Streamlit SOC dashboard — visual triage for Nmap_AI scan results.
# VI: Dashboard SOC Streamlit — trực quan hoá kết quả triage của Nmap_AI.

import datetime
import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULT_DIR = ROOT_DIR / "result"

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#28a745",
}

TRIAGE_COLORS = {
    "Immediate Action": "#dc3545",
    "Urgent":           "#fd7e14",
    "Investigate":      "#ffc107",
    "Monitor":          "#17a2b8",
}

st.set_page_config(
    page_title="Nmap AI — SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("⚙️ Filters")
    show_all_hosts = st.checkbox("Show all hosts (including normal)", value=False)
    severity_filter = st.multiselect(
        "Filter by severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    st.divider()
    st.caption("Run a new scan:")
    st.code("python3 src/main.py full", language="bash")
    st.caption("Monitor mode:")
    st.code("python3 src/main.py monitor", language="bash")

# ── Header ────────────────────────────────────────────────────────────────────
title_col, refresh_col = st.columns([9, 1])
with title_col:
    st.title("🛡️ Nmap AI — SOC Dashboard")
with refresh_col:
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
        st.rerun()

# ── Data loaders ──────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_predictions():
    path = RESULT_DIR / "predictions.csv"
    if not path.exists():
        return None, None
    dataframe = pd.read_csv(path)
    mtime = path.stat().st_mtime
    last_update = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    return dataframe, last_update


@st.cache_data(ttl=30)
def load_baseline():
    path = RESULT_DIR / "baseline.json"
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as baseline_file:
        return json.load(baseline_file)


@st.cache_data(ttl=30)
def load_feature_importance():
    path = RESULT_DIR / "feature_importance.txt"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


@st.cache_data(ttl=30)
def load_network_patterns():
    path = RESULT_DIR / "network_patterns.json"
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as patterns_file:
        return json.load(patterns_file)


df, last_update = load_predictions()

if df is None:
    st.warning("No scan results found. Run `python3 src/main.py full` first.")
    st.stop()

st.caption(f"Last scan results: {last_update}")

# ── Summary Metrics ───────────────────────────────────────────────────────────
st.subheader("Summary")

suspicious_df = df[df["prediction"] == "suspicious"] if "prediction" in df.columns else pd.DataFrame()
total_hosts = len(df)
suspicious_count = len(suspicious_df)
critical_count = int((df["severity"] == "CRITICAL").sum()) if "severity" in df.columns else 0
high_count = int((df["severity"] == "HIGH").sum()) if "severity" in df.columns else 0
immediate_count = int((df["triage_status"] == "Immediate Action").sum()) if "triage_status" in df.columns else 0
investigate_count = int((df["triage_status"] == "Investigate").sum()) if "triage_status" in df.columns else 0

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Total Hosts", total_hosts)
m2.metric("Suspicious", suspicious_count)
m3.metric("🔴 CRITICAL", critical_count)
m4.metric("🟠 HIGH", high_count)
m5.metric("⚡ Immediate Action", immediate_count)
m6.metric("🔍 Investigate", investigate_count)

st.divider()

# ── Distribution Charts ───────────────────────────────────────────────────────
chart_left, chart_right = st.columns(2)

with chart_left:
    st.subheader("Severity Distribution")
    if "severity" in df.columns:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_counts = df["severity"].value_counts().reindex(severity_order, fill_value=0)
        fig_severity = go.Figure(go.Bar(
            x=severity_counts.index.tolist(),
            y=severity_counts.values.tolist(),
            marker_color=[SEVERITY_COLORS.get(s, "#999") for s in severity_counts.index],
            text=severity_counts.values.tolist(),
            textposition="outside",
        ))
        fig_severity.update_layout(margin=dict(t=10, b=10), height=260, showlegend=False)
        st.plotly_chart(fig_severity, use_container_width=True)

with chart_right:
    st.subheader("Triage Distribution")
    if "triage_status" in df.columns:
        triage_df = df[~df["triage_status"].isin(["—", ""])]
        if not triage_df.empty:
            triage_counts = triage_df["triage_status"].value_counts()
            fig_triage = go.Figure(go.Bar(
                x=triage_counts.index.tolist(),
                y=triage_counts.values.tolist(),
                marker_color=[TRIAGE_COLORS.get(t, "#999") for t in triage_counts.index],
                text=triage_counts.values.tolist(),
                textposition="outside",
            ))
            fig_triage.update_layout(margin=dict(t=10, b=10), height=260, showlegend=False)
            st.plotly_chart(fig_triage, use_container_width=True)
        else:
            st.info("No suspicious hosts detected.")

st.divider()

# ── Risk Score Chart ──────────────────────────────────────────────────────────
st.subheader("Risk Score by Host")
if "risk_score" in df.columns and "ip" in df.columns:
    risk_df = df[["ip", "hostname", "risk_score", "severity"]].copy()
    risk_df["host_label"] = risk_df.apply(
        lambda r: f"{r['ip']} ({r['hostname']})" if pd.notna(r.get("hostname")) and str(r.get("hostname", "")).strip() else r["ip"],
        axis=1,
    )
    risk_df = risk_df.sort_values("risk_score", ascending=True)
    fig_risk = go.Figure(go.Bar(
        x=risk_df["risk_score"].tolist(),
        y=risk_df["host_label"].tolist(),
        orientation="h",
        marker_color=[SEVERITY_COLORS.get(s, "#999") for s in risk_df["severity"].tolist()],
        text=[f"{s}/100" for s in risk_df["risk_score"].tolist()],
        textposition="outside",
    ))
    fig_risk.update_layout(
        xaxis=dict(range=[0, 112], title="Risk Score (0–100)"),
        margin=dict(t=10, b=10, l=200),
        height=max(220, len(risk_df) * 32),
    )
    st.plotly_chart(fig_risk, use_container_width=True)

# ── Anomaly Score Chart (shown only when IF scores are non-trivial) ───────────
if "anomaly_score" in df.columns and df["anomaly_score"].max() > 0.01:
    st.subheader("Isolation Forest Anomaly Score")
    st.caption("Unsupervised anomaly detector — 0 = normal profile, 1 = highly anomalous. Flags hosts that don't match learned patterns, even when the classifier says normal.")
    anomaly_df = df[["ip", "hostname", "anomaly_score", "prediction"]].copy()
    anomaly_df["host_label"] = anomaly_df.apply(
        lambda r: f"{r['ip']} ({r['hostname']})" if pd.notna(r.get("hostname")) and str(r.get("hostname", "")).strip() else r["ip"],
        axis=1,
    )
    anomaly_df = anomaly_df.sort_values("anomaly_score", ascending=True)
    fig_anomaly = go.Figure(go.Bar(
        x=anomaly_df["anomaly_score"].tolist(),
        y=anomaly_df["host_label"].tolist(),
        orientation="h",
        marker_color=["#dc3545" if p == "suspicious" else "#6c757d" for p in anomaly_df["prediction"].tolist()],
        text=[f"{s:.2f}" for s in anomaly_df["anomaly_score"].tolist()],
        textposition="outside",
    ))
    fig_anomaly.update_layout(
        xaxis=dict(range=[0, 1.15], title="Anomaly Score"),
        margin=dict(t=10, b=10, l=200),
        height=max(220, len(anomaly_df) * 32),
    )
    st.plotly_chart(fig_anomaly, use_container_width=True)

st.divider()

# ── Host Details Table ────────────────────────────────────────────────────────
st.subheader("Host Details")

display_df = df if show_all_hosts else suspicious_df
if "severity" in display_df.columns and severity_filter:
    display_df = display_df[display_df["severity"].isin(severity_filter)]

if display_df.empty:
    if show_all_hosts:
        st.info("No hosts match the current filter.")
    else:
        st.success("No suspicious hosts detected.")
else:
    table_cols = [c for c in [
        "ip", "hostname", "prediction", "probability_suspicious",
        "risk_score", "severity", "triage_status", "asset_type",
        "anomaly_score", "open_port_count", "risky_port_count", "top_risk_ports",
        "alerts",
    ] if c in display_df.columns]

    table_df = display_df[table_cols].sort_values(
        "risk_score" if "risk_score" in display_df.columns else table_cols[0],
        ascending=False,
    ).reset_index(drop=True)

    def _color_severity_cell(cell_value):
        color_map = {
            "CRITICAL": "background-color: #dc3545; color: white",
            "HIGH":     "background-color: #fd7e14; color: white",
            "MEDIUM":   "background-color: #ffc107; color: black",
            "LOW":      "background-color: #28a745; color: white",
        }
        return color_map.get(str(cell_value), "")

    if "severity" in table_df.columns:
        try:
            styled = table_df.style.map(_color_severity_cell, subset=["severity"])
        except AttributeError:
            styled = table_df.style.applymap(_color_severity_cell, subset=["severity"])
        st.dataframe(styled, use_container_width=True)
    else:
        st.dataframe(table_df, use_container_width=True)

st.divider()

# ── Network Attack Patterns ───────────────────────────────────────────────────
st.subheader("Network-Level Attack Patterns")
pattern_data = load_network_patterns()
if pattern_data is None:
    st.info("No pattern data found. Run `python3 src/main.py full` to generate.")
elif not pattern_data:
    st.success("No cross-host attack patterns detected in the last scan.")
else:
    st.caption(f"{len(pattern_data)} pattern(s) detected across the network.")
    for detected_pattern in pattern_data:
        severity_color = SEVERITY_COLORS.get(detected_pattern["severity"], "#999")
        pattern_header = f"[{detected_pattern['severity']}] {detected_pattern['name']} — {detected_pattern['affected_count']} host(s)"
        with st.expander(pattern_header):
            st.markdown(f"**Description:** {detected_pattern['description']}")
            if detected_pattern.get("mitre"):
                st.markdown(f"**MITRE:** `{detected_pattern['mitre']}`")
            st.markdown(f"**Recommendation:** {detected_pattern['recommendation']}")
            host_rows = [
                {"ip": host_entry["ip"], "hostname": host_entry.get("hostname", "")}
                for host_entry in detected_pattern["affected_hosts"]
            ]
            st.dataframe(pd.DataFrame(host_rows), use_container_width=True)

st.divider()

# ── Baseline Data ─────────────────────────────────────────────────────────────
st.subheader("Baseline State")
baseline_data = load_baseline()
if baseline_data:
    st.caption(f"Baseline tracks {len(baseline_data)} host(s) — compared on every scan to detect new hosts, opened/closed ports, and service version changes.")
    with st.expander("View baseline hosts"):
        baseline_rows = []
        for ip_addr, host_info in baseline_data.items():
            baseline_rows.append({
                "ip":           ip_addr,
                "hostname":     host_info.get("hostname", ""),
                "port_count":   len(host_info.get("ports", [])),
                "ports":        ", ".join(str(p) for p in host_info.get("ports", [])),
            })
        st.dataframe(pd.DataFrame(baseline_rows), use_container_width=True)
else:
    st.info("No baseline saved yet. Run a scan to create the baseline.")

st.divider()

# ── Feature Importance ────────────────────────────────────────────────────────
st.subheader("Top AI Features")
fi_content = load_feature_importance()
if fi_content:
    st.code(fi_content, language="text")
else:
    st.info("No feature importance report found. Run `python3 src/main.py full` first.")
