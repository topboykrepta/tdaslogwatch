from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
ALERTS_PATH = OUTPUTS_DIR / "alerts.json"


def _safe_read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    try:
        # pandas handles ISO8601 like 2026-01-26T10:03:00Z
        ts = pd.to_datetime(value, errors="coerce", utc=True)
        if pd.isna(ts):
            return None
        return ts.to_pydatetime()
    except Exception:
        return None


def _finding_timestamp(finding: Dict[str, Any]) -> Optional[datetime]:
    if isinstance(finding.get("ts"), str):
        return _as_datetime(finding.get("ts"))
    event = finding.get("event")
    if isinstance(event, dict) and isinstance(event.get("ts"), str):
        return _as_datetime(event.get("ts"))
    return None


def _severity_from_score(score: Any) -> str:
    try:
        s = float(score)
    except Exception:
        s = 0.0

    if s >= 7:
        return "high"
    if s >= 3:
        return "medium"
    return "low"


def _run_pipeline() -> tuple[int, str]:
    cmd = [sys.executable, str(PROJECT_ROOT / "src" / "main.py")]
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output.strip()


st.set_page_config(
    page_title="LogWatch TDAS Dashboard",
    layout="wide",
)

st.title("LogWatch TDAS — Dashboard")
st.caption("Explore findings in outputs/alerts.json")

with st.sidebar:
    st.header("Controls")

    if st.button("Run pipeline (generate outputs)", type="primary"):
        code, out = _run_pipeline()
        if code == 0:
            st.success("Pipeline completed.")
        else:
            st.error(f"Pipeline failed (exit {code}).")
        if out:
            st.code(out)

    st.divider()

    if not ALERTS_PATH.exists():
        st.warning("No outputs/alerts.json found yet.")
        st.info("Click 'Run pipeline' above, or run: python src/main.py")
        st.stop()


alerts = _safe_read_json(ALERTS_PATH)
if not isinstance(alerts, list):
    st.error("outputs/alerts.json is not a JSON list.")
    st.stop()

if len(alerts) == 0:
    st.info("No findings in outputs/alerts.json")
    st.stop()

rows = []
for idx, finding in enumerate(alerts):
    if not isinstance(finding, dict):
        continue

    ts = _finding_timestamp(finding)
    score = finding.get("score")

    rows.append(
        {
            "id": idx,
            "timestamp": ts,
            "rule": finding.get("rule", "unknown"),
            "etype": finding.get("etype", "unknown"),
            "entity": finding.get("entity", "unknown"),
            "score": float(score) if isinstance(score, (int, float, str)) and str(score).strip() else 0.0,
            "severity": _severity_from_score(score),
            "event": finding.get("event", {}),
        }
    )

df = pd.DataFrame(rows)

# Sidebar filters
with st.sidebar:
    rule_options = sorted(df["rule"].dropna().unique().tolist())
    etype_options = sorted(df["etype"].dropna().unique().tolist())
    severity_order = ["low", "medium", "high"]
    severity_options = [s for s in severity_order if s in set(df["severity"].dropna())]

    selected_rules = st.multiselect("Rule", rule_options, default=rule_options)
    selected_etypes = st.multiselect("Entity type", etype_options, default=etype_options)
    selected_sev = st.multiselect("Severity", severity_options, default=severity_options)

    query = st.text_input("Search entity", "")

filtered = df[
    df["rule"].isin(selected_rules)
    & df["etype"].isin(selected_etypes)
    & df["severity"].isin(selected_sev)
].copy()

if query.strip():
    q = query.strip().lower()
    filtered = filtered[filtered["entity"].astype(str).str.lower().str.contains(q, na=False)]

# KPIs
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total findings", len(df))
c2.metric("Filtered", len(filtered))
c3.metric("Unique entities (filtered)", filtered[["etype", "entity"]].drop_duplicates().shape[0])
if filtered["timestamp"].notna().any():
    c4.metric("Time span", f"{filtered['timestamp'].min().date()} → {filtered['timestamp'].max().date()}")
else:
    c4.metric("Time span", "n/a")

st.divider()

# Ranking
rank = (
    filtered.groupby(["etype", "entity"], dropna=False)["score"]
    .sum()
    .reset_index()
    .sort_values("score", ascending=False)
)

left, right = st.columns([1, 2])

with left:
    st.subheader("Top entities")
    st.dataframe(rank.head(15), use_container_width=True, hide_index=True)

    st.subheader("By severity")
    sev_counts = filtered["severity"].value_counts().reindex(["high", "medium", "low"]).dropna()
    st.bar_chart(sev_counts)

with right:
    st.subheader("Findings")

    show = filtered.copy()
    if show["timestamp"].notna().any():
        show = show.sort_values("timestamp", ascending=False)

    # Table-like view
    display_cols = ["timestamp", "severity", "rule", "etype", "entity", "score"]
    display_cols = [c for c in display_cols if c in show.columns]
    st.dataframe(show[display_cols], use_container_width=True, hide_index=True)

    st.subheader("Inspect a finding")
    selected_id = st.selectbox(
        "Select finding id",
        options=show["id"].tolist(),
        format_func=lambda i: f"#{i} — {show.loc[show['id'] == i, 'rule'].iloc[0]} / {show.loc[show['id'] == i, 'etype'].iloc[0]}:{show.loc[show['id'] == i, 'entity'].iloc[0]}",
    )

    selected_row = df[df["id"] == selected_id].iloc[0].to_dict()
    st.json(
        {
            "timestamp": selected_row.get("timestamp").isoformat() if selected_row.get("timestamp") else None,
            "severity": selected_row.get("severity"),
            "rule": selected_row.get("rule"),
            "etype": selected_row.get("etype"),
            "entity": selected_row.get("entity"),
            "score": selected_row.get("score"),
            "event": selected_row.get("event"),
        }
    )

# Timeline (best-effort)
if filtered["timestamp"].notna().any():
    st.divider()
    st.subheader("Timeline")
    timeline = filtered.dropna(subset=["timestamp"]).copy()
    timeline["minute"] = pd.to_datetime(timeline["timestamp"], utc=True).dt.floor("min")
    counts = timeline.groupby(["minute", "severity"]).size().reset_index(name="count")
    pivot = counts.pivot(index="minute", columns="severity", values="count").fillna(0)
    st.line_chart(pivot)
