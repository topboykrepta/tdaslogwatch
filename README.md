# LogWatch TDAS — Threat Detection & Analysis System (Simple)

LogWatch TDAS is a lightweight threat detection and analysis system that ingests common security logs (auth, process, network), runs detection rules, scores suspicious entities, and generates alerts + a human-readable report.

## Features
- ✅ Brute-force detection (failed logins in a short window)
- ✅ IP churn / “impossible travel” proxy (many IPs for one user quickly)
- ✅ Suspicious process detection (LOLBins / risky command patterns)
- ✅ Rare destination detection (unexpected outbound connections)
- ✅ Risk scoring + top suspicious entities
- ✅ Streamlit dashboard (filters + rankings)

## Architecture (simple)
1. **Ingest** JSONL logs (one JSON event per line)
2. **Detect** suspicious events via rule-based detectors
3. **Score** entities (user/IP/host) by severity-weighted findings
4. **Output**
   - `outputs/alerts.json` (machine-readable)
   - `outputs/report.md` (human-readable)
   - Streamlit UI for exploration

## Project Structure
tdas-logwatch/
data/ # sample logs (jsonl)
src/ # detection pipeline
outputs/ # generated alerts + report
app.py # Streamlit dashboard
requirements.txt


## Quick Start
```bash
pip install -r requirements.txt
python src/main.py


Outputs:

outputs/alerts.json

outputs/report.md

Run the Dashboard
streamlit run app.py

Log Event Formats (examples)
Auth events
{"ts":"2026-01-26T10:00:00Z","user":"alice","ip":"41.1.2.3","action":"login","status":"fail"}

Process events
{"ts":"2026-01-26T10:03:00Z","host":"pc1","user":"alice","process":"powershell.exe","cmdline":"powershell -enc ..."}

Network events
{"ts":"2026-01-26T10:02:10Z","host":"pc1","dst":"93.184.216.34","port":443}

Severity Scoring

Weights:

low = 1

medium = 3

high = 7

critical = 10

Entity score = sum(weights of findings affecting that entity)

Roadmap (easy upgrades)

MITRE ATT&CK technique mapping per rule

Baselines per host/user (learn “normal” behavior)

Add GeoIP enrichment (real impossible travel)

Add Sigma-style rule definitions (YAML rules)

Export alerts to Slack/Email/Webhooks

Disclaimer

This project is for educational and defensive security use only.


---

## 2) Update requirements.txt (add Streamlit)

```txt
pandas
python-dateutil
streamlit

3) Streamlit dashboard (create app.py in repo root)
import json
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="LogWatch TDAS Dashboard", layout="wide")

st.title("LogWatch TDAS — Threat Detection & Analysis Dashboard")

alerts_path = Path("outputs/alerts.json")

if not alerts_path.exists():
    st.warning("No outputs/alerts.json found. Run: `python src/main.py` first.")
    st.stop()

alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
df = pd.DataFrame(alerts)

if df.empty:
    st.info("No alerts found. Try adjusting sample logs or rules.")
    st.stop()

# Basic cleanup
for col in ["timestamp", "ts"]:
    if col in df.columns:
        df[col] = pd.to_datetime(df[col], errors="coerce")

if "timestamp" in df.columns:
    time_col = "timestamp"
elif "ts" in df.columns:
    time_col = "ts"
else:
    time_col = None

# Sidebar filters
st.sidebar.header("Filters")

sev_order = ["low", "medium", "high", "critical"]
available_sev = [s for s in sev_order if s in set(df.get("severity", []))] or sorted(df["severity"].dropna().unique().tolist())
selected_sev = st.sidebar.multiselect("Severity", available_sev, default=available_sev)

types = sorted(df["type"].dropna().unique().tolist())
selected_types = st.sidebar.multiselect("Alert types", types, default=types)

entity_types = sorted(df["entity_type"].dropna().unique().tolist())
selected_entity_types = st.sidebar.multiselect("Entity types", entity_types, default=entity_types)

query = st.sidebar.text_input("Search (entity / reason)", "")

filtered = df[
    df["severity"].isin(selected_sev) &
    df["type"].isin(selected_types) &
    df["entity_type"].isin(selected_entity_types)
].copy()

if query.strip():
    q = query.strip().lower()
    filtered = filtered[
        filtered["entity"].astype(str).str.lower().str.contains(q, na=False) |
        filtered.get("reason", "").astype(str).str.lower().str.contains(q, na=False)
    ]

# Layout: metrics + rankings + table
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total alerts", len(df))
c2.metric("Filtered alerts", len(filtered))
c3.metric("Unique entities (filtered)", filtered["entity"].nunique())
c4.metric("Unique types (filtered)", filtered["type"].nunique())

st.divider()

# Compute entity scores from filtered alerts
weight = {"low": 1, "medium": 3, "high": 7, "critical": 10}
filtered["score"] = filtered["severity"].map(weight).fillna(1).astype(int)

rank = (
    filtered.groupby(["entity_type", "entity"], dropna=False)["score"]
    .sum()
    .reset_index()
    .sort_values("score", ascending=False)
)

left, right = st.columns([1, 2])

with left:
    st.subheader("Top Suspicious Entities")
    st.dataframe(rank.head(15), use_container_width=True, hide_index=True)

with right:
    st.subheader("Alerts")
    show_cols = [c for c in ["type", "severity", "entity_type", "entity", "reason"] if c in filtered.columns]
    if time_col and time_col in filtered.columns:
        show_cols = [time_col] + show_cols
        filtered_sorted = filtered.sort_values(time_col, ascending=False)
    else:
        filtered_sorted = filtered

    st.dataframe(filtered_sorted[show_cols], use_container_width=True, hide_index=True)

st.divider()

# Optional timeline chart
if time_col and time_col in filtered.columns and filtered[time_col].notna().any():
    st.subheader("Alert Timeline")
    timeline = filtered.dropna(subset=[time_col]).copy()
    timeline["date"] = timeline[time_col].dt.floor("min")
    counts = timeline.groupby(["date", "severity"]).size().reset_index(name="count")
    st.line_chart(counts.pivot(index="date", columns="severity", values="count").fillna(0))
