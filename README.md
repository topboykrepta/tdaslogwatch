# LogWatch TDAS — Threat Detection & Analysis System (Simple)

LogWatch TDAS is a lightweight threat detection and analysis system that ingests common security logs (auth, process, network), runs detection rules, scores suspicious entities, and generates alerts + a human-readable report.

## Features
- ✅ Brute-force detection (failed logins in a short window)
- ✅ IP churn / “impossible travel” proxy (many IPs for one user quickly)
- ✅ Suspicious process detection (LOLBins / risky command patterns)
- ✅ Rare destination detection (unexpected outbound connections)
- ✅ Risk scoring + top suspicious entities
- ✅ Static dashboard (HTML/CSS/JS) for exploration

## Architecture (simple)
1. **Ingest** JSONL logs (one JSON event per line)
2. **Detect** suspicious events via rule-based detectors
3. **Score** entities (user/IP/host) by severity-weighted findings
4. **Output**
   - `outputs/alerts.json` (machine-readable)
   - `outputs/report.md` (human-readable)
    - Static UI in `site/` for exploration

## Project Structure
tdas-logwatch/
data/ # sample logs (jsonl)
src/ # detection pipeline
outputs/ # generated alerts + report
app.py # Streamlit dashboard
requirements.txt


## Quick Start
```bash
python src/main.py
```

Outputs:
- `outputs/alerts.json`
- `outputs/report.md`

## View the Dashboard (static website)

Because browsers block `fetch()` from local files, run a tiny local server from the repo root:

```bash
python -m http.server 8000
```

Then open:
- http://localhost:8000/site/

If you don’t want to run a server, open `site/index.html` directly and use **Upload alerts.json** / drag-drop.

## Log Event Formats (examples)

Auth events:
```json
{"ts":"2026-01-26T10:00:00Z","user":"alice","ip":"41.1.2.3","action":"login","status":"fail"}
```

Process events:
```json
{"ts":"2026-01-26T10:03:00Z","host":"pc1","user":"alice","process":"powershell.exe","cmdline":"powershell -enc ..."}
```

Network events:
```json
{"ts":"2026-01-26T10:02:10Z","host":"pc1","dst":"93.184.216.34","port":443}
```

## Severity Scoring

The dashboard derives severity from each finding’s `score`:
- low: score < 3
- medium: 3 ≤ score < 7
- high: score ≥ 7

## Roadmap (easy upgrades)
- MITRE ATT&CK technique mapping per rule
- Baselines per host/user (learn “normal” behavior)
- Add GeoIP enrichment (real impossible travel)
- Add Sigma-style rule definitions (YAML rules)
- Export alerts to Slack/Email/Webhooks

## Disclaimer
This project is for educational and defensive security use only.
    timeline = filtered.dropna(subset=[time_col]).copy()
    timeline["date"] = timeline[time_col].dt.floor("min")
    counts = timeline.groupby(["date", "severity"]).size().reset_index(name="count")
    st.line_chart(counts.pivot(index="date", columns="severity", values="count").fillna(0))
