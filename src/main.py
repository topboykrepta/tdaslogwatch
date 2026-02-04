import json
from pathlib import Path
from parser import load_jsonl
from rules import (
    rule_bruteforce, rule_ip_churn, rule_suspicious_process, rule_rare_destinations
)
from scorer import score_findings
from report import make_markdown_report

def main():
    project_root = Path(__file__).resolve().parents[1]
    auth = load_jsonl(str(project_root / "data" / "sample_auth.jsonl"))
    proc = load_jsonl(str(project_root / "data" / "sample_process.jsonl"))
    net  = load_jsonl(str(project_root / "data" / "sample_net.jsonl"))

    findings = []
    findings += rule_bruteforce(auth)
    findings += rule_ip_churn(auth)
    findings += rule_suspicious_process(proc)
    findings += rule_rare_destinations(net)

    scores, ranked = score_findings(findings)

    outputs_dir = project_root / "outputs"
    outputs_dir.mkdir(exist_ok=True)
    (outputs_dir / "alerts.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    (outputs_dir / "report.md").write_text(make_markdown_report([x for x in ranked]), encoding="utf-8")

    print(f"Findings: {len(findings)}")
    print("Top entities:")
    for (etype, entity), info in ranked[:5]:
        print(f"- {etype}:{entity} score={info['score']} events={len(info['events'])}")

if __name__ == "__main__":
    main()
