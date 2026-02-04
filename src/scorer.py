from collections import defaultdict

def score_findings(findings):
    grouped = defaultdict(lambda: {"score": 0.0, "events": []})
    for finding in findings or []:
        etype = finding.get("etype", "unknown")
        entity = finding.get("entity", "unknown")
        key = (etype, entity)
        grouped[key]["score"] += float(finding.get("score", 1.0))
        grouped[key]["events"].append(finding)
    ranked = sorted(grouped.items(), key=lambda item: item[1]["score"], reverse=True)
    return grouped, ranked
