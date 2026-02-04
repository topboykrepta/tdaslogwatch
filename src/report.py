def make_markdown_report(ranked):
    lines = []
    lines.append("# Logwatch Report")
    lines.append("")
    if not ranked:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.append("## Top Entities")
    lines.append("")
    lines.append("| Type | Entity | Score | Events |")
    lines.append("| --- | --- | --- | --- |")
    for (etype, entity), info in ranked:
        lines.append(f"| {etype} | {entity} | {info['score']:.1f} | {len(info['events'])} |")

    lines.append("")
    lines.append("## Details")
    lines.append("")
    for (etype, entity), info in ranked:
        lines.append(f"### {etype}:{entity}")
        lines.append(f"- Score: {info['score']:.1f}")
        lines.append(f"- Events: {len(info['events'])}")
        lines.append("")
    return "\n".join(lines) + "\n"
