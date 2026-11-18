import html
import json
from collections import Counter
from datetime import datetime

COLORS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m", "INFO": "\033[90m"}
RESET = "\033[0m"


def summary(findings):
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in ("HIGH", "MEDIUM", "LOW", "INFO")}


def score(findings):
    weights = {"HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
    return max(0, 100 - sum(weights.get(f.severity, 0) for f in findings))


def print_console(result, color=True):
    findings = result["findings"]
    print(f"\nTarget : {result['target']}  (HTTP {result['status']})")
    print(f"Score  : {score(findings)}/100")
    print("Summary: " + ", ".join(f"{k}={v}" for k, v in summary(findings).items()))
    print("-" * 70)
    if not findings:
        print("No issues found. Nice!")
    for f in findings:
        tag = f"[{f.severity}]"
        if color:
            tag = COLORS.get(f.severity, "") + tag + RESET
        print(f"{tag} {f.title}")
        print(f"    {f.description}")
        if f.evidence:
            print(f"    Evidence: {f.evidence}")
        print(f"    Fix: {f.recommendation}\n")


def to_json(result):
    return json.dumps(
        {
            "target": result["target"],
            "status": result["status"],
            "score": score(result["findings"]),
            "summary": summary(result["findings"]),
            "findings": [f.to_dict() for f in result["findings"]],
            "generated": datetime.now().isoformat(timespec="seconds"),
        },
        indent=2,
    )


def to_html(result):
    findings = result["findings"]
    rows = "".join(
        f"<tr class='{f.severity.lower()}'><td>{f.severity}</td><td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.description)}<br><small>{html.escape(f.evidence)}</small></td>"
        f"<td>{html.escape(f.recommendation)}</td></tr>"
        for f in findings
    )
    s = summary(findings)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WebScan report - {html.escape(result['target'])}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#222}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.5rem;vertical-align:top}}
th{{background:#f3f3f3;text-align:left}}.high td:first-child{{color:#c00;font-weight:bold}}
.medium td:first-child{{color:#c70}}.low td:first-child{{color:#06c}}small{{color:#666}}
</style></head><body>
<h1>WebScan Security Report</h1>
<p><b>Target:</b> {html.escape(result['target'])}<br><b>Score:</b> {score(findings)}/100<br>
<b>High:</b> {s['HIGH']} &nbsp; <b>Medium:</b> {s['MEDIUM']} &nbsp; <b>Low:</b> {s['LOW']}</p>
<table><tr><th>Severity</th><th>Issue</th><th>Details</th><th>Recommendation</th></tr>{rows}</table>
<p><small>Generated {datetime.now():%Y-%m-%d %H:%M}</small></p>
</body></html>"""
