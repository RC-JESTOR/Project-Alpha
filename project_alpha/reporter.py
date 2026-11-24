"""CLI, JSON, and standalone Dark-Cyber HTML reporting for Project Alpha."""

import html
import json
from pathlib import Path
from typing import Dict

from .models import ScanReport

SEV_COLORS = {
    "CRITICAL": "#ff2e63",
    "HIGH": "#ff6b35",
    "MEDIUM": "#fbbf24",
    "LOW": "#00d2ff",
    "INFO": "#00ff66",
}


def print_cli_summary(report: ScanReport) -> None:
    counts = report.severity_counts()
    print("\n" + "=" * 72)
    print(f"  PROJECT ALPHA // WEB SECURITY AUDIT REPORT")
    print("=" * 72)
    print(f"  Target URL       : {report.target}")
    print(f"  Render Engine    : {report.mode.upper()}")
    print(f"  Pages Scanned    : {report.pages_scanned}")
    print(f"  Forms Discovered : {report.forms_discovered}")
    print(
        f"  Findings         : {len(report.findings)} "
        f"(CRIT:{counts['CRITICAL']} HIGH:{counts['HIGH']} "
        f"MED:{counts['MEDIUM']} LOW:{counts['LOW']} INFO:{counts['INFO']})"
    )
    print("-" * 72)

    if not report.findings:
        print("  [+] No security issues detected with current checks.")
    else:
        for idx, f in enumerate(report.findings, 1):
            print(f"  [{idx:02d}] [{f.severity:<8}] {f.title}")
            print(f"       URL      : {f.url}")
            print(f"       Evidence : {f.evidence}")
            print(f"       Fix      : {f.remediation}\n")
    print("=" * 72 + "\n")


def export_json(report: ScanReport, output_path: str) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def export_html(report: ScanReport, output_path: str) -> Path:
    counts: Dict[str, int] = report.severity_counts()
    rows = []
    for f in report.findings:
        color = SEV_COLORS.get(f.severity.upper(), "#00ff66")
        rows.append(
            f"<tr>"
            f"<td><span class='badge' style='border-color:{color};color:{color};'>{html.escape(f.severity)}</span></td>"
            f"<td><strong>{html.escape(f.title)}</strong><div class='muted'>{html.escape(f.category)}</div></td>"
            f"<td><code>{html.escape(f.url)}</code></td>"
            f"<td>{html.escape(f.evidence)}</td>"
            f"<td>{html.escape(f.remediation)}</td>"
            f"</tr>"
        )

    table_html = "".join(rows) or "<tr><td colspan='5'>No findings reported.</td></tr>"
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Project Alpha Security Audit — {html.escape(report.target)}</title>
<style>
  body {{ background:#05070b; color:#f3f4f6; font-family:system-ui,Segoe UI,sans-serif; margin:0; padding:32px; }}
  .wrap {{ max-width:1180px; margin:0 auto; }}
  h1 {{ color:#00ff66; letter-spacing:2px; font-size:1.6rem; margin-bottom:4px; }}
  .sub {{ color:#9ca3af; font-family:monospace; font-size:0.85rem; margin-bottom:24px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:24px; }}
  .card {{ background:rgba(14,19,28,0.85); border:1px solid rgba(255,255,255,0.1); border-radius:14px; padding:14px 16px; }}
  .card span {{ display:block; font-size:0.7rem; color:#9ca3af; font-family:monospace; }}
  .card strong {{ font-size:1.5rem; color:#00d2ff; }}
  table {{ width:100%; border-collapse:collapse; background:rgba(14,19,28,0.85); border-radius:16px; overflow:hidden; }}
  th, td {{ padding:12px 14px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.08); font-size:0.86rem; vertical-align:top; }}
  th {{ background:rgba(0,255,102,0.08); color:#00ff66; font-family:monospace; text-transform:uppercase; font-size:0.74rem; }}
  .badge {{ display:inline-block; padding:3px 9px; border-radius:999px; border:1px solid; font-family:monospace; font-size:0.72rem; font-weight:700; }}
  .muted {{ color:#9ca3af; font-size:0.76rem; margin-top:3px; }}
  code {{ color:#00d2ff; word-break:break-all; font-size:0.78rem; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>PROJECT ALPHA // SECURITY AUDIT REPORT</h1>
  <div class="sub">Target: {html.escape(report.target)} | Mode: {html.escape(report.mode)} | Generated: {html.escape(report.finished_at or '')}</div>
  <div class="grid">
    <div class="card"><span>PAGES SCANNED</span><strong>{report.pages_scanned}</strong></div>
    <div class="card"><span>FORMS FOUND</span><strong>{report.forms_discovered}</strong></div>
    <div class="card"><span>HIGH / CRIT</span><strong style="color:#ff6b35;">{counts['HIGH'] + counts['CRITICAL']}</strong></div>
    <div class="card"><span>MEDIUM</span><strong style="color:#fbbf24;">{counts['MEDIUM']}</strong></div>
    <div class="card"><span>LOW / INFO</span><strong style="color:#00ff66;">{counts['LOW'] + counts['INFO']}</strong></div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Endpoint</th><th>Evidence</th><th>Remediation</th></tr></thead>
    <tbody>{table_html}</tbody>
  </table>
</div>
</body>
</html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    return path
