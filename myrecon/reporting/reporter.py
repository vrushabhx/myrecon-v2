import json
from datetime import datetime
from pathlib import Path
from myrecon.models import Scan


def generate_json_report(scan: Scan) -> str:
    return scan.model_dump_json(indent=2)


def generate_html_report(scan: Scan) -> str:
    by_sev = {}
    for f in scan.findings:
        by_sev.setdefault(f.severity.value, []).append(f)

    sev_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
    }

    findings_html = ""
    idx = 0
    for sev in ["critical", "high", "medium", "low", "info"]:
        for f in by_sev.get(sev, []):
            idx += 1
            color = sev_colors.get(sev, "#6c757d")
            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="sev-badge" style="background:{color}">{sev.upper()}</span>
                    <span class="finding-title">{_esc(f.title)}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Module:</strong> {_esc(f.module)}</p>
                    <p><strong>Target:</strong> {_esc(f.target)}</p>
                    {f'<p>{_esc(f.description)}</p>' if f.description else ''}
                    {f'<pre class="evidence">{_esc(f.evidence)}</pre>' if f.evidence else ''}
                </div>
            </div>"""

    sev_summary = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = len(by_sev.get(sev, []))
        if count:
            color = sev_colors[sev]
            sev_summary += f'<span class="sev-badge" style="background:{color}">{sev.upper()}: {count}</span> '

    module_rows = ""
    for name, result in scan.module_results.items():
        status_class = "status-" + result.status.value
        module_rows += f"""
        <tr>
            <td>{_esc(name)}</td>
            <td class="{status_class}">{result.status.value}</td>
            <td>{result.findings_count}</td>
            <td>{result.started_at or '-'}</td>
            <td>{result.finished_at or '-'}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Myrecon Report: {_esc(scan.domain)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0d1117; color:#c9d1d9; }}
.container {{ max-width:1100px; margin:0 auto; padding:20px; }}
h1 {{ color:#58a6ff; margin-bottom:8px; }}
h2 {{ color:#58a6ff; margin:24px 0 12px; border-bottom:1px solid #21262d; padding-bottom:8px; }}
.meta {{ color:#8b949e; margin-bottom:20px; }}
.summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:16px 0; }}
.stat {{ background:#161b22; border:1px solid #21262d; border-radius:8px; padding:16px; text-align:center; }}
.stat-num {{ font-size:2em; font-weight:700; color:#58a6ff; }}
.stat-label {{ color:#8b949e; font-size:0.9em; }}
.sev-badge {{ display:inline-block; padding:2px 10px; border-radius:12px; color:#fff; font-size:0.85em; font-weight:600; margin:2px; }}
table {{ width:100%; border-collapse:collapse; margin:12px 0; }}
th, td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #21262d; }}
th {{ background:#161b22; color:#58a6ff; }}
.status-completed {{ color:#3fb950; }}
.status-failed {{ color:#f85149; }}
.status-skipped {{ color:#8b949e; }}
.finding {{ background:#161b22; border:1px solid #21262d; border-radius:8px; margin:12px 0; overflow:hidden; }}
.finding-header {{ padding:12px 16px; display:flex; align-items:center; gap:10px; border-bottom:1px solid #21262d; }}
.finding-num {{ color:#8b949e; font-weight:600; }}
.finding-title {{ font-weight:600; }}
.finding-body {{ padding:12px 16px; }}
.finding-body p {{ margin:4px 0; }}
.evidence {{ background:#0d1117; border:1px solid #21262d; padding:12px; border-radius:4px; overflow-x:auto; font-size:0.85em; margin-top:8px; white-space:pre-wrap; word-break:break-all; }}
</style>
</head>
<body>
<div class="container">
<h1>Myrecon Report</h1>
<p class="meta">Target: <strong>{_esc(scan.domain)}</strong> | Scan ID: {scan.id} | {scan.created_at}</p>

<div class="summary">
<div class="stat"><div class="stat-num">{len(scan.subdomains)}</div><div class="stat-label">Subdomains</div></div>
<div class="stat"><div class="stat-num">{len(scan.live_hosts)}</div><div class="stat-label">Live Hosts</div></div>
<div class="stat"><div class="stat-num">{sum(len(p) for p in scan.open_ports.values())}</div><div class="stat-label">Open Ports</div></div>
<div class="stat"><div class="stat-num">{len(scan.findings)}</div><div class="stat-label">Findings</div></div>
</div>

<p>{sev_summary}</p>

<h2>Module Results</h2>
<table>
<tr><th>Module</th><th>Status</th><th>Findings</th><th>Started</th><th>Finished</th></tr>
{module_rows}
</table>

<h2>Findings ({len(scan.findings)})</h2>
{findings_html if findings_html else '<p style="color:#8b949e">No findings recorded.</p>'}

<p style="color:#8b949e; margin-top:40px; text-align:center;">Generated by Myrecon v2.0 on {datetime.utcnow().isoformat()}</p>
</div>
</body>
</html>"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
