import asyncio
import json
import logging
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import APIKeyHeader

from myrecon.config import load_config, get_config
from myrecon.models import ScanRequest
from myrecon.scanner import start_scan, get_scan, list_scans, cancel_scan, subscribe, unsubscribe, init_scanner
from myrecon.reporting.reporter import generate_html_report, generate_json_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("myrecon")

app = FastAPI(title="Myrecon", version="2.0.0", description="Automated Bug Bounty Reconnaissance Platform")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Depends(api_key_header)):
    config = get_config()
    required_key = config.get("server", {}).get("api_key", "")
    if required_key and api_key != required_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.on_event("startup")
async def startup():
    load_config()
    init_scanner()
    logger.info("Myrecon v2.0 started")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    scans = list_scans()
    return _render_dashboard(scans)


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _render_scan_detail(scan)


@app.post("/api/scans", dependencies=[Depends(verify_api_key)])
async def api_start_scan(request: ScanRequest):
    scan = await start_scan(request)
    return {"scan_id": scan.id, "status": scan.status.value, "domain": scan.domain}


@app.get("/api/scans", dependencies=[Depends(verify_api_key)])
async def api_list_scans():
    scans = list_scans()
    return [{"id": s.id, "domain": s.domain, "status": s.status.value,
             "findings": len(s.findings), "created_at": s.created_at} for s in scans]


@app.get("/api/scans/{scan_id}", dependencies=[Depends(verify_api_key)])
async def api_get_scan(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return json.loads(scan.model_dump_json())


@app.delete("/api/scans/{scan_id}", dependencies=[Depends(verify_api_key)])
async def api_cancel_scan(scan_id: str):
    if await cancel_scan(scan_id):
        return {"status": "cancelled"}
    raise HTTPException(400, "Cannot cancel scan")


@app.get("/api/scans/{scan_id}/report")
async def api_report(scan_id: str, format: str = "html"):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if format == "json":
        return JSONResponse(content=json.loads(generate_json_report(scan)))
    return HTMLResponse(content=generate_html_report(scan))


@app.get("/api/tools-check")
async def api_tools_check():
    import shutil
    tools = [
        "subfinder", "assetfinder", "amass", "findomain", "httpx", "httprobe",
        "naabu", "nmap", "ffuf", "nuclei", "waybackurls", "gau", "gospider",
        "gowitness", "crlfuzz", "dalfox", "kxss", "gf", "qsreplace", "unfurl",
        "trufflehog", "cloud_enum", "linkfinder", "sqlmap",
    ]
    result = {}
    for t in tools:
        result[t] = shutil.which(t) is not None
    installed = sum(1 for v in result.values() if v)
    return {"tools": result, "installed": installed, "total": len(tools)}


@app.websocket("/ws/scans/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    queue = asyncio.Queue()

    async def on_event(event):
        await queue.put(event)

    subscribe(scan_id, on_event)
    try:
        scan = get_scan(scan_id)
        if scan:
            modules_status = {}
            for name, result in scan.module_results.items():
                modules_status[name] = result.status.value
            await websocket.send_json({
                "type": "status",
                "scan_status": scan.status.value,
                "modules": modules_status,
                "stats": {
                    "subdomains": len(scan.subdomains),
                    "live_hosts": len(scan.live_hosts),
                    "open_ports": sum(len(p) for p in scan.open_ports.values()),
                    "findings": len(scan.findings),
                },
            })

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
                await websocket.send_json(event)
                if event.get("type") in ("completed", "cancelled"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        unsubscribe(scan_id, on_event)


def _render_dashboard(scans) -> str:
    rows = ""
    for s in scans:
        status_class = {
            "running": "status-running", "completed": "status-completed",
            "failed": "status-failed", "queued": "status-queued", "cancelled": "status-cancelled",
        }.get(s.status.value, "")
        rows += f"""
        <tr onclick="location.href='/scan/{s.id}'" style="cursor:pointer">
            <td><code>{s.id}</code></td>
            <td><strong>{_esc(s.domain)}</strong></td>
            <td class="{status_class}">{s.status.value.upper()}</td>
            <td>{len(s.findings)}</td>
            <td>{len(s.subdomains)}</td>
            <td>{s.created_at[:19]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Myrecon Dashboard</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; }}
.container {{ max-width:1200px; margin:0 auto; padding:20px; }}
h1 {{ color:#58a6ff; margin-bottom:4px; font-size:1.8em; }}
.subtitle {{ color:#8b949e; margin-bottom:24px; }}
.new-scan {{ background:#161b22; border:1px solid #21262d; border-radius:12px; padding:24px; margin-bottom:24px; }}
.new-scan h2 {{ color:#58a6ff; margin-bottom:16px; font-size:1.2em; }}
.form-row {{ display:flex; gap:12px; flex-wrap:wrap; align-items:end; }}
input,select {{ background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:10px 14px; border-radius:6px; font-size:0.95em; }}
input:focus {{ border-color:#58a6ff; outline:none; }}
input[type="text"] {{ min-width:280px; }}
button {{ background:#238636; color:#fff; border:none; padding:10px 24px; border-radius:6px; cursor:pointer; font-weight:600; font-size:0.95em; }}
button:hover {{ background:#2ea043; }}
table {{ width:100%; border-collapse:collapse; margin:12px 0; }}
th,td {{ padding:10px 14px; text-align:left; border-bottom:1px solid #21262d; }}
th {{ background:#161b22; color:#58a6ff; }}
tr:hover {{ background:#161b22; }}
.status-running {{ color:#d29922; }}
.status-completed {{ color:#3fb950; }}
.status-failed {{ color:#f85149; }}
.status-queued {{ color:#8b949e; }}
.status-cancelled {{ color:#8b949e; }}
code {{ background:#161b22; padding:2px 6px; border-radius:4px; font-size:0.9em; }}
#result {{ margin-top:12px; padding:12px; background:#161b22; border-radius:6px; display:none; }}
</style>
</head>
<body>
<div class="container">
<h1>Myrecon v2.0</h1>
<p class="subtitle">Automated Bug Bounty Reconnaissance Platform</p>

<div class="new-scan">
<h2>New Scan</h2>
<div class="form-row">
<input type="text" id="domain" placeholder="example.com" required>
<button onclick="startScan()">Start Scan</button>
</div>
<div id="result"></div>
</div>

<h2 style="color:#58a6ff;margin-bottom:12px">Scans</h2>
<table>
<tr><th>ID</th><th>Domain</th><th>Status</th><th>Findings</th><th>Subdomains</th><th>Created</th></tr>
{rows if rows else '<tr><td colspan="6" style="color:#8b949e;text-align:center">No scans yet. Start one above.</td></tr>'}
</table>
</div>
<script>
async function startScan() {{
    const domain = document.getElementById('domain').value.trim();
    if (!domain) return;
    const res = await fetch('/api/scans', {{
        method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{domain}})
    }});
    const data = await res.json();
    const el = document.getElementById('result');
    el.style.display = 'block';
    if (res.ok) {{
        el.innerHTML = 'Scan started! <a href="/scan/'+data.scan_id+'" style="color:#58a6ff">View Progress</a>';
        setTimeout(() => location.reload(), 1500);
    }} else {{
        el.innerHTML = 'Error: ' + (data.detail || JSON.stringify(data));
        el.style.color = '#f85149';
    }}
}}
document.getElementById('domain').addEventListener('keydown', e => {{ if(e.key==='Enter') startScan(); }});
</script>
</body>
</html>"""


def _render_scan_detail(scan) -> str:
    module_rows = ""
    for name, result in scan.module_results.items():
        sc = "status-" + result.status.value
        module_rows += f"<tr><td>{_esc(name)}</td><td class='{sc}'>{result.status.value}</td><td>{result.findings_count}</td></tr>"

    findings_html = ""
    sev_colors = {"critical":"#dc3545","high":"#fd7e14","medium":"#ffc107","low":"#17a2b8","info":"#6c757d"}
    for i, f in enumerate(scan.findings, 1):
        c = sev_colors.get(f.severity.value, "#6c757d")
        findings_html += f"""
        <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;margin:8px 0;padding:14px">
            <span style="color:#8b949e">#{i}</span>
            <span style="background:{c};color:#fff;padding:2px 8px;border-radius:10px;font-size:0.8em">{f.severity.value.upper()}</span>
            <strong>{_esc(f.title)}</strong>
            {f'<p style="margin-top:6px;color:#8b949e">{_esc(f.description[:300])}</p>' if f.description else ''}
            {f'<pre style="background:#0d1117;padding:8px;border-radius:4px;margin-top:6px;font-size:0.85em;overflow-x:auto;white-space:pre-wrap">{_esc(f.evidence[:500])}</pre>' if f.evidence else ''}
        </div>"""

    status_class = "status-" + scan.status.value
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan: {_esc(scan.domain)}</title>
<style>
* {{ margin:0;padding:0;box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; }}
.container {{ max-width:1100px; margin:0 auto; padding:20px; }}
h1 {{ color:#58a6ff; }}
h2 {{ color:#58a6ff; margin:20px 0 10px; }}
a {{ color:#58a6ff; text-decoration:none; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #21262d; }}
th {{ background:#161b22; color:#58a6ff; }}
.status-running {{ color:#d29922; }} .status-completed {{ color:#3fb950; }}
.status-failed {{ color:#f85149; }} .status-pending {{ color:#8b949e; }}
.stats {{ display:flex; gap:12px; margin:16px 0; flex-wrap:wrap; }}
.stat {{ background:#161b22; border:1px solid #21262d; border-radius:8px; padding:14px 20px; text-align:center; min-width:120px; }}
.stat b {{ display:block; font-size:1.6em; color:#58a6ff; }}
.stat span {{ color:#8b949e; font-size:0.85em; }}
.btn {{ display:inline-block; background:#238636; color:#fff; padding:8px 18px; border-radius:6px; font-weight:600; margin:4px; }}
.btn-red {{ background:#da3633; }}
#log {{ background:#0d1117; border:1px solid #21262d; padding:12px; border-radius:6px; max-height:400px; overflow-y:auto; font-family:'Cascadia Code','Fira Code',monospace; font-size:0.85em; line-height:1.6; }}
#log .log-time {{ color:#484f58; }}
#log .log-started {{ color:#58a6ff; }}
#log .log-progress {{ color:#c9d1d9; }}
#log .log-completed {{ color:#3fb950; font-weight:600; }}
#log .log-failed {{ color:#f85149; font-weight:600; }}
#log .log-status {{ color:#8b949e; }}
#log .log-module {{ color:#d2a8ff; }}
</style>
</head>
<body>
<div class="container">
<p><a href="/">&larr; Dashboard</a></p>
<h1>{_esc(scan.domain)}</h1>
<p style="color:#8b949e">ID: {scan.id} | Status: <span class="{status_class}" id="scan-status">{scan.status.value.upper()}</span> | {scan.created_at[:19]}</p>

<div class="stats">
<div class="stat"><b id="stat-subs">{len(scan.subdomains)}</b><span>Subdomains</span></div>
<div class="stat"><b id="stat-hosts">{len(scan.live_hosts)}</b><span>Live Hosts</span></div>
<div class="stat"><b id="stat-ports">{sum(len(p) for p in scan.open_ports.values())}</b><span>Open Ports</span></div>
<div class="stat"><b id="stat-findings">{len(scan.findings)}</b><span>Findings</span></div>
</div>

<a href="/api/scans/{scan.id}/report" class="btn">HTML Report</a>
<a href="/api/scans/{scan.id}/report?format=json" class="btn">JSON Report</a>
{f'<button class="btn btn-red" onclick="cancelScan()">Cancel</button>' if scan.status.value == "running" else ''}

<h2>Modules</h2>
<table id="modules-table"><tr><th>Module</th><th>Status</th><th>Findings</th></tr>{module_rows}</table>

<h2>Live Log</h2>
<div id="log"></div>

<h2>Findings (<span id="findings-count">{len(scan.findings)}</span>)</h2>
<div id="findings-list">
{findings_html if findings_html else '<p style="color:#8b949e">No findings yet.</p>'}
</div>
</div>
<script>
const scanId = "{scan.id}";
const logEl = document.getElementById('log');
let wsConnected = false;

function addLog(text, cls) {{
    const line = document.createElement('div');
    const time = new Date().toLocaleTimeString();
    line.innerHTML = '<span class="log-time">[' + time + ']</span> <span class="' + cls + '">' + text + '</span>';
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
}}

function updateStats(stats) {{
    if (!stats) return;
    if (stats.subdomains !== undefined) document.getElementById('stat-subs').textContent = stats.subdomains;
    if (stats.live_hosts !== undefined) document.getElementById('stat-hosts').textContent = stats.live_hosts;
    if (stats.open_ports !== undefined) document.getElementById('stat-ports').textContent = stats.open_ports;
    if (stats.findings !== undefined) {{
        document.getElementById('stat-findings').textContent = stats.findings;
        document.getElementById('findings-count').textContent = stats.findings;
    }}
}}

function updateModuleRow(module, status) {{
    const table = document.getElementById('modules-table');
    const rows = table.querySelectorAll('tr');
    for (let r of rows) {{
        const cells = r.querySelectorAll('td');
        if (cells.length && cells[0].textContent === module) {{
            cells[1].className = 'status-' + status;
            cells[1].textContent = status;
            return;
        }}
    }}
}}

function connectWS() {{
    addLog('Connecting to scan...', 'log-status');
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(proto + '//' + location.host + '/ws/scans/' + scanId);

    ws.onopen = () => {{
        wsConnected = true;
        addLog('Connected', 'log-status');
    }};

    ws.onmessage = e => {{
        const d = JSON.parse(e.data);
        if (d.type === 'ping') return;

        switch(d.type) {{
            case 'status':
                addLog('Scan status: ' + (d.scan_status || 'unknown').toUpperCase(), 'log-status');
                if (d.modules) {{
                    for (const [mod, st] of Object.entries(d.modules)) {{
                        if (st !== 'pending') addLog('  ' + mod + ': ' + st, 'log-status');
                    }}
                }}
                updateStats(d.stats);
                break;
            case 'started':
                addLog('Scan started', 'log-started');
                break;
            case 'module_started':
                addLog('Starting module: ' + d.module, 'log-started');
                updateModuleRow(d.module, 'running');
                break;
            case 'progress':
                addLog('[' + d.module + '] ' + d.message, 'log-progress');
                break;
            case 'module_completed':
                addLog('Module completed: ' + d.module + ' (' + d.findings_count + ' findings)', 'log-completed');
                updateModuleRow(d.module, 'completed');
                updateStats(d.stats);
                break;
            case 'module_failed':
                addLog('Module FAILED: ' + d.module + ' (' + (d.error || 'unknown error') + ')', 'log-failed');
                updateModuleRow(d.module, 'failed');
                break;
            case 'completed':
                addLog('Scan completed! ' + d.total_findings + ' total findings', 'log-completed');
                document.getElementById('scan-status').textContent = 'COMPLETED';
                document.getElementById('scan-status').className = 'status-completed';
                setTimeout(() => location.reload(), 2000);
                break;
            case 'cancelled':
                addLog('Scan cancelled', 'log-failed');
                setTimeout(() => location.reload(), 1000);
                break;
            default:
                addLog(d.type + ': ' + JSON.stringify(d), 'log-status');
        }}
    }};

    ws.onclose = () => {{
        if (wsConnected) {{
            addLog('Connection closed', 'log-status');
            wsConnected = false;
        }}
    }};
    ws.onerror = () => {{ addLog('WebSocket error, retrying...', 'log-failed'); }};
}}

connectWS();

async function cancelScan() {{
    await fetch('/api/scans/' + scanId, {{method:'DELETE'}});
    location.reload();
}}
</script>
</body>
</html>"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


if __name__ == "__main__":
    import uvicorn
    config = load_config()
    uvicorn.run(app, host=config["server"]["host"], port=config["server"]["port"])
