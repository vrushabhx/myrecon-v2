# Myrecon v2.0

Automated bug bounty reconnaissance platform with a web dashboard, REST API, and Docker deployment.

**Original concept by [Shubham Chaskar (unstabl3)](https://github.com/unstabl3)**. Rewritten as a modern Python + Docker application with web UI.

## Features

- **Web Dashboard**: Start, monitor, and manage scans from your browser
- **REST API**: Programmatic scan control with JSON responses
- **Real-time Updates**: WebSocket-based live progress streaming
- **10 Recon Modules**: Subdomain enum, probing, port scanning, screenshots, dir bruteforce, cloud bucket enum, JS endpoint discovery, URL collection, vulnerability scanning, GitHub recon
- **30+ Tools**: subfinder, amass, assetfinder, httpx, naabu, nmap, ffuf, nuclei, waybackurls, gau, gospider, gowitness, crlfuzz, dalfox, sqlmap, gf patterns, and more
- **HTML/JSON Reports**: Professional reports with severity breakdown
- **Notifications**: Slack, Discord, and Telegram webhooks
- **Docker Deployment**: Single command setup on any OS (Windows, Mac, Linux)
- **API Key Auth**: Optional authentication for remote access

## Quick Start (Windows with Docker Desktop)

### 1. Install Docker Desktop

Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).

### 2. Clone and Configure

```powershell
git clone https://github.com/vrushabhdoshi/Myrecon.git
cd Myrecon
```

Edit `config.yaml` with your API tokens:

```yaml
tokens:
  github_token: "ghp_your_token_here"
  shodan_key: "your_shodan_key"

notifications:
  slack_webhook: "https://hooks.slack.com/services/..."
  discord_webhook: "https://discord.com/api/webhooks/..."

server:
  api_key: "your-secret-api-key"  # Set this for remote access security
```

### 3. Build and Run

```powershell
docker-compose up -d --build
```

### 4. Access

Open `http://localhost:8000` in your browser.

## Expose Over the Internet

### Option A: Cloudflare Tunnel (Recommended, Free)

```powershell
# Install cloudflared
winget install Cloudflare.cloudflared

# Create a quick tunnel
cloudflared tunnel --url http://localhost:8000
```

This gives you a public `https://<random>.trycloudflare.com` URL. For a persistent custom domain:

```powershell
cloudflared tunnel login
cloudflared tunnel create myrecon
cloudflared tunnel route dns myrecon recon.yourdomain.com
cloudflared tunnel run myrecon
```

### Option B: ngrok

```powershell
# Install ngrok
winget install ngrok.ngrok

# Expose
ngrok http 8000
```

### Option C: Port Forwarding

1. Forward port 8000 on your router to your machine's local IP
2. Use a Dynamic DNS service (e.g., No-IP, DuckDNS) for a stable hostname
3. Set `server.api_key` in config.yaml for authentication

**Important**: Always set an API key in `config.yaml` when exposing over the internet.

## API Usage

### Start a scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-api-key" \
  -d '{"domain": "example.com"}'
```

### Start with specific modules

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "modules": ["subdomain", "probing", "portscan"]}'
```

### List scans

```bash
curl http://localhost:8000/api/scans
```

### Get scan details

```bash
curl http://localhost:8000/api/scans/{scan_id}
```

### Download report

```bash
# HTML report
curl http://localhost:8000/api/scans/{scan_id}/report > report.html

# JSON report
curl "http://localhost:8000/api/scans/{scan_id}/report?format=json" > report.json
```

### Cancel a scan

```bash
curl -X DELETE http://localhost:8000/api/scans/{scan_id}
```

## Modules

| Module | Tools Used | Dependencies |
|--------|-----------|-------------|
| `subdomain` | subfinder, assetfinder, amass, findomain | None |
| `probing` | httpx / httprobe | subdomain |
| `portscan` | naabu, nmap | probing |
| `screenshot` | gowitness | probing |
| `dirbrute` | ffuf | probing |
| `cloud_enum` | cloud_enum | subdomain |
| `js_discovery` | linkfinder | probing |
| `url_collection` | waybackurls, gau, gospider | probing |
| `vuln_scan` | nuclei, crlfuzz, kxss, dalfox, gf | url_collection |
| `github_recon` | trufflehog | subdomain |

## Architecture

```
myrecon/
├── app.py           # FastAPI web application
├── config.py        # YAML configuration loader
├── models.py        # Pydantic data models
├── scanner.py       # Scan orchestrator (DAG-based module execution)
├── utils.py         # Shared utilities (tool runner, dedup, file I/O)
├── modules/         # 10 recon modules
├── notify/          # Slack, Discord, Telegram notifiers
└── reporting/       # HTML and JSON report generators
```

## Development

Run locally without Docker:

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m uvicorn myrecon.app:app --reload --host 0.0.0.0 --port 8000
```

## License

MIT License. See [LICENSE](LICENSE).
