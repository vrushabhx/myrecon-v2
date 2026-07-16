### Stage 1: Build Go tools (each installed separately so one failure doesn't block the rest)
FROM golang:1.23-bookworm AS go-builder

ENV CGO_ENABLED=0

# Simple, stable tools first
RUN go install -v github.com/tomnomnom/assetfinder@latest || true
RUN go install -v github.com/tomnomnom/waybackurls@latest || true
RUN go install -v github.com/tomnomnom/gf@latest || true
RUN go install -v github.com/tomnomnom/qsreplace@latest || true
RUN go install -v github.com/tomnomnom/unfurl@latest || true
RUN go install -v github.com/hakluke/hakcheckurl@latest || true

# ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

# Other tools
RUN go install -v github.com/ffuf/ffuf/v2@latest || true
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest || true
RUN go install -v github.com/jaeles-project/gospider@latest || true
RUN go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest || true
RUN go install -v github.com/hahwul/dalfox/v2@latest || true

# gowitness v3 requires CGO for sqlite
RUN CGO_ENABLED=1 go install -v github.com/sensepost/gowitness@latest || true

# amass - use a tagged release instead of master (master often breaks)
RUN go install -v github.com/owasp-amass/amass/v4/...@latest || true

### Stage 2: Runtime
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    git \
    curl \
    wget \
    unzip \
    libpcap-dev \
    chromium \
    figlet \
    jq \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy all successfully built Go binaries
COPY --from=go-builder /go/bin/ /usr/local/bin/

# Python security tools
RUN pip install --no-cache-dir sqlmap arjun && \
    nuclei -update-templates 2>/dev/null || true

# gf patterns for vulnerability detection
RUN git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns && \
    mkdir -p /root/.gf && \
    cp /tmp/gf-patterns/*.json /root/.gf/ && \
    rm -rf /tmp/gf-patterns

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data/scans

ENV MYRECON_CONFIG=/app/config.yaml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

CMD ["python", "-m", "uvicorn", "myrecon.app:app", "--host", "0.0.0.0", "--port", "8000"]
