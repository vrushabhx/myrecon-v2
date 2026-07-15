### Stage 1: Build Go tools
FROM golang:1.22-bookworm AS go-builder

RUN go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/sensepost/gowitness@latest && \
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/tomnomnom/unfurl@latest && \
    go install -v github.com/hakluke/hakcheckurl@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master

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

COPY --from=go-builder /go/bin/* /usr/local/bin/

RUN pip install --no-cache-dir sqlmap linkfinder arjun && \
    nuclei -update-templates 2>/dev/null || true

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
