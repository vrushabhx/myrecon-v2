### Stage 1: Build Go tools
FROM golang:1.24-bookworm AS go-builder

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=0

# Simple, stable tools
RUN go install -v github.com/tomnomnom/assetfinder@latest || true
RUN go install -v github.com/tomnomnom/waybackurls@latest || true
RUN go install -v github.com/tomnomnom/gf@latest || true
RUN go install -v github.com/tomnomnom/qsreplace@latest || true
RUN go install -v github.com/tomnomnom/unfurl@latest || true
RUN go install -v github.com/hakluke/hakcheckurl@latest || true

# Other Go tools
RUN go install -v github.com/ffuf/ffuf/v2@latest || true
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest || true
RUN go install -v github.com/jaeles-project/gospider@latest || true
RUN go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest || true
RUN go install -v github.com/hahwul/dalfox/v2@latest || true

# naabu needs libpcap
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

# gowitness needs CGO for sqlite
RUN CGO_ENABLED=1 go install -v github.com/sensepost/gowitness@latest || true

# amass
RUN go install -v github.com/owasp-amass/amass/v4/...@latest || true


### Stage 2: Runtime
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap git curl wget unzip jq \
    libpcap-dev chromium figlet dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Python security tools
RUN pip install --no-cache-dir sqlmap arjun

# Copy Go-built binaries
COPY --from=go-builder /go/bin/ /usr/local/bin/

# gf patterns for vulnerability detection
RUN git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns && \
    mkdir -p /root/.gf && \
    cp /tmp/gf-patterns/*.json /root/.gf/ && \
    rm -rf /tmp/gf-patterns

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Download pre-built ProjectDiscovery binaries AFTER pip install
# (pip httpx library installs a CLI wrapper that overwrites Go httpx)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    for TOOL in subfinder httpx nuclei naabu; do \
        echo "--- ${TOOL} ---" && \
        URL=$(curl -sL "https://api.github.com/repos/projectdiscovery/${TOOL}/releases/latest" \
            | jq -r ".assets[] | select(.name | test(\"linux_${ARCH}.zip\")) | .browser_download_url") && \
        if [ -n "$URL" ] && [ "$URL" != "null" ]; then \
            curl -sL "$URL" -o "/tmp/${TOOL}.zip" && \
            unzip -o "/tmp/${TOOL}.zip" -d "/tmp/${TOOL}_dir" && \
            cp "/tmp/${TOOL}_dir/${TOOL}" "/usr/local/bin/${TOOL}" && \
            chmod +x "/usr/local/bin/${TOOL}" && \
            rm -rf "/tmp/${TOOL}.zip" "/tmp/${TOOL}_dir" && \
            echo "  OK"; \
        else echo "  SKIP"; fi; \
    done

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

RUN mkdir -p /data/scans

ENV MYRECON_CONFIG=/app/config.yaml

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "myrecon.app:app", "--host", "0.0.0.0", "--port", "8000"]
