import logging
import os
from pathlib import Path
import yaml

logger = logging.getLogger("myrecon.config")

_config = None

_DEFAULTS = {
    "data_dir": "/data",
    "server": {"host": "0.0.0.0", "port": 8000, "api_key": ""},
    "tokens": {"github_token": "", "shodan_key": ""},
    "notifications": {},
    "tools": {
        "threads": 50,
        "timeout": 3600,
        "nuclei_severity": "critical,high,medium,low",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "dns_wordlist": "/app/wordlists/dns_subdomains.txt",
        "resolvers": "/app/wordlists/resolvers.txt",
        "max_sqlmap_urls": 100,
        "max_redirect_urls": 50,
        "max_lfi_urls": 50,
        "max_ssti_urls": 50,
    },
    "scan_defaults": {
        "modules": [
            "subdomain", "subdomain_bruteforce", "probing", "portscan",
            "screenshot", "dirbrute", "js_discovery", "csp_extraction",
            "url_collection", "vuln_scan", "subdomain_takeover",
            "cloud_enum", "github_recon",
        ],
        "wordlist": "/app/wordlists/paths.txt",
        "excluded_subdomains": [],
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(path: str = None) -> dict:
    global _config
    if _config and not path:
        return _config

    config_path = path or os.environ.get("MYRECON_CONFIG", "/app/config.yaml")
    fallback = Path(__file__).parent.parent / "config.yaml"

    p = Path(config_path)
    if not p.exists():
        p = fallback

    parsed = None
    if p.exists():
        try:
            raw = p.read_bytes()
            # Strip BOM if present
            if raw.startswith(b"\xef\xbb\xbf"):
                raw = raw[3:]
            content = raw.decode("utf-8", errors="replace")
            # Strip all carriage returns
            content = content.replace("\r", "")
            parsed = yaml.safe_load(content)
        except Exception as e:
            logger.warning("Failed to parse %s: %s. Using defaults.", p, e)

    if not isinstance(parsed, dict):
        parsed = {}

    _config = _deep_merge(_DEFAULTS, parsed)
    os.makedirs(_config["data_dir"], exist_ok=True)
    return _config


def get_config() -> dict:
    if _config is None:
        return load_config()
    return _config
