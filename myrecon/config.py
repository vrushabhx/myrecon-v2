import os
from pathlib import Path
import yaml


_config = None


def load_config(path: str = None) -> dict:
    global _config
    if _config and not path:
        return _config

    config_path = path or os.environ.get("MYRECON_CONFIG", "/app/config.yaml")
    fallback = Path(__file__).parent.parent / "config.yaml"

    p = Path(config_path)
    if not p.exists():
        p = fallback

    with open(p) as f:
        _config = yaml.safe_load(f)

    _config.setdefault("data_dir", "/data")
    _config.setdefault("server", {})
    _config["server"].setdefault("host", "0.0.0.0")
    _config["server"].setdefault("port", 8000)
    _config["server"].setdefault("api_key", "")
    _config.setdefault("tokens", {})
    _config.setdefault("notifications", {})
    _config.setdefault("tools", {})
    _config["tools"].setdefault("threads", 50)
    _config["tools"].setdefault("timeout", 3600)
    _config.setdefault("scan_defaults", {})

    os.makedirs(_config["data_dir"], exist_ok=True)
    return _config


def get_config() -> dict:
    if _config is None:
        return load_config()
    return _config
