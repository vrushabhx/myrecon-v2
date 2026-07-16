import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable

from myrecon.config import get_config
from myrecon.models import Scan, ScanStatus, ModuleStatus, ScanRequest
from myrecon.modules import ALL_MODULES

logger = logging.getLogger("myrecon")

_scans: dict[str, Scan] = {}
_listeners: dict[str, list[Callable]] = {}


def get_scan(scan_id: str) -> Scan | None:
    return _scans.get(scan_id)


def list_scans() -> list[Scan]:
    return sorted(_scans.values(), key=lambda s: s.created_at, reverse=True)


def subscribe(scan_id: str, callback: Callable):
    _listeners.setdefault(scan_id, []).append(callback)


def unsubscribe(scan_id: str, callback: Callable):
    if scan_id in _listeners:
        _listeners[scan_id] = [c for c in _listeners[scan_id] if c is not callback]


async def _emit(scan_id: str, event: dict):
    for cb in _listeners.get(scan_id, []):
        try:
            await cb(event)
        except Exception:
            pass


def _resolve_modules(requested: list[str]) -> list[str]:
    if not requested:
        requested = list(ALL_MODULES.keys())

    resolved = []
    visited = set()

    def _add(name: str):
        if name in visited or name not in ALL_MODULES:
            return
        visited.add(name)
        mod_cls = ALL_MODULES[name]
        for dep in mod_cls.dependencies:
            _add(dep)
        resolved.append(name)

    for m in requested:
        _add(m)
    return resolved


def _save_scan(scan: Scan):
    scan_file = Path(scan.scan_dir) / "scan.json"
    scan_file.parent.mkdir(parents=True, exist_ok=True)
    scan_file.write_text(scan.model_dump_json(indent=2))


def _load_scans():
    config = get_config()
    data_dir = Path(config["data_dir"])
    scans_dir = data_dir / "scans"
    if not scans_dir.exists():
        return
    for scan_dir in scans_dir.iterdir():
        scan_file = scan_dir / "scan.json"
        if scan_file.exists():
            try:
                scan = Scan.model_validate_json(scan_file.read_text())
                _scans[scan.id] = scan
            except Exception as e:
                logger.error(f"Failed to load scan from {scan_file}: {e}")


async def start_scan(request: ScanRequest) -> Scan:
    config = get_config()
    scan = Scan(
        domain=request.domain,
        modules_requested=request.modules or list(ALL_MODULES.keys()),
        config={
            "tokens": config.get("tokens", {}),
            "tools": config.get("tools", {}),
            "wordlist": request.wordlist or config.get("scan_defaults", {}).get("wordlist", ""),
            "blind_xss": request.blind_xss,
            "ssrf_url": request.ssrf_url,
            "excluded_subdomains": request.excluded_subdomains,
            "notifications": config.get("notifications", {}),
        },
    )

    data_dir = Path(config["data_dir"])
    scan.scan_dir = str(data_dir / "scans" / scan.id)
    Path(scan.scan_dir).mkdir(parents=True, exist_ok=True)

    _scans[scan.id] = scan
    _save_scan(scan)

    asyncio.create_task(_run_scan(scan, request.notify))
    return scan


async def cancel_scan(scan_id: str) -> bool:
    scan = _scans.get(scan_id)
    if not scan or scan.status != ScanStatus.RUNNING:
        return False
    scan.status = ScanStatus.CANCELLED
    _save_scan(scan)
    await _emit(scan_id, {"type": "cancelled"})
    return True


async def _run_scan(scan: Scan, notify: bool = True):
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow().isoformat()
    await _emit(scan.id, {"type": "started", "scan_id": scan.id})
    _save_scan(scan)

    modules_to_run = _resolve_modules(scan.modules_requested)
    logger.info(f"Scan {scan.id}: running modules {modules_to_run}")

    for mod_name in modules_to_run:
        if scan.status == ScanStatus.CANCELLED:
            break

        scan.set_module_status(mod_name, ModuleStatus.RUNNING)
        await _emit(scan.id, {"type": "module_started", "module": mod_name})
        _save_scan(scan)

        try:
            mod_instance = ALL_MODULES[mod_name]()

            async def _progress(msg):
                await _emit(scan.id, {"type": "progress", "module": mod_name, "message": msg})

            mod_instance._progress_callback = _progress
            new_findings = await mod_instance.run(scan)
            for f in new_findings:
                scan.add_finding(f)

            scan.set_module_status(mod_name, ModuleStatus.COMPLETED)
            scan.module_results[mod_name].findings_count = len(new_findings)
            await _emit(scan.id, {
                "type": "module_completed",
                "module": mod_name,
                "findings_count": len(new_findings),
                "stats": {
                    "subdomains": len(scan.subdomains),
                    "live_hosts": len(scan.live_hosts),
                    "open_ports": sum(len(p) for p in scan.open_ports.values()),
                    "findings": len(scan.findings),
                    "urls": len(scan.urls),
                },
            })
            logger.info(f"Scan {scan.id}: {mod_name} completed with {len(new_findings)} findings")

        except Exception as e:
            logger.error(f"Scan {scan.id}: {mod_name} failed: {e}", exc_info=True)
            scan.set_module_status(mod_name, ModuleStatus.FAILED, str(e))
            await _emit(scan.id, {"type": "module_failed", "module": mod_name, "error": str(e)})

        _save_scan(scan)

    if scan.status != ScanStatus.CANCELLED:
        scan.status = ScanStatus.COMPLETED
    scan.finished_at = datetime.utcnow().isoformat()
    _save_scan(scan)

    await _emit(scan.id, {
        "type": "completed",
        "total_findings": len(scan.findings),
        "status": scan.status.value,
    })

    if notify:
        try:
            from myrecon.notify.notifier import send_notifications
            await send_notifications(scan)
        except Exception as e:
            logger.error(f"Notification failed: {e}")

    logger.info(f"Scan {scan.id} finished: {len(scan.findings)} findings")


def init_scanner():
    _load_scans()
