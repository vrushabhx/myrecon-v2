from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists


class JsDiscoveryModule(BaseModule):
    name = "js_discovery"
    description = "Discover endpoints from JavaScript files"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        js_dir = Path(scan.scan_dir) / "js_endpoints"
        js_dir.mkdir(parents=True, exist_ok=True)

        if not scan.live_hosts:
            return findings

        if not tool_exists("linkfinder"):
            logger.warning("linkfinder not installed, skipping JS discovery")
            return findings

        all_endpoints = []
        for host in scan.live_hosts[:30]:
            code, stdout, _ = await run_tool(
                ["python3", "-m", "linkfinder", "-i", host, "-d", "-o", "cli"],
                timeout=60,
            )
            if stdout.strip():
                endpoints = [l.strip() for l in stdout.splitlines() if l.strip()]
                all_endpoints.extend(endpoints)
                (js_dir / f"{host.replace('://', '_').replace('/', '_')}.txt").write_text(
                    "\n".join(endpoints)
                )

        if all_endpoints:
            unique = list(set(all_endpoints))
            (js_dir / "all_endpoints.txt").write_text("\n".join(unique))
            findings.append(self.make_finding(
                title=f"JS Endpoint Discovery: {len(unique)} unique endpoints",
                severity=Severity.INFO,
                target=scan.domain,
                evidence="\n".join(unique[:30]),
            ))

        return findings
