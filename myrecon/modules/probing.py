from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines


class ProbingModule(BaseModule):
    name = "probing"
    description = "Probe subdomains for live HTTP/HTTPS hosts"
    dependencies = ["subdomain"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        probe_dir = Path(scan.scan_dir) / "probing"
        probe_dir.mkdir(parents=True, exist_ok=True)

        if not scan.subdomains:
            logger.warning("No subdomains to probe")
            return findings

        input_file = probe_dir / "input.txt"
        write_lines(str(input_file), scan.subdomains)

        live = []
        if tool_exists("httpx"):
            live = await self._run_httpx(input_file, probe_dir)
        elif tool_exists("httprobe"):
            live = await self._run_httprobe(input_file, probe_dir)
        else:
            logger.error("Neither httpx nor httprobe installed")
            return findings

        scan.live_hosts = live
        write_lines(str(probe_dir / "live_hosts.txt"), live)

        findings.append(self.make_finding(
            title=f"Host Probing: {len(live)} live hosts from {len(scan.subdomains)} subdomains",
            description=f"Probed {len(scan.subdomains)} subdomains, {len(live)} responded on HTTP/HTTPS",
            severity=Severity.INFO,
            target=scan.domain,
            evidence="\n".join(live[:30]) + (f"\n... and {len(live)-30} more" if len(live) > 30 else ""),
        ))
        return findings

    async def _run_httpx(self, input_file: Path, out_dir: Path) -> list[str]:
        out = out_dir / "httpx.txt"
        code, stdout, _ = await run_tool(
            ["httpx", "-l", str(input_file), "-silent", "-threads", "100",
             "-timeout", "15", "-no-color", "-o", str(out)],
            timeout=600,
        )
        if out.exists():
            return [l.strip() for l in out.read_text().splitlines() if l.strip()]
        return [l.strip() for l in stdout.splitlines() if l.strip()]

    async def _run_httprobe(self, input_file: Path, out_dir: Path) -> list[str]:
        input_data = input_file.read_text()
        code, stdout, _ = await run_tool(
            ["httprobe", "-c", "100", "-t", "20000"],
            input_data=input_data,
            timeout=600,
        )
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        (out_dir / "httprobe.txt").write_text("\n".join(lines))
        return lines
