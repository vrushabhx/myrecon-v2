from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines


class ScreenshotModule(BaseModule):
    name = "screenshot"
    description = "Take screenshots of live hosts"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        ss_dir = Path(scan.scan_dir) / "screenshots"
        ss_dir.mkdir(parents=True, exist_ok=True)

        if not scan.live_hosts:
            await self.progress("No live hosts for screenshots")
            return findings

        input_file = ss_dir / "targets.txt"
        write_lines(str(input_file), scan.live_hosts)

        if tool_exists("gowitness"):
            await self.progress(f"Running gowitness on {len(scan.live_hosts)} hosts...")
            await self._run_gowitness(input_file, ss_dir)
            await self.progress("Screenshots complete")
            findings.append(self.make_finding(
                title=f"Screenshots: captured {len(scan.live_hosts)} hosts",
                severity=Severity.INFO,
                target=scan.domain,
            ))
        else:
            await self.progress("gowitness not installed, skipping screenshots")

        return findings

    async def _run_gowitness(self, input_file: Path, out_dir: Path):
        await run_tool(
            ["gowitness", "file", "-f", str(input_file),
             "--screenshot-path", str(out_dir), "--threads", "10"],
            timeout=900,
        )
