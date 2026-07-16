from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines


class DirbruteModule(BaseModule):
    name = "dirbrute"
    description = "Directory bruteforce using ffuf"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        dir_dir = Path(scan.scan_dir) / "directory"
        dir_dir.mkdir(parents=True, exist_ok=True)

        if not scan.live_hosts or not tool_exists("ffuf"):
            if not tool_exists("ffuf"):
                await self.progress("ffuf not installed, skipping")
            else:
                await self.progress("No live hosts for directory bruteforce")
            return findings

        wordlist = scan.config.get("wordlist") or "/app/wordlists/paths.txt"
        ua = scan.config.get("tools", {}).get("user_agent", "Mozilla/5.0")
        threads = min(scan.config.get("tools", {}).get("threads", 50), 100)
        target_count = min(len(scan.live_hosts), 50)

        total_found = 0
        for i, host in enumerate(scan.live_hosts[:50]):
            await self.progress(f"ffuf [{i+1}/{target_count}]: {host}")
            out_file = dir_dir / f"ffuf_{host.replace('://', '_').replace('/', '_')}.json"
            code, stdout, _ = await run_tool(
                ["ffuf", "-u", f"{host}/FUZZ", "-w", wordlist,
                 "-H", f"User-Agent: {ua}",
                 "-mc", "200,204,301,302,307,401,403",
                 "-fc", "404",
                 "-t", str(threads),
                 "-timeout", "10",
                 "-o", str(out_file),
                 "-of", "json",
                 "-s"],
                timeout=120,
            )
            if out_file.exists() and out_file.stat().st_size > 10:
                total_found += 1

        if total_found > 0:
            findings.append(self.make_finding(
                title=f"Directory Bruteforce: results for {total_found} hosts",
                severity=Severity.INFO,
                target=scan.domain,
            ))
        return findings
