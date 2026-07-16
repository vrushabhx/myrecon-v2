import json
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

        all_discovered = []
        for i, host in enumerate(scan.live_hosts[:50]):
            await self.progress(f"ffuf [{i+1}/{target_count}]: {host}")
            out_file = dir_dir / f"ffuf_{host.replace('://', '_').replace('/', '_')}.json"
            code, stdout, _ = await run_tool(
                ["ffuf", "-u", f"{host}/FUZZ", "-w", wordlist,
                 "-H", f"User-Agent: {ua}",
                 "-H", "X-Forwarded-For: 127.0.0.1",
                 "-mc", "200,204,301,302,307,401,403",
                 "-fc", "404",
                 "-fl", "1,2,3",
                 "-t", str(threads),
                 "-timeout", "10",
                 "-o", str(out_file),
                 "-of", "json",
                 "-s"],
                timeout=120,
            )
            if not out_file.exists() or out_file.stat().st_size < 10:
                continue

            try:
                data = json.loads(out_file.read_text())
                results = data.get("results", [])
                if not results:
                    continue

                accessible = []
                restricted = []
                redirects = []

                for r in results:
                    entry = {
                        "url": r.get("url", ""),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                        "words": r.get("words", 0),
                        "lines": r.get("lines", 0),
                        "path": r.get("input", {}).get("FUZZ", ""),
                    }
                    if entry["status"] in (200, 204):
                        accessible.append(entry)
                    elif entry["status"] in (401, 403):
                        restricted.append(entry)
                    elif entry["status"] in (301, 302, 307):
                        redirects.append(entry)

                    all_discovered.append(f"{entry['status']} {entry['url']}")

                if accessible:
                    evidence_lines = [f"  [{e['status']}] {e['url']} (size: {e['length']}, words: {e['words']})"
                                      for e in accessible[:20]]
                    findings.append(self.make_finding(
                        title=f"Accessible Paths on {host[:60]} ({len(accessible)} found)",
                        description=f"Directory bruteforce discovered {len(accessible)} accessible paths (HTTP 200/204) on {host}. These may expose sensitive functionality, admin panels, debug endpoints, or information disclosure.",
                        severity=Severity.MEDIUM,
                        target=host,
                        evidence="\n".join(evidence_lines),
                    ))

                if restricted:
                    evidence_lines = [f"  [{e['status']}] {e['url']} (size: {e['length']})"
                                      for e in restricted[:20]]
                    findings.append(self.make_finding(
                        title=f"Restricted Paths on {host[:60]} ({len(restricted)} found)",
                        description=f"Found {len(restricted)} restricted paths (HTTP 401/403) on {host}. These confirm the existence of protected resources that may be targets for authorization bypass testing.",
                        severity=Severity.LOW,
                        target=host,
                        evidence="\n".join(evidence_lines),
                    ))

            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to parse ffuf output for {host}: {e}")

        if all_discovered:
            write_lines(str(dir_dir / "discovered_paths.txt"), all_discovered)

        return findings
