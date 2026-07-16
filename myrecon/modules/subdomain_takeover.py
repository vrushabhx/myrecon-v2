import json
from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines


class SubdomainTakeoverModule(BaseModule):
    name = "subdomain_takeover"
    description = "Check for subdomain takeover vulnerabilities"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        takeover_dir = Path(scan.scan_dir) / "takeover"
        takeover_dir.mkdir(parents=True, exist_ok=True)

        if not scan.subdomains:
            await self.progress("No subdomains to check for takeover")
            return findings

        subs_file = takeover_dir / "subs_input.txt"
        write_lines(str(subs_file), scan.subdomains)

        if tool_exists("subjack"):
            await self.progress(f"Running subjack on {len(scan.subdomains)} subdomains...")
            f = await self._run_subjack(scan, takeover_dir, subs_file)
            findings.extend(f)
        elif tool_exists("nuclei"):
            await self.progress("Running nuclei takeover templates...")
            f = await self._run_nuclei_takeover(scan, takeover_dir, subs_file)
            findings.extend(f)
        else:
            await self.progress("No takeover tool installed (subjack/nuclei), skipping")

        if findings:
            await self.progress(f"Found {len(findings)} potential subdomain takeovers")
        else:
            await self.progress("No subdomain takeovers detected")

        return findings

    async def _run_subjack(self, scan: Scan, out_dir: Path, subs_file: Path) -> list[Finding]:
        findings = []
        out_file = out_dir / "subjack.txt"

        code, stdout, stderr = await run_tool(
            ["subjack", "-w", str(subs_file), "-t", "50",
             "-timeout", "20", "-o", str(out_file), "-ssl", "-a"],
            timeout=600,
        )

        output = out_file.read_text() if out_file.exists() else stdout
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if "not vulnerable" in line.lower():
                continue

            findings.append(Finding(
                module="subdomain_takeover",
                title=f"Subdomain Takeover: {line[:80]}",
                description=f"Potential subdomain takeover detected. The subdomain's DNS record (CNAME) points to an unclaimed third-party resource. An attacker could register the resource and serve malicious content on this subdomain.",
                severity=Severity.HIGH,
                target=line.split()[0] if line.split() else scan.domain,
                evidence=line,
                raw_output=line,
            ))

        return findings

    async def _run_nuclei_takeover(self, scan: Scan, out_dir: Path, subs_file: Path) -> list[Finding]:
        findings = []
        out_file = out_dir / "nuclei_takeover.jsonl"

        code, stdout, stderr = await run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "http/takeovers/",
             "-silent", "-jsonl", "-o", str(out_file)],
            timeout=600,
        )

        output = out_file.read_text() if out_file.exists() else ""
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                matched = data.get("matched-at", "")
                name = info.get("name", "Subdomain Takeover")
                sev_str = info.get("severity", "high").lower()
                sev = {"critical": Severity.CRITICAL, "high": Severity.HIGH}.get(sev_str, Severity.HIGH)

                findings.append(Finding(
                    module="subdomain_takeover",
                    title=f"Subdomain Takeover [{data.get('template-id', '')}]: {name}",
                    description=f"Nuclei detected a potential subdomain takeover at {matched}. Template: {data.get('template-id', '')}. {info.get('description', '')}",
                    severity=sev,
                    target=matched,
                    evidence=f"Template: {data.get('template-id')}\nMatched: {matched}",
                    raw_output=line,
                ))
            except json.JSONDecodeError:
                continue

        return findings
