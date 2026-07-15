import os
from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, dedup_lines, write_lines


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Subdomain enumeration using multiple tools"
    dependencies = []

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        sub_dir = Path(scan.scan_dir) / "subdomains"
        sub_dir.mkdir(parents=True, exist_ok=True)
        all_subs = []

        tools = [
            ("subfinder", self._run_subfinder),
            ("assetfinder", self._run_assetfinder),
            ("amass", self._run_amass),
            ("findomain", self._run_findomain),
        ]

        for tool_name, runner in tools:
            if not tool_exists(tool_name):
                logger.warning(f"{tool_name} not installed, skipping")
                continue
            try:
                subs = await runner(scan.domain, sub_dir)
                all_subs.extend(subs)
                logger.info(f"{tool_name} found {len(subs)} subdomains")
            except Exception as e:
                logger.error(f"{tool_name} failed: {e}")

        github_token = scan.config.get("tokens", {}).get("github_token", "")
        if github_token:
            try:
                subs = await self._run_github_subdomains(scan.domain, github_token, sub_dir)
                all_subs.extend(subs)
            except Exception as e:
                logger.error(f"github-subdomains failed: {e}")

        unique = dedup_lines(all_subs)
        filtered = [s for s in unique if s.endswith(f".{scan.domain}") or s == scan.domain]

        excluded = scan.config.get("excluded_subdomains", [])
        if excluded:
            filtered = [s for s in filtered if s not in excluded]

        scan.subdomains = filtered
        out_file = sub_dir / f"{scan.domain}_all.txt"
        write_lines(str(out_file), filtered)

        findings.append(self.make_finding(
            title=f"Subdomain Enumeration: {len(filtered)} unique subdomains",
            description=f"Found {len(filtered)} unique subdomains for {scan.domain}",
            severity=Severity.INFO,
            target=scan.domain,
            evidence="\n".join(filtered[:50]) + (f"\n... and {len(filtered)-50} more" if len(filtered) > 50 else ""),
        ))
        return findings

    async def _run_subfinder(self, domain: str, out_dir: Path) -> list[str]:
        out = out_dir / "subfinder.txt"
        code, stdout, stderr = await run_tool(
            ["subfinder", "-all", "-d", domain, "-silent", "-o", str(out)],
            timeout=600,
        )
        if out.exists():
            return out.read_text().strip().splitlines()
        return [l.strip() for l in stdout.splitlines() if l.strip()]

    async def _run_assetfinder(self, domain: str, out_dir: Path) -> list[str]:
        code, stdout, _ = await run_tool(
            ["assetfinder", "--subs-only", domain],
            timeout=300,
        )
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        (out_dir / "assetfinder.txt").write_text("\n".join(lines))
        return lines

    async def _run_amass(self, domain: str, out_dir: Path) -> list[str]:
        out = out_dir / "amass.txt"
        config = os.environ.get("AMASS_CONFIG", "")
        cmd = ["amass", "enum", "-passive", "-d", domain, "-o", str(out)]
        if config:
            cmd.extend(["-config", config])
        code, stdout, _ = await run_tool(cmd, timeout=900)
        if out.exists():
            return out.read_text().strip().splitlines()
        return []

    async def _run_findomain(self, domain: str, out_dir: Path) -> list[str]:
        code, stdout, _ = await run_tool(
            ["findomain", "-t", domain, "-q"],
            timeout=300,
        )
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        (out_dir / "findomain.txt").write_text("\n".join(lines))
        return lines

    async def _run_github_subdomains(self, domain: str, token: str, out_dir: Path) -> list[str]:
        if not tool_exists("github-subdomains"):
            return []
        code, stdout, _ = await run_tool(
            ["github-subdomains", "-t", token, "-d", domain],
            timeout=300,
        )
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        (out_dir / "github_subs.txt").write_text("\n".join(lines))
        return lines
