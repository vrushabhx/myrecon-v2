from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists


class GithubReconModule(BaseModule):
    name = "github_recon"
    description = "Search GitHub for leaked secrets and sensitive data"
    dependencies = ["subdomain"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        gh_dir = Path(scan.scan_dir) / "github_recon"
        gh_dir.mkdir(parents=True, exist_ok=True)

        github_token = scan.config.get("tokens", {}).get("github_token", "")
        if not github_token:
            await self.progress("No GitHub token configured, skipping")
            return findings

        if tool_exists("gitGraber.py") or tool_exists("trufflehog"):
            if tool_exists("trufflehog"):
                await self.progress("Running trufflehog for GitHub secret scanning...")
                code, stdout, _ = await run_tool(
                    ["trufflehog", "github", "--org", scan.domain.split(".")[0],
                     "--token", github_token, "--json"],
                    timeout=600,
                )
                if stdout.strip():
                    (gh_dir / "trufflehog.json").write_text(stdout)
                    findings.append(Finding(
                        module="github_recon",
                        title="GitHub Secret Leak: potential secrets found",
                        description=f"TruffleHog found potential secrets in GitHub repos related to {scan.domain}",
                        severity=Severity.HIGH,
                        target=scan.domain,
                        evidence=stdout[:2000],
                    ))
        else:
            await self.progress("No GitHub recon tools installed (trufflehog), skipping")

        return findings
