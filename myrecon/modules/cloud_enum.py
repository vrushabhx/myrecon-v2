from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists


class CloudEnumModule(BaseModule):
    name = "cloud_enum"
    description = "Enumerate cloud storage buckets (S3, GCP, Azure)"
    dependencies = ["subdomain"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        cloud_dir = Path(scan.scan_dir) / "cloud"
        cloud_dir.mkdir(parents=True, exist_ok=True)

        keyword = scan.domain.split(".")[0]

        if tool_exists("cloud_enum"):
            for provider, flag in [("aws", "--disable-azure --disable-gcp"),
                                   ("gcp", "--disable-azure --disable-aws"),
                                   ("azure", "--disable-aws --disable-gcp")]:
                out = cloud_dir / f"{provider}.txt"
                cmd = ["cloud_enum", "-k", keyword, "-l", str(out), "-t", "20"]
                cmd.extend(flag.split())
                code, stdout, _ = await run_tool(cmd, timeout=600)

                if out.exists() and out.stat().st_size > 0:
                    content = out.read_text().strip()
                    if content:
                        findings.append(self.make_finding(
                            title=f"Cloud Buckets ({provider.upper()}): potential buckets found",
                            description=f"cloud_enum found potential {provider.upper()} storage for keyword '{keyword}'",
                            severity=Severity.LOW,
                            target=scan.domain,
                            evidence=content[:2000],
                        ))
        else:
            logger.warning("cloud_enum not installed, skipping cloud enumeration")

        return findings
