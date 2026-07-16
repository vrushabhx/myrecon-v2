import re
from pathlib import Path

import httpx as httpx_client

from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import dedup_lines, write_lines

CSP_DIRECTIVE_RE = re.compile(r"([\w-]+)\s+([^;]+)")
DOMAIN_RE = re.compile(r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])\.[a-zA-Z]{2,})")
UNSAFE_KEYWORDS = {"'unsafe-inline'", "'unsafe-eval'"}


class CspExtractionModule(BaseModule):
    name = "csp_extraction"
    description = "Extract domains from Content-Security-Policy headers"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        csp_dir = Path(scan.scan_dir) / "csp"
        csp_dir.mkdir(parents=True, exist_ok=True)

        if not scan.live_hosts:
            await self.progress("No live hosts for CSP extraction")
            return findings

        await self.progress(f"Checking CSP headers on {min(len(scan.live_hosts), 50)} hosts...")

        all_csp_domains = set()
        all_unsafe = set()
        hosts_with_csp = 0
        hosts_without_csp = 0

        async with httpx_client.AsyncClient(follow_redirects=True, timeout=15, verify=False) as client:
            for host in scan.live_hosts[:50]:
                try:
                    resp = await client.get(host)
                    csp_header = resp.headers.get("content-security-policy", "")
                    csp_ro = resp.headers.get("content-security-policy-report-only", "")
                    combined = f"{csp_header}; {csp_ro}".strip("; ")

                    if not combined:
                        hosts_without_csp += 1
                        continue

                    hosts_with_csp += 1
                    domains, unsafe = self._parse_csp(combined, scan.domain)
                    all_csp_domains.update(domains)
                    all_unsafe.update(unsafe)

                except Exception:
                    continue

        csp_domains_list = sorted(all_csp_domains)
        target_subs = [d for d in csp_domains_list if d.endswith(f".{scan.domain}")]
        third_party = [d for d in csp_domains_list if not d.endswith(f".{scan.domain}")]

        if target_subs:
            new_subs = [d for d in target_subs if d not in scan.subdomains]
            scan.subdomains = dedup_lines(scan.subdomains + new_subs)
            scan.csp_domains = dedup_lines(scan.csp_domains + target_subs)

            if new_subs:
                await self.progress(f"CSP revealed {len(new_subs)} new subdomains")

        if csp_domains_list:
            write_lines(str(csp_dir / "csp_domains.txt"), csp_domains_list)
            if target_subs:
                write_lines(str(csp_dir / "csp_subdomains.txt"), target_subs)
            if third_party:
                write_lines(str(csp_dir / "csp_third_party.txt"), third_party)

            findings.append(self.make_finding(
                title=f"CSP Domain Discovery: {len(csp_domains_list)} domains extracted",
                description=f"Extracted {len(csp_domains_list)} domains from CSP headers across {hosts_with_csp} hosts. Found {len(target_subs)} subdomains of {scan.domain} and {len(third_party)} third-party domains. {hosts_without_csp} hosts had no CSP header.",
                severity=Severity.INFO,
                target=scan.domain,
                evidence="Subdomains:\n" + "\n".join(target_subs[:15]) +
                         ("\n\nThird-party:\n" + "\n".join(third_party[:10]) if third_party else ""),
            ))

        if all_unsafe:
            findings.append(self.make_finding(
                title=f"Weak CSP: {', '.join(all_unsafe)} detected",
                description=f"Content-Security-Policy uses unsafe directives: {', '.join(all_unsafe)}. 'unsafe-inline' allows inline script execution (XSS risk). 'unsafe-eval' allows eval() and similar dynamic code execution.",
                severity=Severity.MEDIUM,
                target=scan.domain,
                evidence=f"Unsafe directives found: {', '.join(all_unsafe)}",
            ))

        if hosts_without_csp > 0 and hosts_with_csp == 0:
            findings.append(self.make_finding(
                title=f"Missing CSP Header on {hosts_without_csp} hosts",
                description=f"No Content-Security-Policy header found on any of the {hosts_without_csp} tested hosts. CSP helps prevent XSS and data injection attacks.",
                severity=Severity.LOW,
                target=scan.domain,
            ))

        return findings

    def _parse_csp(self, csp: str, target_domain: str) -> tuple[set[str], set[str]]:
        domains = set()
        unsafe = set()

        for directive_match in CSP_DIRECTIVE_RE.finditer(csp):
            values = directive_match.group(2).split()
            for val in values:
                val_clean = val.strip().strip("'\"")

                if val_clean.lower() in UNSAFE_KEYWORDS:
                    unsafe.add(val_clean)
                    continue

                if val_clean in ("'self'", "'none'", "'strict-dynamic'", "'nonce-", "data:", "blob:", "mediastream:"):
                    continue
                if val_clean.startswith("'nonce-") or val_clean.startswith("'sha"):
                    continue
                if val_clean.startswith("*."):
                    val_clean = val_clean[2:]

                for m in DOMAIN_RE.findall(val_clean):
                    if "." in m and not m.startswith("0.") and len(m) > 4:
                        domains.add(m)

        return domains, unsafe
