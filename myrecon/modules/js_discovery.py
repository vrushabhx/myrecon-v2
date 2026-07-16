import re
from pathlib import Path
from urllib.parse import urlparse, urljoin

import httpx as httpx_client

from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, dedup_lines, write_lines

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
BUCKET_PATTERNS = [
    re.compile(r'["\']?(https?://[a-zA-Z0-9._-]+\.s3[.-]amazonaws\.com[/\w.-]*)["\']?'),
    re.compile(r'["\']?(https?://s3[.-][a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9._/-]+)["\']?'),
    re.compile(r'["\']?(https?://storage\.googleapis\.com/[a-zA-Z0-9._/-]+)["\']?'),
    re.compile(r'["\']?([a-zA-Z0-9._-]+\.storage\.googleapis\.com)["\']?'),
    re.compile(r'["\']?(https?://[a-zA-Z0-9._-]+\.blob\.core\.windows\.net[/\w.-]*)["\']?'),
]
API_ENDPOINT_RE = re.compile(r'["\'](/api/[a-zA-Z0-9/_.-]+)["\']')


class JsDiscoveryModule(BaseModule):
    name = "js_discovery"
    description = "JS endpoint mining, domain extraction, and bucket discovery"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        js_dir = Path(scan.scan_dir) / "js_endpoints"
        js_dir.mkdir(parents=True, exist_ok=True)

        if not scan.live_hosts:
            await self.progress("No live hosts for JS discovery")
            return findings

        all_endpoints = []
        js_file_urls = []

        if tool_exists("linkfinder"):
            await self.progress(f"Mining JS endpoints from {min(30, len(scan.live_hosts))} hosts...")
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
        else:
            await self.progress("linkfinder not installed, using HTML-based JS discovery")

        await self.progress("Discovering JS files from live hosts...")
        js_file_urls = await self._discover_js_files(scan.live_hosts[:30])
        await self.progress(f"Found {len(js_file_urls)} JS files")

        if js_file_urls:
            await self.progress(f"Analyzing {min(len(js_file_urls), 100)} JS files for domains and secrets...")
            js_domains, buckets, api_endpoints = await self._analyze_js_files(
                js_file_urls[:100], scan.domain
            )

            if js_domains:
                new_subs = [d for d in js_domains if d not in scan.subdomains]
                scan.subdomains = dedup_lines(scan.subdomains + new_subs)
                scan.js_domains = dedup_lines(scan.js_domains + js_domains)
                write_lines(str(js_dir / "js_domains.txt"), js_domains)
                if new_subs:
                    findings.append(self.make_finding(
                        title=f"JS Domain Discovery: {len(new_subs)} new subdomains from JavaScript",
                        description=f"Analyzed JavaScript files and discovered {len(new_subs)} subdomains of {scan.domain} that were not found by passive enumeration. These may be internal, staging, or API endpoints.",
                        severity=Severity.LOW,
                        target=scan.domain,
                        evidence="\n".join(new_subs[:30]),
                    ))

            if buckets:
                write_lines(str(js_dir / "js_buckets.txt"), buckets)
                findings.append(self.make_finding(
                    title=f"Cloud Buckets in JS: {len(buckets)} cloud storage URLs found",
                    description=f"Found {len(buckets)} cloud storage bucket references (S3, GCS, Azure Blob) hardcoded in JavaScript files. These should be tested for public access and sensitive data exposure.",
                    severity=Severity.MEDIUM,
                    target=scan.domain,
                    evidence="\n".join(buckets[:20]),
                ))

            if api_endpoints:
                all_endpoints.extend(api_endpoints)

        if all_endpoints:
            unique = dedup_lines(all_endpoints)
            (js_dir / "all_endpoints.txt").write_text("\n".join(unique))

            full_urls = []
            for ep in unique:
                if ep.startswith("http"):
                    full_urls.append(ep)
                elif ep.startswith("/"):
                    for host in scan.live_hosts[:5]:
                        full_urls.append(urljoin(host, ep))
                        break

            full_urls = dedup_lines(full_urls)
            scan.urls = dedup_lines(scan.urls + full_urls)
            scan.js_endpoints = dedup_lines(scan.js_endpoints + full_urls)

            findings.append(self.make_finding(
                title=f"JS Endpoint Discovery: {len(unique)} unique endpoints",
                description=f"Extracted {len(unique)} unique API endpoints and paths from JavaScript files. These have been merged into the URL collection for vulnerability scanning.",
                severity=Severity.INFO,
                target=scan.domain,
                evidence="\n".join(unique[:30]),
            ))

        return findings

    async def _discover_js_files(self, hosts: list[str]) -> list[str]:
        js_urls = set()
        async with httpx_client.AsyncClient(follow_redirects=True, timeout=15, verify=False) as client:
            for host in hosts:
                try:
                    resp = await client.get(host)
                    for match in SCRIPT_SRC_RE.findall(resp.text):
                        if match.startswith("http"):
                            js_urls.add(match)
                        elif match.startswith("//"):
                            js_urls.add("https:" + match)
                        elif match.startswith("/"):
                            js_urls.add(urljoin(host, match))
                except Exception:
                    continue
        return list(js_urls)

    async def _analyze_js_files(self, js_urls: list[str], target_domain: str) -> tuple[list[str], list[str], list[str]]:
        domains = set()
        buckets = set()
        api_endpoints = set()

        domain_re = re.compile(
            r'["\']?(https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?\.{escaped})[/"\'\s]'.format(
                escaped=re.escape(target_domain)
            )
        )

        async with httpx_client.AsyncClient(follow_redirects=True, timeout=15, verify=False) as client:
            for url in js_urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200 or len(resp.content) > 5 * 1024 * 1024:
                        continue
                    content = resp.text

                    for match in domain_re.findall(content):
                        full_domain = match[1]
                        if full_domain != target_domain and len(full_domain) > len(target_domain):
                            domains.add(full_domain)

                    for pattern in BUCKET_PATTERNS:
                        for match in pattern.findall(content):
                            buckets.add(match)

                    for match in API_ENDPOINT_RE.findall(content):
                        api_endpoints.add(match)

                except Exception:
                    continue

        return list(domains), list(buckets), list(api_endpoints)
