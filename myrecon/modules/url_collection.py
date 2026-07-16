import re
from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, dedup_lines, write_lines


STATIC_EXT = re.compile(r"\.(jpg|jpeg|png|svg|gif|ttf|css|woff|woff2|eot|mp[34]|pdf|exe)$", re.I)


class UrlCollectionModule(BaseModule):
    name = "url_collection"
    description = "Collect URLs from Wayback Machine, GAU, and web crawling"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        url_dir = Path(scan.scan_dir) / "urls"
        url_dir.mkdir(parents=True, exist_ok=True)

        if not scan.live_hosts:
            await self.progress("No live hosts for URL collection")
            return findings

        stripped = [h.replace("https://", "").replace("http://", "").split("/")[0]
                    for h in scan.live_hosts]
        stripped = list(set(stripped))
        input_file = url_dir / "hosts.txt"
        write_lines(str(input_file), stripped)

        all_urls = []

        if tool_exists("waybackurls"):
            await self.progress("Running waybackurls...")
            urls = await self._run_waybackurls(input_file, url_dir)
            all_urls.extend(urls)
            await self.progress(f"waybackurls collected {len(urls)} URLs")
        else:
            await self.progress("waybackurls not installed, skipping")

        if tool_exists("gau"):
            await self.progress("Running gau...")
            urls = await self._run_gau(input_file, url_dir)
            all_urls.extend(urls)
            await self.progress(f"gau collected {len(urls)} URLs")
        else:
            await self.progress("gau not installed, skipping")

        if tool_exists("gospider"):
            await self.progress(f"Running gospider on {min(30, len(scan.live_hosts))} hosts...")
            urls = await self._run_gospider(scan.live_hosts[:30], url_dir)
            all_urls.extend(urls)
            await self.progress(f"gospider collected {len(urls)} URLs")
        else:
            await self.progress("gospider not installed, skipping")

        filtered = [u for u in all_urls if not STATIC_EXT.search(u)]
        parameterized = [u for u in filtered if "=" in u]
        unique_all = dedup_lines(filtered)
        unique_params = dedup_lines(parameterized)

        scan.urls = unique_all
        write_lines(str(url_dir / "all_urls.txt"), unique_all)
        write_lines(str(url_dir / "parameterized.txt"), unique_params)

        findings.append(self.make_finding(
            title=f"URL Collection: {len(unique_all)} URLs ({len(unique_params)} with parameters)",
            severity=Severity.INFO,
            target=scan.domain,
            evidence=f"Total: {len(unique_all)}\nParameterized: {len(unique_params)}",
        ))
        return findings

    async def _run_waybackurls(self, input_file: Path, out_dir: Path) -> list[str]:
        input_data = input_file.read_text()
        code, stdout, _ = await run_tool(
            ["waybackurls", "-no-subs"],
            input_data=input_data,
            timeout=600,
        )
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        (out_dir / "waybackurls.txt").write_text("\n".join(lines))
        return lines

    async def _run_gau(self, input_file: Path, out_dir: Path) -> list[str]:
        input_data = input_file.read_text()
        code, stdout, _ = await run_tool(
            ["gau", "--threads", "5"],
            input_data=input_data,
            timeout=600,
        )
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        (out_dir / "gau.txt").write_text("\n".join(lines))
        return lines

    async def _run_gospider(self, hosts: list[str], out_dir: Path) -> list[str]:
        crawl_dir = out_dir / "crawl"
        crawl_dir.mkdir(exist_ok=True)
        all_lines = []
        for host in hosts:
            code, stdout, _ = await run_tool(
                ["gospider", "-s", host, "-c", "10", "-d", "2", "-t", "5", "--no-redirect"],
                timeout=120,
            )
            for line in stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    url = parts[-1]
                    if url.startswith("http"):
                        all_lines.append(url)
        (out_dir / "gospider.txt").write_text("\n".join(all_lines))
        return all_lines
