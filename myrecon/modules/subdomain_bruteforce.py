from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, dedup_lines, write_lines


class SubdomainBruteforceModule(BaseModule):
    name = "subdomain_bruteforce"
    description = "Active DNS subdomain bruteforcing with puredns/shuffledns"
    dependencies = ["subdomain"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        brute_dir = Path(scan.scan_dir) / "subdomain_brute"
        brute_dir.mkdir(parents=True, exist_ok=True)

        wordlist = scan.config.get("tools", {}).get("dns_wordlist", "/app/wordlists/dns_subdomains.txt")
        resolvers = scan.config.get("tools", {}).get("resolvers", "/app/wordlists/resolvers.txt")

        if not Path(wordlist).exists():
            await self.progress(f"DNS wordlist not found: {wordlist}, skipping bruteforce")
            return findings

        if not Path(resolvers).exists():
            await self.progress(f"Resolvers file not found: {resolvers}, skipping bruteforce")
            return findings

        before_count = len(scan.subdomains)
        new_subs = []

        if tool_exists("puredns"):
            await self.progress("Running puredns bruteforce...")
            new_subs = await self._run_puredns(scan, brute_dir, wordlist, resolvers)
        elif tool_exists("shuffledns"):
            await self.progress("Running shuffledns bruteforce...")
            new_subs = await self._run_shuffledns(scan, brute_dir, wordlist, resolvers)
        elif tool_exists("massdns"):
            await self.progress("Running massdns bruteforce...")
            new_subs = await self._run_massdns(scan, brute_dir, wordlist, resolvers)
        else:
            await self.progress("No DNS bruteforce tool installed (puredns/shuffledns/massdns), skipping")
            return findings

        actually_new = [s for s in new_subs if s not in scan.subdomains]
        scan.subdomains = dedup_lines(scan.subdomains + actually_new)
        scan.brute_subdomains = dedup_lines(scan.brute_subdomains + actually_new)

        if actually_new:
            write_lines(str(brute_dir / "new_subdomains.txt"), actually_new)
            await self.progress(f"Bruteforce discovered {len(actually_new)} new subdomains")
            findings.append(self.make_finding(
                title=f"DNS Bruteforce: {len(actually_new)} new subdomains discovered",
                description=f"Active DNS bruteforcing discovered {len(actually_new)} subdomains of {scan.domain} that were not found by passive enumeration. Total subdomains now: {len(scan.subdomains)} (was {before_count}).",
                severity=Severity.INFO,
                target=scan.domain,
                evidence="\n".join(actually_new[:30]),
            ))
        else:
            await self.progress("No new subdomains found via bruteforce")

        if scan.subdomains:
            await self.progress("Resolving all subdomains for validation...")
            resolved = await self._resolve_subdomains(scan, brute_dir, resolvers)
            if resolved:
                write_lines(str(brute_dir / "resolved.txt"), resolved)
                await self.progress(f"{len(resolved)} subdomains resolve to valid IPs")

        return findings

    async def _run_puredns(self, scan: Scan, out_dir: Path, wordlist: str, resolvers: str) -> list[str]:
        out_file = out_dir / "puredns_brute.txt"
        code, stdout, stderr = await run_tool(
            ["puredns", "bruteforce", wordlist, scan.domain,
             "-r", resolvers, "--wildcard-batch", "1000",
             "-q", "-w", str(out_file)],
            timeout=3600,
        )
        if out_file.exists():
            return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
        return [l.strip() for l in stdout.splitlines() if l.strip() and scan.domain in l]

    async def _run_shuffledns(self, scan: Scan, out_dir: Path, wordlist: str, resolvers: str) -> list[str]:
        out_file = out_dir / "shuffledns_brute.txt"
        code, stdout, stderr = await run_tool(
            ["shuffledns", "-d", scan.domain, "-w", wordlist,
             "-r", resolvers, "-silent", "-o", str(out_file)],
            timeout=3600,
        )
        if out_file.exists():
            return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
        return [l.strip() for l in stdout.splitlines() if l.strip()]

    async def _run_massdns(self, scan: Scan, out_dir: Path, wordlist: str, resolvers: str) -> list[str]:
        candidates_file = out_dir / "massdns_candidates.txt"
        with open(candidates_file, "w") as f:
            with open(wordlist) as wl:
                for line in wl:
                    word = line.strip()
                    if word:
                        f.write(f"{word}.{scan.domain}\n")

        out_file = out_dir / "massdns_output.txt"
        code, stdout, stderr = await run_tool(
            ["massdns", "-r", resolvers, str(candidates_file),
             "-t", "A", "-o", "S", "-w", str(out_file)],
            timeout=3600,
        )

        results = []
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "A":
                    domain = parts[0].rstrip(".")
                    if domain.endswith(scan.domain):
                        results.append(domain)
        return dedup_lines(results)

    async def _resolve_subdomains(self, scan: Scan, out_dir: Path, resolvers: str) -> list[str]:
        if not scan.subdomains:
            return []

        subs_file = out_dir / "all_subs.txt"
        write_lines(str(subs_file), scan.subdomains)

        if tool_exists("puredns"):
            out_file = out_dir / "resolved.txt"
            code, stdout, _ = await run_tool(
                ["puredns", "resolve", str(subs_file), "-r", resolvers, "-q", "-w", str(out_file)],
                timeout=600,
            )
            if out_file.exists():
                return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]

        return scan.subdomains
