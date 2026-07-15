from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class VulnScanModule(BaseModule):
    name = "vuln_scan"
    description = "Vulnerability scanning: Nuclei, CRLF, XSS, SQLi, SSRF, SSTI"
    dependencies = ["url_collection"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        vuln_dir = Path(scan.scan_dir) / "vulns"
        vuln_dir.mkdir(parents=True, exist_ok=True)

        if tool_exists("nuclei"):
            f = await self._run_nuclei(scan, vuln_dir)
            findings.extend(f)

        if tool_exists("crlfuzz"):
            f = await self._run_crlfuzz(scan, vuln_dir)
            findings.extend(f)

        if tool_exists("kxss"):
            f = await self._run_xss_check(scan, vuln_dir)
            findings.extend(f)

        f = await self._run_gf_patterns(scan, vuln_dir)
        findings.extend(f)

        return findings

    async def _run_nuclei(self, scan: Scan, vuln_dir: Path) -> list[Finding]:
        findings = []
        if not scan.live_hosts:
            return findings

        input_file = vuln_dir / "nuclei_input.txt"
        write_lines(str(input_file), scan.live_hosts)

        severity = scan.config.get("tools", {}).get("nuclei_severity", "critical,high,medium,low")
        ua = scan.config.get("tools", {}).get("user_agent", "Mozilla/5.0")
        out = vuln_dir / "nuclei.txt"

        await run_tool(["nuclei", "-update-templates"], timeout=120)
        code, stdout, _ = await run_tool(
            ["nuclei", "-l", str(input_file), "-severity", severity,
             "-o", str(out), "-c", "50", "-stats",
             "-H", f"User-Agent: {ua}", "-silent"],
            timeout=3600,
        )

        output = out.read_text() if out.exists() else stdout
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            sev = Severity.INFO
            for key, val in SEVERITY_MAP.items():
                if f"[{key}]" in line.lower():
                    sev = val
                    break
            findings.append(Finding(
                module="vuln_scan",
                title=f"Nuclei: {line[:120]}",
                description=line,
                severity=sev,
                target=scan.domain,
                raw_output=line,
            ))

        return findings

    async def _run_crlfuzz(self, scan: Scan, vuln_dir: Path) -> list[Finding]:
        findings = []
        if not scan.live_hosts:
            return findings

        input_file = vuln_dir / "crlf_input.txt"
        write_lines(str(input_file), scan.live_hosts)
        out = vuln_dir / "crlf.txt"

        input_data = "\n".join(scan.live_hosts)
        code, stdout, _ = await run_tool(
            ["crlfuzz", "-l", str(input_file), "-s", "-o", str(out), "-c", "50"],
            timeout=600,
        )

        output = out.read_text() if out.exists() else stdout
        for line in output.strip().splitlines():
            if line.strip():
                findings.append(Finding(
                    module="vuln_scan",
                    title=f"CRLF Injection: {line.strip()[:100]}",
                    description=f"CRLF injection detected at {line.strip()}",
                    severity=Severity.MEDIUM,
                    target=line.strip(),
                ))

        return findings

    async def _run_xss_check(self, scan: Scan, vuln_dir: Path) -> list[Finding]:
        findings = []
        parameterized = [u for u in scan.urls if "=" in u]
        if not parameterized:
            return findings

        input_data = "\n".join(parameterized[:500])
        code, stdout, _ = await run_tool(
            ["kxss"],
            input_data=input_data,
            timeout=600,
        )

        reflected = []
        for line in stdout.splitlines():
            if line.strip():
                reflected.append(line.strip())

        if reflected and tool_exists("dalfox"):
            reflect_file = vuln_dir / "reflected_params.txt"
            urls_to_test = []
            for line in reflected:
                parts = line.split()
                for p in parts:
                    if p.startswith("http"):
                        urls_to_test.append(p)
                        break

            if urls_to_test:
                write_lines(str(reflect_file), urls_to_test[:200])
                blind = scan.config.get("blind_xss", "")
                cmd = ["dalfox", "file", str(reflect_file), "-o", str(vuln_dir / "dalfox.txt"), "-w", "30"]
                if blind:
                    cmd.extend(["-blind", blind])
                code, stdout, _ = await run_tool(cmd, timeout=1800)

                dalfox_out = vuln_dir / "dalfox.txt"
                output = dalfox_out.read_text() if dalfox_out.exists() else stdout
                for line in output.splitlines():
                    if "[V]" in line or "[POC]" in line:
                        findings.append(Finding(
                            module="vuln_scan",
                            title=f"XSS: {line.strip()[:100]}",
                            description=line.strip(),
                            severity=Severity.HIGH,
                            target=scan.domain,
                            raw_output=line,
                        ))

        if reflected and not findings:
            (vuln_dir / "xss_reflections.txt").write_text("\n".join(reflected))
            findings.append(Finding(
                module="vuln_scan",
                title=f"XSS Reflections: {len(reflected)} parameters reflect input",
                description="Parameters that reflect user input were found. Manual testing recommended.",
                severity=Severity.LOW,
                target=scan.domain,
                evidence="\n".join(reflected[:20]),
            ))

        return findings

    async def _run_gf_patterns(self, scan: Scan, vuln_dir: Path) -> list[Finding]:
        findings = []
        parameterized = [u for u in scan.urls if "=" in u]
        if not parameterized or not tool_exists("gf"):
            return findings

        input_data = "\n".join(parameterized)
        patterns = {
            "ssrf": Severity.HIGH,
            "sqli": Severity.HIGH,
            "ssti": Severity.MEDIUM,
            "lfi": Severity.HIGH,
            "rce": Severity.CRITICAL,
            "idor": Severity.MEDIUM,
            "redirect": Severity.LOW,
        }

        for pattern, severity in patterns.items():
            code, stdout, _ = await run_tool(
                ["gf", pattern],
                input_data=input_data,
                timeout=60,
            )
            matches = [l.strip() for l in stdout.splitlines() if l.strip()]
            if matches:
                out_file = vuln_dir / f"gf_{pattern}.txt"
                write_lines(str(out_file), matches)
                findings.append(Finding(
                    module="vuln_scan",
                    title=f"GF Pattern ({pattern}): {len(matches)} potential targets",
                    description=f"Found {len(matches)} URLs matching the '{pattern}' pattern for manual testing",
                    severity=severity,
                    target=scan.domain,
                    evidence="\n".join(matches[:15]),
                ))

        return findings
