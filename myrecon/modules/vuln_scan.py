import json
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs

import httpx as httpx_client

from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines, read_lines, url_origin


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\etc\\passwd",
    "/etc/passwd",
    "....//....//....//....//windows/win.ini",
]
LFI_SIGNATURES = ["root:x:0:0:", "root:*:0:0:", "[fonts]", "[extensions]", "for 16-bit app support"]

SSTI_PROBES = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
]


class VulnScanModule(BaseModule):
    name = "vuln_scan"
    description = "Vulnerability scanning: Nuclei, CRLF, XSS, SQLi, SSRF, SSTI, LFI, Open Redirect"
    dependencies = ["url_collection"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        vuln_dir = Path(scan.scan_dir) / "vulns"
        vuln_dir.mkdir(parents=True, exist_ok=True)

        if tool_exists("nuclei"):
            await self.progress("Running nuclei vulnerability scanner...")
            f = await self._run_nuclei(scan, vuln_dir)
            findings.extend(f)
            await self.progress(f"nuclei found {len(f)} issues")
        else:
            await self.progress("nuclei not installed, skipping")

        if tool_exists("crlfuzz"):
            await self.progress("Running crlfuzz...")
            f = await self._run_crlfuzz(scan, vuln_dir)
            findings.extend(f)
            await self.progress(f"crlfuzz found {len(f)} issues")
        else:
            await self.progress("crlfuzz not installed, skipping")

        if tool_exists("kxss"):
            await self.progress("Running XSS reflection check...")
            f = await self._run_xss_check(scan, vuln_dir)
            findings.extend(f)
            await self.progress(f"XSS check found {len(f)} issues")
        else:
            await self.progress("kxss not installed, skipping XSS check")

        await self.progress("Running gf pattern matching...")
        gf_results = await self._run_gf_patterns(scan, vuln_dir)
        findings.extend(gf_results["findings"])
        if gf_results["findings"]:
            await self.progress(f"gf patterns found {len(gf_results['findings'])} potential targets")

        if tool_exists("sqlmap") and gf_results.get("sqli_urls"):
            await self.progress("Running sqlmap on SQLi candidates...")
            f = await self._run_sqlmap(scan, vuln_dir, gf_results["sqli_urls"])
            findings.extend(f)
            await self.progress(f"sqlmap found {len(f)} SQL injection(s)")

        redirect_urls = gf_results.get("redirect_urls", [])
        extra_redirects = [u for u in scan.urls if "=http" in u and u not in redirect_urls]
        all_redirect_urls = list(set(redirect_urls + extra_redirects))
        if all_redirect_urls:
            await self.progress("Testing open redirect candidates...")
            f = await self._run_open_redirect(scan, vuln_dir, all_redirect_urls)
            findings.extend(f)
            await self.progress(f"Open redirect check found {len(f)} issues")

        if gf_results.get("lfi_urls"):
            await self.progress("Testing LFI candidates...")
            f = await self._run_lfi_check(scan, vuln_dir, gf_results["lfi_urls"])
            findings.extend(f)
            await self.progress(f"LFI check found {len(f)} issues")

        if gf_results.get("ssti_urls"):
            await self.progress("Testing SSTI candidates...")
            f = await self._run_ssti_check(scan, vuln_dir, gf_results["ssti_urls"])
            findings.extend(f)
            await self.progress(f"SSTI check found {len(f)} issues")

        return findings

    async def _run_nuclei(self, scan: Scan, vuln_dir: Path) -> list[Finding]:
        findings = []
        if not scan.live_hosts:
            return findings

        input_file = vuln_dir / "nuclei_input.txt"
        write_lines(str(input_file), scan.live_hosts)

        severity = scan.config.get("tools", {}).get("nuclei_severity", "critical,high,medium,low")
        ua = scan.config.get("tools", {}).get("user_agent", "Mozilla/5.0")
        out = vuln_dir / "nuclei.jsonl"

        await run_tool(["nuclei", "-update-templates"], timeout=120)
        code, stdout, _ = await run_tool(
            ["nuclei", "-l", str(input_file), "-severity", severity,
             "-o", str(out), "-c", "50", "-jsonl",
             "-H", f"User-Agent: {ua}"],
            timeout=3600,
        )

        output = out.read_text() if out.exists() else ""
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev_str = info.get("severity", "info").lower()
                sev = SEVERITY_MAP.get(sev_str, Severity.INFO)
                template_id = data.get("template-id", "unknown")
                name = info.get("name", "Unknown")
                matched_at = data.get("matched-at", scan.domain)
                desc = info.get("description", "")
                matcher = data.get("matcher-name", "")
                tags = ", ".join(info.get("tags", [])[:5])

                description = desc or f"Nuclei template {template_id} matched"
                if matcher:
                    description += f" (matcher: {matcher})"
                if tags:
                    description += f". Tags: {tags}"

                findings.append(Finding(
                    module="vuln_scan",
                    title=f"Nuclei [{template_id}]: {name}",
                    description=description,
                    severity=sev,
                    target=matched_at,
                    evidence=f"Template: {template_id}\nMatched: {matched_at}\nSeverity: {sev_str}",
                    raw_output=line,
                ))
            except json.JSONDecodeError:
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

        code, stdout, _ = await run_tool(
            ["crlfuzz", "-l", str(input_file), "-s", "-o", str(out), "-c", "50"],
            timeout=600,
        )

        output = out.read_text() if out.exists() else stdout
        seen_origins = set()
        vuln_urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            origin = url_origin(line)
            if origin not in seen_origins:
                seen_origins.add(origin)
                vuln_urls.append(line)

        for url in vuln_urls[:50]:
            findings.append(Finding(
                module="vuln_scan",
                title=f"CRLF Injection: {url[:100]}",
                description=f"CRLF injection (HTTP header injection) detected. The server reflects injected CRLF characters in response headers, allowing an attacker to set arbitrary headers or split HTTP responses.",
                severity=Severity.MEDIUM,
                target=url,
                evidence=f"Vulnerable URL: {url}",
            ))

        if len(vuln_urls) > 50:
            write_lines(str(vuln_dir / "crlf_all.txt"), vuln_urls)

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
            urls_to_test = []
            for line in reflected:
                parts = line.split()
                for p in parts:
                    if p.startswith("http"):
                        urls_to_test.append(p)
                        break

            if urls_to_test:
                reflect_file = vuln_dir / "reflected_params.txt"
                write_lines(str(reflect_file), urls_to_test[:200])
                blind = scan.config.get("blind_xss", "")
                dalfox_out = vuln_dir / "dalfox.jsonl"
                cmd = ["dalfox", "file", str(reflect_file),
                       "-o", str(dalfox_out), "-w", "30",
                       "-format", "json"]
                if blind:
                    cmd.extend(["-blind", blind])
                code, stdout, _ = await run_tool(cmd, timeout=1800)

                output = dalfox_out.read_text() if dalfox_out.exists() else stdout
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        vtype = data.get("type", "")
                        if vtype in ("V", "verified", "POC", "poc"):
                            poc_url = data.get("data", data.get("poc", ""))
                            param = data.get("param", "")
                            inject_type = data.get("inject_type", data.get("cwe", ""))
                            sev = Severity.CRITICAL if vtype in ("V", "verified") else Severity.HIGH

                            findings.append(Finding(
                                module="vuln_scan",
                                title=f"XSS ({inject_type}): {param} parameter" if param else f"XSS: {poc_url[:80]}",
                                description=f"Cross-Site Scripting vulnerability confirmed by dalfox. Injection type: {inject_type}. Parameter: {param}.",
                                severity=sev,
                                target=poc_url[:200],
                                evidence=f"POC URL: {poc_url}\nParameter: {param}\nType: {inject_type}",
                                raw_output=line,
                            ))
                    except json.JSONDecodeError:
                        if "[V]" in line or "[POC]" in line:
                            findings.append(Finding(
                                module="vuln_scan",
                                title=f"XSS: {line.strip()[:100]}",
                                description=f"Cross-Site Scripting confirmed by dalfox.",
                                severity=Severity.HIGH,
                                target=scan.domain,
                                raw_output=line,
                            ))

        if reflected and not findings:
            (vuln_dir / "xss_reflections.txt").write_text("\n".join(reflected))
            findings.append(Finding(
                module="vuln_scan",
                title=f"XSS Reflections: {len(reflected)} parameters reflect input",
                description=f"Found {len(reflected)} parameters that reflect user input without sanitization. These should be manually tested for XSS.",
                severity=Severity.LOW,
                target=scan.domain,
                evidence="\n".join(reflected[:20]),
            ))

        return findings

    async def _run_gf_patterns(self, scan: Scan, vuln_dir: Path) -> dict:
        result = {"findings": [], "sqli_urls": [], "redirect_urls": [], "lfi_urls": [], "ssti_urls": []}
        parameterized = [u for u in scan.urls if "=" in u]
        if not parameterized or not tool_exists("gf"):
            return result

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
                result["findings"].append(Finding(
                    module="vuln_scan",
                    title=f"GF Pattern ({pattern}): {len(matches)} potential targets",
                    description=f"Found {len(matches)} URLs matching the '{pattern}' pattern. These endpoints have parameters commonly associated with {pattern.upper()} vulnerabilities and should be tested.",
                    severity=severity,
                    target=scan.domain,
                    evidence="\n".join(matches[:15]),
                ))
                if pattern == "sqli":
                    result["sqli_urls"] = matches
                elif pattern == "redirect":
                    result["redirect_urls"] = matches
                elif pattern == "lfi":
                    result["lfi_urls"] = matches
                elif pattern == "ssti":
                    result["ssti_urls"] = matches

        return result

    async def _run_sqlmap(self, scan: Scan, vuln_dir: Path, sqli_urls: list[str]) -> list[Finding]:
        findings = []
        max_urls = scan.config.get("tools", {}).get("max_sqlmap_urls", 100)
        urls = sqli_urls[:max_urls]
        if not urls:
            return findings

        sqli_input = vuln_dir / "sqlmap_input.txt"
        write_lines(str(sqli_input), urls)
        sqlmap_dir = vuln_dir / "sqlmap"
        sqlmap_dir.mkdir(exist_ok=True)

        code, stdout, stderr = await run_tool(
            ["sqlmap", "-m", str(sqli_input), "--batch", "--random-agent",
             "--level=1", "--risk=1", "--output-dir", str(sqlmap_dir),
             "--time-sec=5", "--text-only"],
            timeout=1800,
        )

        for target_dir in sqlmap_dir.iterdir():
            if not target_dir.is_dir():
                continue
            log_file = target_dir / "log"
            if not log_file.exists():
                continue
            log_content = log_file.read_text()
            if "is vulnerable" in log_content.lower() or "injectable" in log_content.lower():
                vuln_lines = [l for l in log_content.splitlines()
                              if "is vulnerable" in l.lower() or "injectable" in l.lower()
                              or "parameter" in l.lower() or "payload" in l.lower()]
                findings.append(Finding(
                    module="vuln_scan",
                    title=f"SQL Injection: {target_dir.name[:80]}",
                    description=f"SQLMap confirmed SQL injection vulnerability at {target_dir.name}. The parameter is injectable and allows database manipulation.",
                    severity=Severity.CRITICAL,
                    target=target_dir.name,
                    evidence="\n".join(vuln_lines[:20]),
                    raw_output=log_content[:2000],
                ))

        return findings

    async def _run_open_redirect(self, scan: Scan, vuln_dir: Path, redirect_urls: list[str]) -> list[Finding]:
        findings = []
        max_urls = scan.config.get("tools", {}).get("max_redirect_urls", 50)
        urls = redirect_urls[:max_urls]
        if not urls:
            return findings

        payloads_file = Path("/app/payloads/open_redirect.txt")
        if not payloads_file.exists():
            payloads_file = Path("/Users/doshiv/tools/myrecon-v2/payloads/open_redirect.txt")
        if not payloads_file.exists():
            return findings

        payloads = read_lines(str(payloads_file))[:20]
        if not payloads:
            return findings

        confirmed = []
        async with httpx_client.AsyncClient(follow_redirects=False, timeout=10, verify=False) as client:
            for url in urls[:30]:
                for payload in payloads[:5]:
                    try:
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query, keep_blank_values=True)
                        for key in params:
                            if "http" in str(params[key]).lower() or "url" in key.lower() or "redirect" in key.lower() or "return" in key.lower() or "next" in key.lower():
                                params[key] = [payload]
                        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                        resp = await client.get(test_url)
                        location = resp.headers.get("location", "")
                        if location and ("evil.com" in location or "google.com" in location or payload.replace("//", "") in location):
                            confirmed.append({"url": test_url, "location": location, "payload": payload})
                            break
                    except Exception:
                        continue

        seen = set()
        for item in confirmed:
            origin = url_origin(item["url"])
            if origin in seen:
                continue
            seen.add(origin)
            findings.append(Finding(
                module="vuln_scan",
                title=f"Open Redirect: {origin[:80]}",
                description=f"Open redirect confirmed. The application redirects to an attacker-controlled domain without validation, enabling phishing attacks.",
                severity=Severity.MEDIUM,
                target=item["url"][:200],
                evidence=f"URL: {item['url']}\nRedirects to: {item['location']}\nPayload: {item['payload']}",
            ))

        return findings

    async def _run_lfi_check(self, scan: Scan, vuln_dir: Path, lfi_urls: list[str]) -> list[Finding]:
        findings = []
        max_urls = scan.config.get("tools", {}).get("max_lfi_urls", 50)
        urls = lfi_urls[:max_urls]
        if not urls:
            return findings

        confirmed = []
        async with httpx_client.AsyncClient(follow_redirects=True, timeout=10, verify=False) as client:
            for url in urls:
                for payload in LFI_PAYLOADS:
                    try:
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query, keep_blank_values=True)
                        for key in params:
                            params[key] = [payload]
                        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                        resp = await client.get(test_url)
                        body = resp.text
                        for sig in LFI_SIGNATURES:
                            if sig in body:
                                confirmed.append({"url": test_url, "payload": payload, "signature": sig})
                                break
                        if confirmed and confirmed[-1]["url"] == test_url:
                            break
                    except Exception:
                        continue

        seen = set()
        for item in confirmed:
            origin = url_origin(item["url"])
            if origin in seen:
                continue
            seen.add(origin)
            findings.append(Finding(
                module="vuln_scan",
                title=f"Local File Inclusion: {origin[:80]}",
                description=f"LFI vulnerability confirmed. The application includes local files based on user input, allowing an attacker to read sensitive server files like /etc/passwd.",
                severity=Severity.HIGH,
                target=item["url"][:200],
                evidence=f"URL: {item['url']}\nPayload: {item['payload']}\nSignature found: {item['signature']}",
            ))

        write_lines(str(vuln_dir / "lfi_confirmed.txt"), [c["url"] for c in confirmed])
        return findings

    async def _run_ssti_check(self, scan: Scan, vuln_dir: Path, ssti_urls: list[str]) -> list[Finding]:
        findings = []
        max_urls = scan.config.get("tools", {}).get("max_ssti_urls", 50)
        urls = ssti_urls[:max_urls]
        if not urls:
            return findings

        confirmed = []
        async with httpx_client.AsyncClient(follow_redirects=True, timeout=10, verify=False) as client:
            for url in urls:
                for probe, expected in SSTI_PROBES:
                    try:
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query, keep_blank_values=True)
                        for key in params:
                            params[key] = [probe]
                        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                        resp = await client.get(test_url)
                        if expected in resp.text and probe not in resp.text:
                            confirmed.append({"url": test_url, "probe": probe, "expected": expected})
                            break
                    except Exception:
                        continue

        seen = set()
        for item in confirmed:
            origin = url_origin(item["url"])
            if origin in seen:
                continue
            seen.add(origin)
            findings.append(Finding(
                module="vuln_scan",
                title=f"Server-Side Template Injection: {origin[:80]}",
                description=f"SSTI vulnerability confirmed. The server evaluates template expressions in user input, potentially allowing remote code execution. Probe: {item['probe']} returned: {item['expected']}.",
                severity=Severity.HIGH,
                target=item["url"][:200],
                evidence=f"URL: {item['url']}\nProbe: {item['probe']}\nExpected output: {item['expected']}",
            ))

        write_lines(str(vuln_dir / "ssti_confirmed.txt"), [c["url"] for c in confirmed])
        return findings
