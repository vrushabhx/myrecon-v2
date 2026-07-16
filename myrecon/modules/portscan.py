from pathlib import Path
from myrecon.modules.base import BaseModule, logger
from myrecon.models import Scan, Finding, Severity
from myrecon.utils import run_tool, tool_exists, write_lines


class PortscanModule(BaseModule):
    name = "portscan"
    description = "Full port scan with service detection"
    dependencies = ["probing"]

    async def run(self, scan: Scan) -> list[Finding]:
        findings = []
        port_dir = Path(scan.scan_dir) / "portscan"
        port_dir.mkdir(parents=True, exist_ok=True)

        hosts = [h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                 for h in scan.live_hosts]
        hosts = list(set(hosts))
        if not hosts:
            await self.progress("No hosts for port scanning")
            return findings

        input_file = port_dir / "hosts.txt"
        write_lines(str(input_file), hosts)

        if tool_exists("naabu"):
            await self.progress(f"Running naabu on {len(hosts)} hosts...")
            naabu_results = await self._run_naabu(input_file, port_dir)
            scan.open_ports = naabu_results
            total_open = sum(len(p) for p in naabu_results.values())
            await self.progress(f"naabu found {total_open} open ports across {len(naabu_results)} hosts")

            all_targets = []
            all_ports = set()
            for host, ports in naabu_results.items():
                all_targets.append(host)
                all_ports.update(ports)

            if all_targets and all_ports and tool_exists("nmap"):
                await self.progress(f"Running nmap service detection on {len(all_ports)} ports...")
                await self._run_nmap(all_targets, all_ports, port_dir)
                await self.progress("nmap service detection complete")

            total_open = sum(len(p) for p in naabu_results.values())
            findings.append(self.make_finding(
                title=f"Port Scan: {total_open} open ports across {len(naabu_results)} hosts",
                description=f"Scanned {len(hosts)} hosts, found {total_open} open ports",
                severity=Severity.INFO,
                target=scan.domain,
                evidence="\n".join(f"{h}: {','.join(map(str,p))}" for h, p in list(naabu_results.items())[:20]),
            ))
        else:
            await self.progress("naabu not installed, skipping port scan")

        return findings

    async def _run_naabu(self, input_file: Path, out_dir: Path) -> dict[str, list[int]]:
        out = out_dir / "naabu.txt"
        code, stdout, _ = await run_tool(
            ["naabu", "-iL", str(input_file), "-rate", "1000", "-p", "-",
             "-silent", "-o", str(out)],
            timeout=1200,
        )
        results = {}
        output = out.read_text() if out.exists() else stdout
        for line in output.strip().splitlines():
            line = line.strip()
            if ":" in line:
                host, port = line.rsplit(":", 1)
                try:
                    results.setdefault(host, []).append(int(port))
                except ValueError:
                    pass
        return results

    async def _run_nmap(self, targets: list[str], ports: set[int], out_dir: Path):
        target_file = out_dir / "nmap_targets.txt"
        write_lines(str(target_file), targets)
        port_str = ",".join(str(p) for p in sorted(ports))
        await run_tool(
            ["nmap", "-iL", str(target_file), "-p", port_str, "-sV", "-T3",
             "-oA", str(out_dir / "nmap_scan")],
            timeout=1800,
        )
