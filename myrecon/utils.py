import asyncio
import logging
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("myrecon")

STATIC_EXT = re.compile(
    r"\.(jpg|jpeg|png|svg|gif|ico|ttf|css|woff|woff2|eot|mp[34]|pdf|exe|zip|gz|tar|bz2|rar|7z|webp|avif)$",
    re.I,
)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


async def run_tool(
    cmd: list[str],
    cwd: str = None,
    timeout: int = 3600,
    input_data: str = None,
) -> tuple[int, str, str]:
    logger.info(f"Running: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data.encode() if input_data else None),
            timeout=timeout,
        )
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        logger.warning(f"Tool timed out after {timeout}s: {' '.join(cmd)}")
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        logger.error(f"Tool not found: {cmd[0]}")
        return -1, "", f"Tool not found: {cmd[0]}"


def dedup_lines(lines: list[str]) -> list[str]:
    seen = set()
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            result.append(stripped)
    return result


def read_lines(filepath: str) -> list[str]:
    p = Path(filepath)
    if not p.exists():
        return []
    return dedup_lines(p.read_text().splitlines())


def write_lines(filepath: str, lines: list[str]):
    Path(filepath).write_text("\n".join(lines) + "\n")


def merge_files(output: str, *inputs: str) -> list[str]:
    all_lines = []
    for f in inputs:
        all_lines.extend(read_lines(f))
    result = dedup_lines(all_lines)
    write_lines(output, result)
    return result


def filter_static_urls(urls: list[str]) -> list[str]:
    return [u for u in urls if not STATIC_EXT.search(u)]


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def url_origin(url: str) -> str:
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return url
