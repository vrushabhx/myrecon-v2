import logging
import httpx
from myrecon.models import Scan

logger = logging.getLogger("myrecon")


async def send_notifications(scan: Scan):
    notifications = scan.config.get("notifications", {})

    slack_url = notifications.get("slack_webhook", "")
    if slack_url:
        await _send_slack(slack_url, scan)

    discord_url = notifications.get("discord_webhook", "")
    if discord_url:
        await _send_discord(discord_url, scan)

    tg_token = notifications.get("telegram_bot_token", "")
    tg_chat = notifications.get("telegram_chat_id", "")
    if tg_token and tg_chat:
        await _send_telegram(tg_token, tg_chat, scan)


def _build_summary(scan: Scan) -> str:
    by_sev = {}
    for f in scan.findings:
        by_sev.setdefault(f.severity.value, []).append(f)

    lines = [
        f"*Myrecon Scan Complete: {scan.domain}*",
        f"Status: {scan.status.value}",
        f"Total Findings: {len(scan.findings)}",
        f"Subdomains: {len(scan.subdomains)}",
        f"Live Hosts: {len(scan.live_hosts)}",
        "",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            lines.append(f"  {sev.upper()}: {len(by_sev[sev])}")
            for f in by_sev[sev][:5]:
                lines.append(f"    - {f.title}")

    return "\n".join(lines)


async def _send_slack(webhook_url: str, scan: Scan):
    try:
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json={"text": _build_summary(scan)}, timeout=10)
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")


async def _send_discord(webhook_url: str, scan: Scan):
    try:
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json={"content": _build_summary(scan)}, timeout=10)
    except Exception as e:
        logger.error(f"Discord notification failed: {e}")


async def _send_telegram(bot_token: str, chat_id: str, scan: Scan):
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        async with httpx.AsyncClient() as client:
            await client.post(url, json={
                "chat_id": chat_id,
                "text": _build_summary(scan),
                "parse_mode": "Markdown",
            }, timeout=10)
    except Exception as e:
        logger.error(f"Telegram notification failed: {e}")
