"""
Sroq Email Reporting Module

Sends scan summary and attachments via SMTP.
"""

import os
from pathlib import Path
from email.message import EmailMessage
from smtplib import SMTP_SSL
import logging


def send_report(results: dict, output_dir: str, attachments: dict = None, email_cfg: dict = None) -> bool:
    """
    Send scan summary and attachments via email.

    Supports email config from YAML with environment variable overrides.

    YAML config keys (email_cfg):
    - smtp_host: SMTP server hostname
    - smtp_port: SMTP port (typically 465 for SSL)
    - smtp_user: SMTP username (usually email)
    - smtp_pass: SMTP password
    - to: Recipient email address
    - from (optional): Sender email (defaults to smtp_user)

    Environment variables (override YAML):
    - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SROQ_EMAIL_TO, SROQ_EMAIL_FROM

    Args:
        results: Scan results dict
        output_dir: Output directory (for finding attachments)
        attachments: dict of {filename: full_path} to attach (e.g., CSV, XLSX, PNG)
        email_cfg: Optional dict with email config from YAML

    Returns:
        bool: True if sent successfully, False otherwise.
    """
    logger = logging.getLogger("sroq")

    if email_cfg is None:
        email_cfg = {}

    # Resolve SMTP config: YAML first, then env var fallback
    smtp_host = email_cfg.get("smtp_host") or os.getenv("SMTP_HOST")
    smtp_port_str = str(email_cfg.get("smtp_port") or "") or os.getenv("SMTP_PORT", "")
    smtp_user = email_cfg.get("smtp_user") or os.getenv("SMTP_USER")
    smtp_pass = email_cfg.get("smtp_pass") or os.getenv("SMTP_PASS")
    email_to = email_cfg.get("to") or os.getenv("SROQ_EMAIL_TO")
    email_from = email_cfg.get("from") or os.getenv("SROQ_EMAIL_FROM") or smtp_user

    # Validate required fields
    try:
        if not smtp_host:
            raise ValueError("SMTP_HOST not configured")
        if not smtp_port_str:
            raise ValueError("SMTP_PORT not configured")
        smtp_port = int(smtp_port_str)
        if not smtp_user:
            raise ValueError("SMTP_USER not configured")
        if not smtp_pass:
            raise ValueError("SMTP_PASS not configured")
        if not email_to:
            raise ValueError("SROQ_EMAIL_TO not configured")
    except (ValueError, TypeError) as e:
        logger.error(f"Email config error: {e}")
        return False

    # Build message body
    timestamp = results.get("timestamp", "unknown")
    body_lines = [
        f"Sroq Scan Report - {timestamp}",
        "=" * 60,
        "",
    ]

    # Network summary
    total_hosts = sum(len(net.get("hosts", [])) for net in results.get("networks", []))
    total_cves = sum(
        host["vulners"]["unique_cve_count"]
        for net in results.get("networks", [])
        for host in net.get("hosts", [])
    )

    body_lines.append(f"Total Networks: {len(results.get('networks', []))}")
    body_lines.append(f"Total Hosts: {total_hosts}")
    body_lines.append(f"Total Unique CVEs: {total_cves}")
    body_lines.append("")

    # Top 5 riskiest hosts globally
    all_hosts = [
        (host, net["name"], net["cidr"])
        for net in results.get("networks", [])
        for host in net.get("hosts", [])
    ]
    all_hosts.sort(key=lambda x: -x[0].get("risk_score", 0))

    if all_hosts:
        body_lines.append("Top 5 Riskiest Hosts:")
        body_lines.append("-" * 60)
        for host, net_name, net_cidr in all_hosts[:5]:
            ip = host.get("ip", "?")
            risk = host.get("risk_score", 0)
            cves = host["vulners"]["unique_cve_count"]
            cvss = host["vulners"]["max_cvss"]
            body_lines.append(
                f"  {ip} (net: {net_name}) - risk:{risk} CVEs:{cves} max_cvss:{cvss}"
            )
        body_lines.append("")

    body = "\n".join(body_lines)

    # Create message
    msg = EmailMessage()
    msg["Subject"] = f"Sroq Report - {timestamp}"
    msg["From"] = email_from
    msg["To"] = email_to
    msg.set_content(body)

    # Attach files if provided
    if attachments:
        for filename, filepath in attachments.items():
            if filepath and Path(filepath).exists():
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    # Determine MIME type by extension
                    if filename.endswith(".csv"):
                        maintype, subtype = "text", "csv"
                    elif filename.endswith(".xlsx"):
                        maintype, subtype = "application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    elif filename.endswith(".png"):
                        maintype, subtype = "image", "png"
                    elif filename.endswith(".json"):
                        maintype, subtype = "application", "json"
                    else:
                        maintype, subtype = "application", "octet-stream"

                    msg.add_attachment(
                        data, maintype=maintype, subtype=subtype, filename=filename
                    )
                except Exception as e:
                    logger.warning(f"Failed to attach {filename}: {e}")

    # Send via SMTP
    try:
        with SMTP_SSL(smtp_host, smtp_port) as smtp:
            smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
        logger.info(f"Email sent to {email_to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False
