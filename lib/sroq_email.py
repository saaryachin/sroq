"""
Sroq Email Reporting Module

Sends scan summary and attachments via SMTP.
"""

import os
from pathlib import Path
from email.message import EmailMessage
from smtplib import SMTP_SSL
import logging


def _get_env(var: str) -> str:
    """Get environment variable, raise error if not found."""
    value = os.getenv(var)
    if not value:
        raise ValueError(f"Environment variable {var} is not set")
    return value


def send_report(results: dict, output_dir: str, attachments: dict = None) -> bool:
    """
    Send scan summary and attachments via email.

    Environment variables required:
    - SMTP_HOST: SMTP server hostname
    - SMTP_PORT: SMTP port (typically 465 for SSL)
    - SMTP_USER: SMTP username (usually email)
    - SMTP_PASS: SMTP password
    - SROQ_EMAIL_TO: Recipient email address
    - SROQ_EMAIL_FROM (optional): Sender email (defaults to SMTP_USER)

    Args:
        results: Scan results dict
        output_dir: Output directory (for finding attachments)
        attachments: dict of {filename: full_path} to attach (e.g., CSV, XLSX, PNG)

    Returns:
        bool: True if sent successfully, False otherwise.
    """
    logger = logging.getLogger("sroq")

    # Get SMTP config from environment
    try:
        smtp_host = _get_env("SMTP_HOST")
        smtp_port = int(_get_env("SMTP_PORT"))
        smtp_user = _get_env("SMTP_USER")
        smtp_pass = _get_env("SMTP_PASS")
        email_to = _get_env("SROQ_EMAIL_TO")
        email_from = os.getenv("SROQ_EMAIL_FROM", smtp_user)
    except ValueError as e:
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
