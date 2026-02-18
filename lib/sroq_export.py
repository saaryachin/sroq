"""
Sroq Export Module

Flat-table CSV export from scan results. One row per host per network.
"""

import csv
from pathlib import Path


# Column headers in export order
_HEADERS = [
    "timestamp",
    "network_name",
    "network_cidr",
    "host_ip",
    "open_ports_count",
    "open_ports",
    "unique_cve_count",
    "max_cvss",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "unknown_count",
    "risk_score",
    "risk_cvss_sum",
    "top_cves",
]


def generate_csv(results: dict, output_dir: str) -> str:
    """
    Write a flat CSV summary from scan results.

    One row per host per network. Returns the output path, or "" if there
    are no hosts across all networks (file is not created in that case).

    Args:
        results: Scan results dict (same structure saved as JSON)
        output_dir: Directory to write the CSV file into

    Returns:
        str: Absolute/relative path to the written CSV, or "" if skipped
    """
    rows = []
    timestamp = results.get("timestamp", "")

    for network in results.get("networks", []):
        net_name = network.get("name", "")
        net_cidr = network.get("cidr", "")

        for host in network.get("hosts", []):
            ip = host.get("ip", "")

            open_ports = host.get("open_ports", [])
            open_ports_count = len(open_ports)
            open_ports_str = ";".join(str(p) for p in open_ports)

            vulners = host.get("vulners", {})
            severity = vulners.get("severity", {})
            cves = vulners.get("cves", [])  # already sorted: cvss desc, id asc

            # Top 5 CVEs: list is pre-sorted, take first 5
            top_cves_str = ";".join(
                f"{c['id']}({c['cvss']})" for c in cves[:5]
            )

            rows.append({
                "timestamp":       timestamp,
                "network_name":    net_name,
                "network_cidr":    net_cidr,
                "host_ip":         ip,
                "open_ports_count": open_ports_count,
                "open_ports":      open_ports_str,
                "unique_cve_count": vulners.get("unique_cve_count", 0),
                "max_cvss":        vulners.get("max_cvss", 0.0),
                "critical_count":  severity.get("critical", 0),
                "high_count":      severity.get("high", 0),
                "medium_count":    severity.get("medium", 0),
                "low_count":       severity.get("low", 0),
                "unknown_count":   severity.get("unknown", 0),
                "risk_score":      host.get("risk_score", 0),
                "risk_cvss_sum":   host.get("risk_cvss_sum", 0.0),
                "top_cves":        top_cves_str,
            })

    if not rows:
        return ""

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    filepath = out_path / f"sroq_{timestamp}.csv"

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    return str(filepath)
