"""
Sroq Report Generation Module

Provides graph and report generation from scan results.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def generate_severity_graph(results: dict, output_dir: str) -> str:
    """
    Generate a stacked bar chart of host vulnerability severity distribution.

    One bar per host, stacked by severity level (low, medium, high, critical, unknown).

    Args:
        results: Scan results dict containing networks and hosts
        output_dir: Directory to save PNG file

    Returns:
        Full path to saved PNG file (empty string if no hosts)
    """
    # Collect data across all networks
    all_hosts = []
    all_lows = []
    all_mediums = []
    all_highs = []
    all_criticals = []
    all_unknowns = []

    for network in results.get('networks', []):
        for host in network.get('hosts', []):
            all_hosts.append(host['ip'])
            severity = host['vulners']['severity']
            all_lows.append(severity.get('low', 0))
            all_mediums.append(severity.get('medium', 0))
            all_highs.append(severity.get('high', 0))
            all_criticals.append(severity.get('critical', 0))
            all_unknowns.append(severity.get('unknown', 0))

    if not all_hosts:
        # No hosts scanned, return empty path
        return ""

    # Dynamic figure width based on host count
    fig_width = max(8, len(all_hosts) * 0.6)

    fig, ax = plt.subplots(figsize=(fig_width, 6))

    x_pos = range(len(all_hosts))
    bar_width = 0.6

    # Stack bars from bottom to top: low, medium, high, critical, unknown
    ax.bar(x_pos, all_lows, bar_width, label='Low', color='green')
    ax.bar(x_pos, all_mediums, bar_width, bottom=all_lows, label='Medium', color='yellow')

    bottoms_high = [all_lows[i] + all_mediums[i] for i in range(len(all_lows))]
    ax.bar(x_pos, all_highs, bar_width, bottom=bottoms_high, label='High', color='orange')

    bottoms_critical = [bottoms_high[i] + all_highs[i] for i in range(len(bottoms_high))]
    ax.bar(x_pos, all_criticals, bar_width, bottom=bottoms_critical, label='Critical', color='red')

    bottoms_unknown = [bottoms_critical[i] + all_criticals[i] for i in range(len(bottoms_critical))]
    ax.bar(x_pos, all_unknowns, bar_width, bottom=bottoms_unknown, label='Unknown', color='gray')

    # Labels and formatting
    ax.set_xlabel('Host IP')
    ax.set_ylabel('CVE Count')
    ax.set_title('Sroq Host Vulnerability Severity Distribution')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(all_hosts, rotation=45, ha='right')
    ax.legend()

    # Save figure
    timestamp = results['timestamp']
    filename = f"sroq_{timestamp}.png"
    filepath = f"{output_dir}/{filename}"

    plt.tight_layout()
    plt.savefig(filepath, dpi=100)
    plt.close()

    return filepath
