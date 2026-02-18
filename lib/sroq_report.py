"""
Sroq Report Generation Module

Provides graph and report generation from scan results.
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def generate_severity_graph(results: dict, output_dir: str) -> str:
    """
    Generate a stacked bar chart of host vulnerability severity distribution.

    Hosts are sorted by descending risk_score. Each bar is annotated with
    unique CVE count and risk score. Scales automatically for large host counts.

    Args:
        results: Scan results dict containing networks and hosts
        output_dir: Directory to save PNG file

    Returns:
        Full path to saved PNG file (empty string if no hosts)
    """
    # Collect flat host list across all networks
    host_entries = []
    for network in results.get('networks', []):
        for host in network.get('hosts', []):
            host_entries.append({
                'ip': host['ip'],
                'severity': host['vulners']['severity'],
                'unique_cve_count': host['vulners']['unique_cve_count'],
                'risk_score': host.get('risk_score', 0),
            })

    if not host_entries:
        return ""

    # Sort by descending risk_score for visual priority
    host_entries.sort(key=lambda h: -h['risk_score'])

    n = len(host_entries)
    all_ips     = [h['ip'] for h in host_entries]
    all_lows    = [h['severity'].get('low', 0)      for h in host_entries]
    all_mediums = [h['severity'].get('medium', 0)   for h in host_entries]
    all_highs   = [h['severity'].get('high', 0)     for h in host_entries]
    all_crits   = [h['severity'].get('critical', 0) for h in host_entries]
    all_unkns   = [h['severity'].get('unknown', 0)  for h in host_entries]

    # Dynamic sizing: wider + smaller font + steeper rotation for large counts
    if n > 20:
        fig_width  = max(12, n * 0.5)
        font_size  = 7
        rotation   = 70
        ann_size   = 6
    else:
        fig_width  = max(8, n * 0.6)
        font_size  = 9
        rotation   = 45
        ann_size   = 8

    fig, ax = plt.subplots(figsize=(fig_width, 6))
    x_pos     = range(n)
    bar_width = 0.6

    # Stack bars bottom to top: low → medium → high → critical → unknown
    ax.bar(x_pos, all_lows,    bar_width, label='Low',      color='green')
    ax.bar(x_pos, all_mediums, bar_width, label='Medium',   color='yellow',
           bottom=all_lows)

    bot_high = [all_lows[i] + all_mediums[i] for i in range(n)]
    ax.bar(x_pos, all_highs, bar_width, label='High', color='orange',
           bottom=bot_high)

    bot_crit = [bot_high[i] + all_highs[i] for i in range(n)]
    ax.bar(x_pos, all_crits, bar_width, label='Critical', color='red',
           bottom=bot_crit)

    bot_unkn = [bot_crit[i] + all_crits[i] for i in range(n)]
    ax.bar(x_pos, all_unkns, bar_width, label='Unknown', color='gray',
           bottom=bot_unkn)

    # Annotate each bar: "N CVEs | risk R" above the top of the bar
    for i, h in enumerate(host_entries):
        bar_top = (bot_unkn[i] + all_unkns[i])
        label = f"{h['unique_cve_count']} | risk {h['risk_score']}"
        ax.text(i, bar_top + 0.3, label,
                ha='center', va='bottom', fontsize=ann_size)

    ax.set_xlabel('Host IP')
    ax.set_ylabel('CVE Count')
    ax.set_title('Sroq Host Vulnerability Severity Distribution')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(all_ips, rotation=rotation, ha='right', fontsize=font_size)
    ax.legend()

    # Build output path with pathlib (normalises ./out → out)
    timestamp = results['timestamp']
    filepath = Path(output_dir) / f"sroq_{timestamp}.png"

    plt.tight_layout()
    plt.savefig(filepath, dpi=100)
    plt.close()

    return str(filepath)
