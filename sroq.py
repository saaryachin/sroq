#!/usr/bin/env python3

import argparse
import sys
import json
from pathlib import Path
from typing import Optional, Dict, List, Set, Any, Tuple
from datetime import datetime
import ipaddress

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install it with: pip install PyYAML", file=sys.stderr)
    sys.exit(1)

from lib.sroq_scan import run_scan
from lib.sroq_report import generate_severity_graph
from lib.sroq_export import generate_csv
from lib.sroq_excel import generate_excel


def load_config(config_file: str) -> Dict[str, Any]:
    """Load YAML configuration file."""
    path = Path(config_file)
    if not path.exists():
        print(f"Error: Config file not found: {config_file}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, 'r') as f:
            content = yaml.safe_load(f)
            return content if content is not None else {}
    except Exception as e:
        print(f"Error loading config file {config_file}: {e}", file=sys.stderr)
        sys.exit(1)


def normalize_target(target: str) -> str:
    """
    Normalize target to include CIDR notation.
    If IP address without CIDR, add /32.
    """
    target = target.strip()
    try:
        # Try to parse as IP network (with CIDR)
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        try:
            # Try to parse as IP address (no CIDR)
            ipaddress.ip_address(target)
            return f"{target}/32"
        except ValueError:
            # Not a valid IP or CIDR, return as-is
            return target


def parse_excludes(exclude_args: Optional[List[str]]) -> Set[str]:
    """
    Parse exclude arguments.
    Supports both repeatable flags and comma-separated values.
    Returns a set of normalized exclude IPs.
    """
    excludes = set()
    if not exclude_args:
        return excludes

    for exclude_arg in exclude_args:
        # Split by comma to support comma-separated values
        for exclude in exclude_arg.split(','):
            exclude = exclude.strip()
            if exclude:
                # Normalize each exclude
                normalized = normalize_target(exclude)
                excludes.add(normalized)

    return excludes


def merge_configs(cli_args: argparse.Namespace, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge CLI arguments with config file settings.
    CLI arguments override config settings where applicable.
    Excludes from both sources are merged.
    Network segmentation (name + cidr) is preserved.
    """
    resolved = {
        'networks': [],
        'excludes': set(),
        'brute': False,
        'graph': False,
        'csv': False,
        'email': False,
        'excel': False,
        'verbose': False,
        'config_file': cli_args.config_file,
    }

    # Load networks from config targets.networks
    if 'targets' in config and 'networks' in config['targets']:
        networks = config['targets']['networks']
        if isinstance(networks, list):
            for network in networks:
                if isinstance(network, dict) and 'cidr' in network:
                    # Preserve network structure with name and cidr
                    resolved['networks'].append({
                        'name': network.get('name', 'unnamed'),
                        'cidr': normalize_target(network['cidr'])
                    })

    # Load excludes from config targets.exclude
    if 'targets' in config and 'exclude' in config['targets']:
        excludes = config['targets']['exclude']
        if isinstance(excludes, list):
            resolved['excludes'].update(parse_excludes(excludes))

    # Load behavior defaults from report section
    if 'report' in config:
        report = config['report']
        resolved['graph'] = report.get('graph_default', False)
        resolved['csv'] = report.get('csv_default', False)
        resolved['email'] = report.get('email_default', False)
        resolved['excel'] = report.get('excel_default', False)

    # brute defaults to False (no config default)
    resolved['brute'] = False

    # Override with CLI target (replaces all networks from config)
    if cli_args.target:
        resolved['networks'] = [{
            'name': 'cli',
            'cidr': normalize_target(cli_args.target)
        }]

    # Merge CLI excludes with config excludes
    if cli_args.exclude:
        resolved['excludes'].update(parse_excludes(cli_args.exclude))

    # Override with CLI behavior flags (enables features)
    if cli_args.brute:
        resolved['brute'] = True

    if cli_args.graph:
        resolved['graph'] = True

    if cli_args.csv:
        resolved['csv'] = True

    if cli_args.excel:
        resolved['excel'] = True

    if cli_args.email:
        resolved['email'] = True

    if cli_args.verbose:
        resolved['verbose'] = True

    # Validate that at least one network is configured
    if not resolved['networks']:
        print("Error: No target networks configured. Use --target or configure networks in config file.", file=sys.stderr)
        sys.exit(1)

    return resolved


def validate_config(resolved: Dict[str, Any], config: Dict[str, Any], cli_target: Optional[str], verbose: bool) -> Tuple[bool, str]:
    """
    Validate resolved configuration.

    Returns:
        (is_valid, error_message)
    """
    # Check networks
    if not cli_target:  # If --target not provided, networks from config must exist
        if not resolved['networks']:
            return False, "Invalid config: networks must be non-empty"

        for i, net in enumerate(resolved['networks']):
            if 'name' not in net or not isinstance(net['name'], str) or not net['name']:
                return False, f"Invalid config: network {i} missing or empty 'name'"
            if 'cidr' not in net or not isinstance(net['cidr'], str):
                return False, f"Invalid config: network {i} missing 'cidr'"
            try:
                ipaddress.ip_network(net['cidr'], strict=False)
            except ValueError:
                return False, f"Invalid config: network {i} has invalid CIDR: {net['cidr']}"

    # Check excludes
    if resolved['excludes']:
        for exclude in resolved['excludes']:
            # Already normalized, should be valid
            try:
                ipaddress.ip_network(exclude, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(exclude.split('/')[0])
                except ValueError:
                    return False, f"Invalid config: exclude '{exclude}' is not valid IP or CIDR"

    # Check ports policy
    ports_policy_str = config.get('scan', {}).get('ports', 'top-1000')
    if ports_policy_str not in ['top-1000', 'top-100', 'all']:
        # Check if it's a comma-separated list of ports
        try:
            if ',' in ports_policy_str:
                ports = [int(p.strip()) for p in ports_policy_str.split(',')]
                for p in ports:
                    if not (1 <= p <= 65535):
                        return False, f"Invalid config: port {p} out of range (1-65535)"
            else:
                return False, f"Invalid config: ports policy '{ports_policy_str}' is invalid"
        except (ValueError, AttributeError):
            return False, f"Invalid config: ports policy '{ports_policy_str}' is invalid"

    # Check booleans
    for key in ['brute', 'graph', 'email', 'verbose', 'excel']:
        if key in resolved and not isinstance(resolved[key], bool):
            return False, f"Invalid config: {key} must be boolean"

    # Warn about unknown top-level keys (only if verbose or config flag)
    known_keys = {'targets', 'scan', 'report', 'bruteforce', 'general', 'email'}
    if verbose or sys.argv[1:2] == ['--config']:
        for key in config.keys():
            if key not in known_keys:
                print(f"Warning: unknown config key '{key}'", file=sys.stderr)

    return True, ""


def print_config(resolved: Dict[str, Any], config_file_used: str, config_exists: bool, config_valid: bool) -> None:
    """Print resolved configuration with provenance in JSON format."""
    output = {
        'config_file_used': config_file_used,
        'config_exists': config_exists,
        'config_valid': config_valid,
        'networks': resolved['networks'],
        'excludes': sorted(list(resolved['excludes'])),
        'brute': resolved['brute'],
        'graph': resolved['graph'],
        'csv': resolved['csv'],
        'email': resolved['email'],
        'excel': resolved['excel'],
        'verbose': resolved['verbose'],
        'config_file': resolved['config_file'],
    }
    print(json.dumps(output, indent=2))


def print_summary(results: Dict[str, Any]) -> None:
    """Print minimal scan summary to console."""
    for network in results['networks']:
        name = network['name']
        cidr = network['cidr']
        hosts = network['hosts']
        num_hosts = len(hosts)

        # Aggregate CVE stats across all hosts in this network
        total_open_ports = sum(len(host['open_ports']) for host in hosts)
        total_cves = sum(host['vulners']['unique_cve_count'] for host in hosts)
        max_cvss = max((host['vulners']['max_cvss'] for host in hosts), default=0.0)
        agg_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for host in hosts:
            for level, count in host['vulners']['severity'].items():
                agg_severity[level] += count

        print(f"Network: {name}")
        print(f"  CIDR: {cidr}")
        print(f"  Hosts: {num_hosts}")
        print(f"  Total Open Ports: {total_open_ports}")
        print(f"  Total Unique CVEs: {total_cves}")
        print(f"  Max CVSS: {max_cvss}")
        print(f"  Severity: critical={agg_severity['critical']} high={agg_severity['high']} medium={agg_severity['medium']} low={agg_severity['low']} unknown={agg_severity['unknown']}")

        # Top risky hosts (up to 3, sorted by risk_score desc)
        top = sorted(hosts, key=lambda h: -h.get('risk_score', 0))[:3]
        if top:
            print(f"  Top risky hosts:")
            for h in top:
                print(f"    {h['ip']}  risk={h.get('risk_score', 0)}  CVEs={h['vulners']['unique_cve_count']}  max_cvss={h['vulners']['max_cvss']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Sroq - A clean CLI tool for network scanning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Core arguments
    parser.add_argument(
        '-t', '--target',
        help='Target CIDR or IP address (overrides config networks)',
        type=str,
        default=None,
    )

    parser.add_argument(
        '--exclude',
        help='Exclude IP or CIDR (can be repeated or comma-separated)',
        action='append',
        default=None,
    )

    # Behavior flags
    parser.add_argument(
        '-b', '--brute',
        help='Enable brute force scanning',
        action='store_true',
    )

    parser.add_argument(
        '-g', '--graph',
        help='Generate graph output',
        action='store_true',
    )

    parser.add_argument(
        '-c', '--csv',
        help='Export results as CSV',
        action='store_true',
    )

    parser.add_argument(
        '-x', '--excel',
        help='Export results as Excel (.xlsx)',
        action='store_true',
    )

    parser.add_argument(
        '-e', '--email',
        help='Include email collection',
        action='store_true',
    )

    parser.add_argument(
        '-v', '--verbose',
        help='Enable verbose output',
        action='store_true',
    )

    # Config arguments
    parser.add_argument(
        '--config',
        help='Print resolved configuration and exit',
        action='store_true',
    )

    parser.add_argument(
        '--config-file',
        help='Path to configuration file (default: ./sroq.yml)',
        type=str,
        default='./sroq.yml',
    )

    args = parser.parse_args()

    # Convert config file to absolute path
    config_file_path = Path(args.config_file).resolve()
    config_file_used = str(config_file_path)
    config_exists = config_file_path.exists()

    # Load config file (errors if not found)
    config = load_config(args.config_file)

    # Merge configurations
    resolved = merge_configs(args, config)

    # Validate configuration
    config_valid, error_msg = validate_config(resolved, config, args.target, args.verbose)

    # If --config flag, print and exit
    if args.config:
        print_config(resolved, config_file_used, config_exists, config_valid)
        sys.exit(0)

    # If validation failed, print error and exit
    if not config_valid:
        print(f"Error: {error_msg}", file=sys.stderr)
        sys.exit(1)

    # Determine ports policy
    ports_policy = "top-1000"
    if 'scan' in config and 'ports' in config['scan']:
        ports_policy = config['scan']['ports']

    # Determine bruteforce credfile
    credfile = None
    if 'bruteforce' in config and 'credfile' in config['bruteforce']:
        credfile = config['bruteforce']['credfile']

    # Run scan with runtime tracking
    print("Starting scan...")

    start_time = datetime.now()

    try:
        results = run_scan(
            resolved['networks'],
            list(resolved['excludes']),
            ports_policy,
            resolved['brute'],
            credfile,
            resolved['verbose']
        )
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(130)

    finish_time = datetime.now()
    duration = (finish_time - start_time).total_seconds()

    print("Scan completed.")

    # Add runtime metadata and provenance to results
    results["started_at"] = start_time.isoformat()
    results["finished_at"] = finish_time.isoformat()
    results["duration_seconds"] = duration
    results["config_file_used"] = config_file_used

    # Determine output directory
    out_dir = "./out"
    if 'general' in config and 'out_dir' in config['general']:
        out_dir = config['general']['out_dir']

    # Ensure output directory exists
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # Save results as JSON
    timestamp = results['timestamp']
    json_filename = f"sroq_{timestamp}.json"
    json_path = Path(out_dir) / json_filename

    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)

    # Print summary
    print_summary(results)
    print(f"Saved JSON: {json_path}")

    # Generate graph if requested
    if resolved['graph']:
        graph_path = generate_severity_graph(results, out_dir)
        if graph_path:
            print(f"Saved graph: {graph_path}")

    # Export CSV if requested
    if resolved['csv']:
        csv_path = generate_csv(results, out_dir)
        if csv_path:
            print(f"Saved CSV: {csv_path}")

    # Export Excel if requested (also generates CSV)
    if resolved['excel']:
        csv_path = generate_csv(results, out_dir)
        if csv_path:
            print(f"Saved CSV: {csv_path}")
        excel_path = generate_excel(results, out_dir)
        if excel_path:
            print(f"Saved Excel: {excel_path}")


if __name__ == '__main__':
    main()
