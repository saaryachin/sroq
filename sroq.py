#!/usr/bin/env python3

import argparse
import sys
import json
from pathlib import Path
from typing import Optional, Dict, List, Set, Any
from datetime import datetime
import ipaddress

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install it with: pip install PyYAML", file=sys.stderr)
    sys.exit(1)

from lib.sroq_scan import run_scan


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

    if cli_args.email:
        resolved['email'] = True

    if cli_args.verbose:
        resolved['verbose'] = True

    # Validate that at least one network is configured
    if not resolved['networks']:
        print("Error: No target networks configured. Use --target or configure networks in config file.", file=sys.stderr)
        sys.exit(1)

    return resolved


def print_config(resolved: Dict[str, Any]) -> None:
    """Print resolved configuration in JSON format."""
    output = {
        'networks': resolved['networks'],
        'excludes': sorted(list(resolved['excludes'])),
        'brute': resolved['brute'],
        'graph': resolved['graph'],
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

        # Calculate totals
        total_open_ports = sum(len(host['open_ports']) for host in hosts)
        total_exploits = sum(host['vulners_exploit_count'] for host in hosts)

        print(f"Network: {name}")
        print(f"  CIDR: {cidr}")
        print(f"  Hosts: {num_hosts}")
        print(f"  Total Open Ports: {total_open_ports}")
        print(f"  Total Exploits: {total_exploits}")
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

    # Load config file (errors if not found)
    config = load_config(args.config_file)

    # Merge configurations
    resolved = merge_configs(args, config)

    # If --config flag, print and exit
    if args.config:
        print_config(resolved)
        sys.exit(0)

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

    # Add runtime metadata to results
    results["started_at"] = start_time.isoformat()
    results["finished_at"] = finish_time.isoformat()
    results["duration_seconds"] = duration

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


if __name__ == '__main__':
    main()
