"""
Sroq Scanning Module

Provides network scanning functionality using nmap.
Handles host discovery, service detection, and vulnerability scanning.
"""

import nmap
from datetime import datetime


def discover_hosts(cidr: str, excludes: list[str]) -> list[str]:
    """
    Discover live hosts in the given CIDR range using nmap ping scan.

    Args:
        cidr: Network CIDR notation (e.g., "192.168.1.0/24")
        excludes: List of IPs/CIDRs to exclude from scan

    Returns:
        Sorted list of live host IP addresses
    """
    nm = nmap.PortScanner()

    # Build arguments for host discovery
    args = '-sn'
    if excludes:
        # Strip CIDR suffix from excludes (e.g., "192.168.122.65/32" -> "192.168.122.65")
        exclude_ips = [exclude.split('/')[0] for exclude in excludes]
        exclude_str = ','.join(exclude_ips)
        args += f' --exclude {exclude_str}'

    # Run discovery scan
    nm.scan(hosts=cidr, arguments=args)

    # Return sorted list of discovered hosts that are UP
    return sorted([host for host in nm.all_hosts() if nm[host].state() == "up"])


def scan_host(ip: str, ports_policy: str) -> dict:
    """
    Perform detailed scan on a single host with service detection and vulnerability scanning.

    Args:
        ip: Target IP address
        ports_policy: Port scanning policy ("top-1000", "top-100", "all", or "22,80,443")

    Returns:
        Dictionary containing scan results:
        {
            "ip": str,
            "open_ports": list[int],
            "vulners_exploit_count": int
        }
    """
    nm = nmap.PortScanner()

    # Build scan arguments
    args = '-sV --script vulners'

    # Apply ports policy
    if ports_policy == "top-100":
        args += ' --top-ports 100'
    elif ports_policy == "all":
        args += ' -p-'
    elif ports_policy != "top-1000":
        # Custom port list (e.g., "22,80,443")
        args += f' -p {ports_policy}'
    # "top-1000" uses default nmap behavior (no extra flag needed)

    # Run detailed scan
    scan_result = nm.scan(hosts=ip, arguments=args)

    # Initialize result variables
    open_ports = []
    exploit_count = 0

    # Parse scan results safely from scan_result dict
    host_data = scan_result.get("scan", {}).get(ip, {})

    if host_data:
        for proto, ports_data in host_data.items():
            if not isinstance(ports_data, dict):
                continue
            for port, port_info in ports_data.items():
                if isinstance(port_info, dict) and port_info.get("state") == "open":
                    open_ports.append(int(port))
                    vulners_output = port_info.get("script", {}).get("vulners", "")
                    exploit_count += vulners_output.count("*EXPLOIT*")

    return {
        "ip": ip,
        "open_ports": sorted(open_ports),
        "vulners_exploit_count": exploit_count
    }


def execute_brute_force(ip: str, network_name: str, credfile: str | None, verbose: bool) -> dict:
    """
    Execute brute force attacks on a host.

    Args:
        ip: Target IP address
        network_name: Name of the network being scanned
        credfile: Path to credentials file (None if not available)
        verbose: Print verbose feedback

    Returns:
        Dictionary with brute force results:
        {
            "enabled": bool,
            "success_ports": list[int],
            "success_count": int
        }
    """
    # Verbose: before brute force
    if verbose:
        print(f"[{network_name}] Conducting brute force against {ip}...")

    # Brute force execution placeholder for Phase 3
    # In later phases, this will attempt brute force attacks on common ports
    # using the provided credentials file
    success_ports = []
    success_count = 0

    # Verbose: after brute force
    if verbose:
        print(f"[{network_name}] Brute force completed for {ip} ({success_count} successes).")

    return {
        "enabled": True,
        "success_ports": success_ports,
        "success_count": success_count
    }


def run_scan(
    networks: list[dict],
    excludes: list[str],
    ports_policy: str,
    brute_enabled: bool,
    credfile: str | None,
    verbose: bool = False
) -> dict:
    """
    Run complete scan across multiple networks.

    Args:
        networks: List of network dicts with "name" and "cidr" keys
        excludes: List of IPs/CIDRs to exclude from all scans
        ports_policy: Port scanning policy to apply
        brute_enabled: Whether brute force is enabled (placeholder for Phase 3)
        credfile: Path to credentials file (placeholder for Phase 3)
        verbose: Enable verbose runtime output

    Returns:
        Dictionary containing complete scan results:
        {
            "timestamp": str,
            "networks": [
                {
                    "name": str,
                    "cidr": str,
                    "hosts": [host_results, ...]
                }, ...
            ]
        }
    """
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Results structure
    results = {
        "timestamp": timestamp,
        "networks": []
    }

    # Scan each network separately
    for network in networks:
        network_name = network["name"]
        network_cidr = network["cidr"]

        # Verbose: before host discovery
        if verbose:
            print(f"[{network_name}] Discovering hosts in {network_cidr}...")

        # Discover hosts in this network
        live_hosts = discover_hosts(network_cidr, excludes)

        # Verbose: after host discovery
        if verbose:
            print(f"[{network_name}] Found {len(live_hosts)} live hosts.")

        # Scan each discovered host
        host_results = []
        for i, host_ip in enumerate(live_hosts, 1):
            # Verbose: before scanning each host
            if verbose:
                print(f"[{network_name}] Scanning {host_ip} ({i}/{len(live_hosts)})...")

            # Perform detailed scan
            host_data = scan_host(host_ip, ports_policy)

            # Execute brute force if enabled
            if brute_enabled:
                brute_result = execute_brute_force(host_ip, network_name, credfile, verbose)
                host_data["brute"] = brute_result
            else:
                # Brute force disabled: placeholder only
                host_data["brute"] = {
                    "enabled": False,
                    "success_ports": [],
                    "success_count": 0
                }

            host_results.append(host_data)

        # Add network results
        results["networks"].append({
            "name": network_name,
            "cidr": network_cidr,
            "hosts": host_results
        })

    return results
