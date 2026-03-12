#!/usr/bin/env python3
"""
IP RANGE SCANNER
================

Scan a range of IP addresses for live hosts.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only scan networks you own or have permission to test.
Unauthorized scanning is ILLEGAL.

Author: CyberSecurity Tools Hub
"""

import socket
import argparse
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import subprocess
import platform

def ping_host(ip: str, timeout: int = 1) -> bool:
    """
    Check if a host is alive using ping.
    
    Args:
        ip: IP address
        timeout: Timeout in seconds
    
    Returns:
        True if host is alive
    """
    system = platform.system().lower()
    
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return result.returncode == 0
    except:
        return False

def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host.
    
    Args:
        ip: IP address
        port: Port number
        timeout: Connection timeout
    
    Returns:
        True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_ip_range(
    network: str,
    method: str = 'ping',
    ports: list = None,
    threads: int = 50,
    timeout: int = 1,
    verbose: bool = False
) -> list:
    """
    Scan an IP range for live hosts.
    
    Args:
        network: Network in CIDR notation (e.g., 192.168.1.0/24)
        method: Scan method ('ping' or 'port')
        ports: Ports to scan if method is 'port'
        threads: Number of threads
        timeout: Timeout per host
        verbose: Show progress
    
    Returns:
        List of live hosts
    """
    live_hosts = []
    
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        hosts = list(network_obj.hosts())
    except:
        print(f"[!] Invalid network: {network}")
        return []
    
    print(f"\n  Scanning {len(hosts)} hosts in {network}...")
    print(f"  Method: {method}")
    print(f"  Threads: {threads}\n")
    
    def check_host(ip):
        ip_str = str(ip)
        
        if method == 'ping':
            if ping_host(ip_str, timeout):
                return {'ip': ip_str, 'status': 'alive'}
        elif method == 'port' and ports:
            open_ports = []
            for port in ports:
                if check_port(ip_str, port, timeout):
                    open_ports.append(port)
            if open_ports:
                return {'ip': ip_str, 'status': 'alive', 'ports': open_ports}
        
        return None
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in hosts}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if verbose and completed % 20 == 0:
                print(f"  Progress: {completed}/{len(hosts)}")
            
            result = future.result()
            if result:
                live_hosts.append(result)
                if 'ports' in result:
                    print(f"  [+] {result['ip']}: Ports {result['ports']}")
                else:
                    print(f"  [+] {result['ip']}: Alive")
    
    return sorted(live_hosts, key=lambda x: tuple(map(int, x['ip'].split('.'))))

def main():
    parser = argparse.ArgumentParser(
        description="IP Range Scanner - Scan IP ranges for live hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DISCLAIMER:
Only scan networks you own or have permission to test!

Examples:
  python ip_range_scanner.py 192.168.1.0/24
  python ip_range_scanner.py 10.0.0.0/24 --port-scan -p 22,80,443
  python ip_range_scanner.py 172.16.0.0/16 -t 100 -v
        """
    )
    
    parser.add_argument("network", help="Network range in CIDR notation")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout in seconds")
    parser.add_argument("--port-scan", action="store_true", help="Use port scanning instead of ping")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  WARNING: Only scan networks you have permission to test!")
    print("!"*60)
    
    try:
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        elif args.port_scan:
            ports = [22, 80, 443, 3389]
        
        method = 'port' if args.port_scan else 'ping'
        
        print("\n" + "="*60)
        print("  IP RANGE SCANNER - CyberSecurity Tools Hub")
        print("="*60)
        print(f"  Network: {args.network}")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        start_time = datetime.now()
        live_hosts = scan_ip_range(
            args.network,
            method=method,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose
        )
        end_time = datetime.now()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE")
        print(f"  Duration: {end_time - start_time}")
        print(f"  Live hosts found: {len(live_hosts)}")
        print(f"{'='*60}\n")
        
        if live_hosts:
            print("  LIVE HOSTS:")
            print("  " + "-"*56)
            for host in live_hosts:
                if 'ports' in host:
                    print(f"  {host['ip']:<20} Ports: {host['ports']}")
                else:
                    print(f"  {host['ip']}")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    'network': args.network,
                    'duration': str(end_time - start_time),
                    'hosts_found': len(live_hosts),
                    'hosts': live_hosts
                }, f, indent=2)
            print(f"\n  Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
