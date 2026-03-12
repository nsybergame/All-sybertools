#!/usr/bin/env python3
"""
PORT SCANNER
============

A simple port scanner that checks for open ports on a target host.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only use this on systems you own or have explicit permission to test.
Unauthorized port scanning is illegal in many jurisdictions.

Author: CyberSecurity Tools Hub
"""

import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Common ports with service names
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    27017: "MongoDB"
}

def scan_port(target: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scan a single port on the target.
    
    Args:
        target: IP address or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary with port info and status
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            try:
                socket.setdefaulttimeout(timeout)
                banner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                banner.connect((target, port))
                banner_info = banner.recv(1024).decode().strip()[:50]
                banner.close()
            except:
                banner_info = ""
            
            return {
                "port": port,
                "status": "OPEN",
                "service": service,
                "banner": banner_info
            }
        return None
    except:
        return None

def scan_target(target: str, ports: list, max_threads: int = 100, timeout: float = 1.0, verbose: bool = False):
    """
    Scan multiple ports on a target.
    
    Args:
        target: IP address or hostname
        ports: List of ports to scan
        max_threads: Maximum concurrent threads
        timeout: Connection timeout
        verbose: Print progress
    
    Returns:
        List of open ports
    """
    open_ports = []
    
    print(f"\n{'='*60}")
    print(f"  PORT SCANNER - CyberSecurity Tools Hub")
    print(f"{'='*60}")
    print(f"  Target: {target}")
    print(f"  Ports: {len(ports)} ports to scan")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target, port, timeout): port for port in ports}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if verbose and completed % 100 == 0:
                print(f"  Progress: {completed}/{len(ports)} ports scanned...")
            
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"  [+] Port {result['port']:5d} ({result['service']:15s}): OPEN {result['banner']}")
    
    return sorted(open_ports, key=lambda x: x['port'])

def parse_port_range(port_str: str) -> list:
    """Parse port range string like '1-1000' or '80,443,8080'"""
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner - Check for open ports on a target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py 192.168.1.1
  python port_scanner.py example.com -p 1-1000
  python port_scanner.py 10.0.0.1 -p 80,443,8080,8443
  python port_scanner.py target.com -p 1-65535 -t 0.5 -v
        """
    )
    
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="Port range to scan (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-T", "--threads", type=int, default=100,
                        help="Maximum concurrent threads (default: 100)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress updates")
    parser.add_argument("--common", action="store_true",
                        help="Scan only common ports")
    
    args = parser.parse_args()
    
    # Legal warning
    print("\n" + "!"*60)
    print("  WARNING: Only scan systems you own or have permission to test!")
    print("  Unauthorized scanning may be illegal in your jurisdiction.")
    print("!"*60 + "\n")
    
    try:
        # Resolve hostname
        target_ip = socket.gethostbyname(args.target)
        if target_ip != args.target:
            print(f"  Resolved {args.target} to {target_ip}")
        
        # Determine ports to scan
        if args.common:
            ports = list(COMMON_PORTS.keys())
        else:
            ports = parse_port_range(args.ports)
        
        # Run scan
        start_time = datetime.now()
        open_ports = scan_target(target_ip, ports, args.threads, args.timeout, args.verbose)
        end_time = datetime.now()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE")
        print(f"  Duration: {end_time - start_time}")
        print(f"  Open ports found: {len(open_ports)}")
        print(f"{'='*60}\n")
        
        if open_ports:
            print("  OPEN PORTS SUMMARY:")
            print("  " + "-"*56)
            print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER':<30}")
            print("  " + "-"*56)
            for p in open_ports:
                banner = p['banner'][:28] if p['banner'] else "-"
                print(f"  {p['port']:<8} {p['service']:<15} {banner:<30}")
        else:
            print("  No open ports found.")
        
    except socket.gaierror:
        print(f"\n[!] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
