#!/usr/bin/env python3
"""
NETWORK SCANNER
===============

Discover devices on a local network using ARP requests.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only use on networks you own or have permission to scan.
Unauthorized network scanning may be illegal.

Requirements:
    pip install scapy

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import socket
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def get_local_network() -> str:
    """Get the local network range."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume /24 network
        parts = local_ip.split('.')
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return network
    except:
        return None

def scan_network_simple(network: str, timeout: int = 3) -> list:
    """
    Scan network without scapy using ping (slower but no dependencies).
    """
    import subprocess
    import ipaddress
    
    devices = []
    print(f"  Scanning network: {network}")
    print(f"  (Using ping sweep - this may take a while...)\n")
    
    network_obj = ipaddress.ip_network(network, strict=False)
    
    for ip in network_obj.hosts():
        ip_str = str(ip)
        try:
            # Ping with timeout
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip_str],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                devices.append({
                    'ip': ip_str,
                    'mac': 'N/A',
                    'hostname': get_hostname(ip_str)
                })
                print(f"  [+] Found: {ip_str}")
        except:
            pass
    
    return devices

def get_hostname(ip: str) -> str:
    """Get hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def scan_network_scapy(network: str, timeout: int = 3) -> list:
    """
    Scan network using scapy ARP requests (fast and accurate).
    """
    # Create ARP request
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Send packet and receive responses
    result = srp(packet, timeout=timeout, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': get_hostname(received.psrc)
        })
    
    return sorted(devices, key=lambda x: tuple(map(int, x['ip'].split('.'))))

def print_results(devices: list, scan_time: float):
    """Print scan results."""
    print("\n" + "="*70)
    print("  NETWORK SCAN RESULTS")
    print("="*70)
    
    if not devices:
        print("\n  No devices found on the network.")
        return
    
    print(f"\n  Found {len(devices)} device(s) in {scan_time:.2f} seconds\n")
    print("  " + "-"*66)
    print(f"  {'IP Address':<18} {'MAC Address':<20} {'Hostname':<25}")
    print("  " + "-"*66)
    
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        hostname = device['hostname'][:23]
        print(f"  {ip:<18} {mac:<20} {hostname:<25}")
    
    print("  " + "-"*66)

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner - Discover devices on a network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py                    # Scan local network
  python network_scanner.py -n 192.168.1.0/24  # Scan specific network
  python network_scanner.py -n 10.0.0.0/24 -t 5
        """
    )
    
    parser.add_argument("-n", "--network", help="Network range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3,
                        help="Scan timeout in seconds (default: 3)")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--simple", action="store_true",
                        help="Use ping sweep instead of ARP (slower, no dependencies)")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  WARNING: Only scan networks you own or have permission to!")
    print("!"*60 + "\n")
    
    # Determine network to scan
    network = args.network
    if not network:
        network = get_local_network()
        if network:
            print(f"  Auto-detected network: {network}")
        else:
            print("  [!] Could not auto-detect network. Please specify with -n")
            sys.exit(1)
    
    try:
        start_time = datetime.now()
        
        print(f"\n{'='*70}")
        print(f"  NETWORK SCANNER - CyberSecurity Tools Hub")
        print(f"{'='*70}")
        print(f"  Network: {network}")
        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # Choose scan method
        if args.simple or not SCAPY_AVAILABLE:
            if not SCAPY_AVAILABLE and not args.simple:
                print("  [!] scapy not installed, using ping sweep instead")
                print("      Install scapy for faster scans: pip install scapy\n")
            devices = scan_network_simple(network, args.timeout)
        else:
            print("  Scanning network using ARP requests...\n")
            devices = scan_network_scapy(network, args.timeout)
        
        end_time = datetime.now()
        scan_time = (end_time - start_time).total_seconds()
        
        # Print results
        print_results(devices, scan_time)
        
        # Save to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    'network': network,
                    'scan_time': scan_time,
                    'devices_found': len(devices),
                    'devices': devices
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
