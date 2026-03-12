#!/usr/bin/env python3
"""
PING TOOL
=========

Check if a host is alive using ICMP ping.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Use responsibly and respect network policies.

Author: CyberSecurity Tools Hub
"""

import subprocess
import argparse
import sys
import platform
import re
from datetime import datetime
import statistics

def ping_host(host: str, count: int = 4, timeout: int = 2, interval: float = 0.5) -> dict:
    """
    Ping a host and return statistics.
    
    Args:
        host: Hostname or IP address
        count: Number of ping packets
        timeout: Timeout per packet in seconds
        interval: Interval between packets
    
    Returns:
        Dictionary with ping results
    """
    # Determine ping command based on OS
    system = platform.system().lower()
    
    if system == 'windows':
        cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
    else:
        cmd = ['ping', '-c', str(count), '-W', str(timeout), '-i', str(interval), host]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * (timeout + interval) + 10)
        output = result.stdout
        
        # Parse results
        return parse_ping_output(output, system)
        
    except subprocess.TimeoutExpired:
        return {
            'host': host,
            'status': 'timeout',
            'packets_sent': count,
            'packets_received': 0,
            'packet_loss': 100.0,
            'avg_latency': None,
            'min_latency': None,
            'max_latency': None,
            'output': 'Command timed out'
        }
    except Exception as e:
        return {
            'host': host,
            'status': 'error',
            'error': str(e),
            'output': ''
        }

def parse_ping_output(output: str, system: str) -> dict:
    """Parse ping command output."""
    result = {
        'host': '',
        'status': 'unknown',
        'packets_sent': 0,
        'packets_received': 0,
        'packet_loss': 100.0,
        'avg_latency': None,
        'min_latency': None,
        'max_latency': None,
        'rtts': [],
        'output': output
    }
    
    lines = output.lower().split('\n')
    
    # Extract host
    host_match = re.search(r'ping\s+(\S+)', output.lower())
    if host_match:
        result['host'] = host_match.group(1)
    
    # Parse based on OS
    if system == 'windows':
        # Windows ping output
        # Example: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        packets_match = re.search(r'sent\s*=\s*(\d+),\s*received\s*=\s*(\d+),\s*lost\s*=\s*(\d+)', output.lower())
        if packets_match:
            result['packets_sent'] = int(packets_match.group(1))
            result['packets_received'] = int(packets_match.group(2))
            if result['packets_sent'] > 0:
                result['packet_loss'] = (result['packets_sent'] - result['packets_received']) / result['packets_sent'] * 100
        
        # Parse latency
        # Example: "Minimum = 1ms, Maximum = 2ms, Average = 1ms"
        latency_match = re.search(r'minimum\s*=\s*(\d+)ms,\s*maximum\s*=\s*(\d+)ms,\s*average\s*=\s*(\d+)ms', output.lower())
        if latency_match:
            result['min_latency'] = float(latency_match.group(1))
            result['max_latency'] = float(latency_match.group(2))
            result['avg_latency'] = float(latency_match.group(3))
    else:
        # Unix/Linux ping output
        # Example: "4 packets transmitted, 4 received, 0% packet loss"
        packets_match = re.search(r'(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+received', output.lower())
        if packets_match:
            result['packets_sent'] = int(packets_match.group(1))
            result['packets_received'] = int(packets_match.group(2))
            if result['packets_sent'] > 0:
                result['packet_loss'] = (result['packets_sent'] - result['packets_received']) / result['packets_sent'] * 100
        
        # Parse latency
        # Example: "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms"
        latency_match = re.search(r'rtt\s+min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)', output.lower())
        if latency_match:
            result['min_latency'] = float(latency_match.group(1))
            result['avg_latency'] = float(latency_match.group(2))
            result['max_latency'] = float(latency_match.group(3))
        
        # Extract individual RTTs
        rtt_matches = re.findall(r'time=([\d.]+)\s*ms', output.lower())
        result['rtts'] = [float(rtt) for rtt in rtt_matches]
    
    # Determine status
    if result['packets_received'] > 0:
        result['status'] = 'reachable'
    else:
        result['status'] = 'unreachable'
    
    return result

def print_ping_result(result: dict, verbose: bool = False):
    """Pretty print ping results."""
    print("\n" + "="*60)
    print(f"  PING RESULTS: {result['host']}")
    print("="*60)
    
    if result['status'] == 'error':
        print(f"\n  [!] Error: {result.get('error', 'Unknown error')}")
        return
    
    status_icon = "✓" if result['status'] == 'reachable' else "✗"
    status_color = "green" if result['status'] == 'reachable' else "red"
    
    print(f"\n  Status: {status_icon} {result['status'].upper()}")
    print(f"\n  Statistics:")
    print(f"    Packets Sent:     {result['packets_sent']}")
    print(f"    Packets Received: {result['packets_received']}")
    print(f"    Packet Loss:      {result['packet_loss']:.1f}%")
    
    if result['avg_latency'] is not None:
        print(f"\n  Latency:")
        print(f"    Minimum: {result['min_latency']:.2f} ms")
        print(f"    Average: {result['avg_latency']:.2f} ms")
        print(f"    Maximum: {result['max_latency']:.2f} ms")
    
    if result['rtts'] and len(result['rtts']) > 1:
        print(f"    Std Dev: {statistics.stdev(result['rtts']):.2f} ms")
    
    if verbose:
        print(f"\n  Raw Output:")
        print("  " + "-"*56)
        for line in result['output'].split('\n'):
            if line.strip():
                print(f"  {line}")
    
    print("\n" + "="*60)

def continuous_ping(host: str, interval: float = 1.0):
    """Continuous ping until interrupted."""
    print(f"\n  Continuous ping to {host} (Press Ctrl+C to stop)...\n")
    
    try:
        while True:
            result = ping_host(host, count=1, timeout=int(interval))
            
            if result['status'] == 'reachable':
                if result['rtts']:
                    print(f"  [{datetime.now().strftime('%H:%M:%S')}] Reply from {result['host']}: time={result['rtts'][0]:.2f}ms")
                else:
                    print(f"  [{datetime.now().strftime('%H:%M:%S')}] Reply from {result['host']}")
            else:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] Request timeout for {result['host']}")
            
            import time
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n  Ping stopped.")

def main():
    parser = argparse.ArgumentParser(
        description="Ping Tool - Check if a host is alive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ping_tool.py google.com
  python ping_tool.py 8.8.8.8 -c 10
  python ping_tool.py example.com --continuous
        """
    )
    
    parser.add_argument("host", help="Hostname or IP address to ping")
    parser.add_argument("-c", "--count", type=int, default=4,
                        help="Number of ping packets (default: 4)")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="Timeout per packet in seconds (default: 2)")
    parser.add_argument("-i", "--interval", type=float, default=0.5,
                        help="Interval between packets (default: 0.5)")
    parser.add_argument("--continuous", action="store_true",
                        help="Continuous ping mode")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show raw output")
    
    args = parser.parse_args()
    
    try:
        if args.continuous:
            continuous_ping(args.host, args.interval)
        else:
            print(f"\n  Pinging {args.host}...")
            result = ping_host(args.host, args.count, args.timeout, args.interval)
            print_ping_result(result, args.verbose)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
