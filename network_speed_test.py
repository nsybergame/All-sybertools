#!/usr/bin/env python3
"""
NETWORK SPEED TEST
==================

Test network bandwidth and latency.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests speedtest-cli

Author: CyberSecurity Tools Hub
"""

import time
import argparse
import sys
import socket
import threading
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

def ping_latency(host: str, count: int = 4) -> dict:
    """
    Measure ping latency.
    
    Args:
        host: Host to ping
        count: Number of pings
    
    Returns:
        Dictionary with latency stats
    """
    import subprocess
    import platform
    
    system = platform.system().lower()
    
    if system == 'windows':
        cmd = ['ping', '-n', str(count), host]
    else:
        cmd = ['ping', '-c', str(count), host]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 5)
        output = result.stdout
        
        # Parse average latency
        import re
        if system == 'windows':
            match = re.search(r'Average = (\d+)ms', output)
        else:
            match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
        
        if match:
            return {
                'success': True,
                'avg_latency_ms': float(match.group(1)),
                'host': host
            }
        else:
            return {'success': False, 'error': 'Could not parse latency'}
    
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def download_speed_test(url: str = None, size_mb: int = 10) -> dict:
    """
    Test download speed.
    
    Args:
        url: URL to download (optional)
        size_mb: Size of test file in MB
    
    Returns:
        Dictionary with download speed
    """
    if not REQUESTS_AVAILABLE:
        return {'error': 'requests not installed'}
    
    # Default test URLs
    test_urls = [
        'https://speed.cloudflare.com/__down?bytes={}',
        'https://proof.ovh.net/files/{}Mb.dat',
    ]
    
    url = url or test_urls[0].format(size_mb * 1024 * 1024)
    
    try:
        start_time = time.time()
        response = requests.get(url, stream=True, timeout=60)
        total_size = 0
        
        for chunk in response.iter_content(chunk_size=8192):
            total_size += len(chunk)
        
        end_time = time.time()
        duration = end_time - start_time
        
        speed_bps = total_size / duration
        speed_mbps = speed_bps / (1024 * 1024)
        
        return {
            'success': True,
            'speed_mbps': round(speed_mbps, 2),
            'speed_bps': round(speed_bps, 0),
            'downloaded_mb': round(total_size / (1024 * 1024), 2),
            'duration_sec': round(duration, 2)
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

def upload_speed_test(url: str = None, size_mb: int = 5) -> dict:
    """
    Test upload speed.
    
    Args:
        url: URL to upload to (optional)
        size_mb: Size of test data in MB
    
    Returns:
        Dictionary with upload speed
    """
    if not REQUESTS_AVAILABLE:
        return {'error': 'requests not installed'}
    
    # Generate random data
    import random
    data = bytes([random.randint(0, 255) for _ in range(size_mb * 1024 * 1024)])
    
    url = url or 'https://httpbin.org/post'
    
    try:
        start_time = time.time()
        response = requests.post(url, data=data, timeout=60)
        end_time = time.time()
        
        duration = end_time - start_time
        speed_bps = len(data) / duration
        speed_mbps = speed_bps / (1024 * 1024)
        
        return {
            'success': True,
            'speed_mbps': round(speed_mbps, 2),
            'speed_bps': round(speed_bps, 0),
            'uploaded_mb': size_mb,
            'duration_sec': round(duration, 2)
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

def dns_speed_test(domain: str = 'google.com') -> dict:
    """Test DNS resolution speed."""
    try:
        start_time = time.time()
        socket.gethostbyname(domain)
        end_time = time.time()
        
        return {
            'success': True,
            'domain': domain,
            'resolution_time_ms': round((end_time - start_time) * 1000, 2)
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def run_speed_test():
    """Run complete speed test."""
    print("\n" + "="*60)
    print("  NETWORK SPEED TEST - CyberSecurity Tools Hub")
    print("="*60)
    
    print("\n  Running network tests...\n")
    
    # DNS Test
    print("  [1/4] Testing DNS resolution...")
    dns_result = dns_speed_test()
    if dns_result['success']:
        print(f"        DNS: {dns_result['resolution_time_ms']} ms")
    else:
        print(f"        DNS: {dns_result['error']}")
    
    # Latency Test
    print("\n  [2/4] Testing latency...")
    latency_result = ping_latency('8.8.8.8', count=4)
    if latency_result['success']:
        print(f"        Latency: {latency_result['avg_latency_ms']} ms")
    else:
        print(f"        Latency: {latency_result['error']}")
    
    # Download Test
    print("\n  [3/4] Testing download speed (10 MB)...")
    download_result = download_speed_test(size_mb=10)
    if download_result['success']:
        print(f"        Download: {download_result['speed_mbps']} Mbps")
    else:
        print(f"        Download: {download_result['error']}")
    
    # Upload Test
    print("\n  [4/4] Testing upload speed (5 MB)...")
    upload_result = upload_speed_test(size_mb=5)
    if upload_result['success']:
        print(f"        Upload: {upload_result['speed_mbps']} Mbps")
    else:
        print(f"        Upload: {upload_result['error']}")
    
    print("\n" + "="*60)
    print("  RESULTS SUMMARY")
    print("="*60)
    
    if download_result['success'] and upload_result['success']:
        print(f"\n  Download: {download_result['speed_mbps']} Mbps")
        print(f"  Upload:   {upload_result['speed_mbps']} Mbps")
        if latency_result['success']:
            print(f"  Latency:  {latency_result['avg_latency_ms']} ms")
        if dns_result['success']:
            print(f"  DNS:      {dns_result['resolution_time_ms']} ms")
        
        # Calculate quality score
        dl_score = min(100, download_result['speed_mbps'] / 1)
        ul_score = min(100, upload_result['speed_mbps'] / 0.5)
        lat_score = max(0, 100 - (latency_result['avg_latency_ms'] / 2)) if latency_result['success'] else 50
        
        overall = (dl_score + ul_score + lat_score) / 3
        print(f"\n  Quality Score: {round(overall, 1)}/100")
    
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description="Network Speed Test - Test network bandwidth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_speed_test.py
  python network_speed_test.py --download-only
  python network_speed_test.py --ping google.com
        """
    )
    
    parser.add_argument("--download-only", action="store_true", help="Test download only")
    parser.add_argument("--upload-only", action="store_true", help="Test upload only")
    parser.add_argument("--ping", help="Test ping latency to host")
    parser.add_argument("--size", type=int, default=10, help="Test size in MB")
    
    args = parser.parse_args()
    
    try:
        if args.ping:
            result = ping_latency(args.ping)
            if result['success']:
                print(f"\n  Ping {args.ping}: {result['avg_latency_ms']} ms\n")
            else:
                print(f"\n  Error: {result['error']}\n")
        elif args.download_only:
            result = download_speed_test(size_mb=args.size)
            if result['success']:
                print(f"\n  Download Speed: {result['speed_mbps']} Mbps")
                print(f"  Downloaded: {result['downloaded_mb']} MB\n")
            else:
                print(f"\n  Error: {result['error']}\n")
        elif args.upload_only:
            result = upload_speed_test(size_mb=args.size)
            if result['success']:
                print(f"\n  Upload Speed: {result['speed_mbps']} Mbps\n")
            else:
                print(f"\n  Error: {result['error']}\n")
        else:
            run_speed_test()
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
