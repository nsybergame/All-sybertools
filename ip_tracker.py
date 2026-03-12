#!/usr/bin/env python3
"""
IP TRACKER
==========

Get geolocation information from an IP address using public APIs.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Respect API rate limits and terms of service.

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import json
import sys
from typing import Dict, Optional

def get_ip_info(ip_address: str = None) -> Dict:
    """
    Get geolocation information for an IP address.
    
    Args:
        ip_address: IP address to look up (None for your own IP)
    
    Returns:
        Dictionary with IP information
    """
    # Using ip-api.com (free, no API key required)
    if ip_address:
        url = f"http://ip-api.com/json/{ip_address}"
    else:
        url = "http://ip-api.com/json/"
    
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if data.get('status') == 'fail':
            return {"error": data.get('message', 'Unknown error')}
        
        return {
            "ip": data.get('query'),
            "country": data.get('country'),
            "country_code": data.get('countryCode'),
            "region": data.get('regionName'),
            "city": data.get('city'),
            "zip": data.get('zip'),
            "lat": data.get('lat'),
            "lon": data.get('lon'),
            "timezone": data.get('timezone'),
            "isp": data.get('isp'),
            "org": data.get('org'),
            "as": data.get('as'),
            "mobile": data.get('mobile', False),
            "proxy": data.get('proxy', False),
            "hosting": data.get('hosting', False)
        }
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}

def get_detailed_info(ip_address: str) -> Dict:
    """Get additional information from multiple sources."""
    result = {"ip_api": get_ip_info(ip_address)}
    
    # Try ipapi.co for additional info
    try:
        if ip_address:
            url = f"https://ipapi.co/{ip_address}/json/"
        else:
            url = "https://ipapi.co/json/"
        
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if 'error' not in data:
            result['ipapi_co'] = {
                "languages": data.get('languages'),
                "currency": data.get('currency'),
                "currency_name": data.get('currency_name'),
                "country_population": data.get('country_population'),
                "in_eu": data.get('in_eu', False)
            }
    except:
        pass
    
    return result

def print_ip_info(info: Dict):
    """Pretty print IP information."""
    print("\n" + "="*60)
    print("  IP GEOLOCATION INFORMATION")
    print("="*60)
    
    if 'error' in info:
        print(f"\n  [!] Error: {info['error']}")
        return
    
    print(f"\n  {'IP Address:':<20} {info.get('ip', 'N/A')}")
    print(f"  {'Country:':<20} {info.get('country', 'N/A')} ({info.get('country_code', '')})")
    print(f"  {'Region:':<20} {info.get('region', 'N/A')}")
    print(f"  {'City:':<20} {info.get('city', 'N/A')}")
    print(f"  {'ZIP Code:':<20} {info.get('zip', 'N/A')}")
    print(f"  {'Coordinates:':<20} {info.get('lat', 'N/A')}, {info.get('lon', 'N/A')}")
    print(f"  {'Timezone:':<20} {info.get('timezone', 'N/A')}")
    print(f"  {'ISP:':<20} {info.get('isp', 'N/A')}")
    print(f"  {'Organization:':<20} {info.get('org', 'N/A')}")
    print(f"  {'AS:':<20} {info.get('as', 'N/A')}")
    
    print("\n  Flags:")
    print(f"  {'  - Mobile:':<20} {'Yes' if info.get('mobile') else 'No'}")
    print(f"  {'  - Proxy/VPN:':<20} {'Yes' if info.get('proxy') else 'No'}")
    print(f"  {'  - Hosting:':<20} {'Yes' if info.get('hosting') else 'No'}")
    
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description="IP Tracker - Get geolocation information from IP address",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_tracker.py                    # Get info about your own IP
  python ip_tracker.py 8.8.8.8            # Get info about specific IP
  python ip_tracker.py 1.1.1.1 -j         # Output as JSON
  python ip_tracker.py 192.168.1.1 -d     # Detailed info from multiple APIs
        """
    )
    
    parser.add_argument("ip", nargs="?", help="IP address to look up (optional)")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("-d", "--detailed", action="store_true",
                        help="Get detailed info from multiple sources")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  IP Tracker - For educational and legitimate purposes only")
    print("!"*60)
    
    try:
        if args.detailed:
            info = get_detailed_info(args.ip)
        else:
            info = get_ip_info(args.ip)
        
        if args.json:
            output = json.dumps(info, indent=2)
            print(output)
        else:
            if 'ip_api' in info:
                print_ip_info(info['ip_api'])
                if 'ipapi_co' in info:
                    print("\n  Additional Info (ipapi.co):")
                    for k, v in info['ipapi_co'].items():
                        print(f"  {k:<20} {v}")
            else:
                print_ip_info(info)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(info, f, indent=2)
            print(f"\n  Output saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
