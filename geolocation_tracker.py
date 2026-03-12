#!/usr/bin/env python3
"""
GEOLocation TRACKER
===================

Track geolocation of multiple IP addresses and visualize data.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_ip_location(ip: str = None, timeout: int = 10) -> dict:
    """
    Get geolocation for an IP address.
    
    Args:
        ip: IP address (None for your own IP)
        timeout: Request timeout
    
    Returns:
        Dictionary with location data
    """
    try:
        url = f"http://ip-api.com/json/{ip}" if ip else "http://ip-api.com/json/"
        response = requests.get(url, timeout=timeout)
        data = response.json()
        
        if data.get('status') == 'fail':
            return {'ip': ip, 'error': data.get('message')}
        
        return {
            'ip': data.get('query'),
            'country': data.get('country'),
            'country_code': data.get('countryCode'),
            'region': data.get('regionName'),
            'city': data.get('city'),
            'zip': data.get('zip'),
            'lat': data.get('lat'),
            'lon': data.get('lon'),
            'timezone': data.get('timezone'),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'as': data.get('as'),
            'mobile': data.get('mobile', False),
            'proxy': data.get('proxy', False),
            'hosting': data.get('hosting', False),
        }
    except Exception as e:
        return {'ip': ip, 'error': str(e)}

def batch_lookup(ips: list, threads: int = 10) -> list:
    """
    Look up multiple IPs in parallel.
    
    Args:
        ips: List of IP addresses
        threads: Number of concurrent threads
    
    Returns:
        List of location results
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(get_ip_location, ip): ip for ip in ips}
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
    
    return results

def generate_map_data(results: list) -> dict:
    """Generate data suitable for map visualization."""
    return {
        'type': 'FeatureCollection',
        'features': [
            {
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [r['lon'], r['lat']]
                },
                'properties': {
                    'ip': r['ip'],
                    'city': r.get('city'),
                    'country': r.get('country'),
                }
            }
            for r in results
            if 'error' not in r and r.get('lat') and r.get('lon')
        ]
    }

def main():
    parser = argparse.ArgumentParser(
        description="GeoLocation Tracker - Track IP locations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python geolocation_tracker.py                    # Your IP
  python geolocation_tracker.py 8.8.8.8            # Specific IP
  python geolocation_tracker.py -f ips.txt         # Batch lookup
  python geolocation_tracker.py -f ips.txt --map   # Generate map data
        """
    )
    
    parser.add_argument("ip", nargs="?", help="IP address to locate")
    parser.add_argument("-f", "--file", help="File with IP addresses (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of threads for batch lookup")
    parser.add_argument("--map", action="store_true",
                        help="Generate GeoJSON for mapping")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  GEOLOCATION TRACKER - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        if args.file:
            # Batch lookup
            with open(args.file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"\n  Looking up {len(ips)} IP addresses...")
            
            results = batch_lookup(ips, args.threads)
            
            # Summary
            countries = {}
            for r in results:
                if 'error' not in r:
                    c = r.get('country', 'Unknown')
                    countries[c] = countries.get(c, 0) + 1
            
            print(f"\n  Results Summary:")
            print(f"    Total: {len(results)}")
            print(f"    Successful: {len([r for r in results if 'error' not in r])}")
            print(f"    Failed: {len([r for r in results if 'error' in r])}")
            
            print(f"\n  Top Countries:")
            for country, count in sorted(countries.items(), key=lambda x: -x[1])[:10]:
                print(f"    {country}: {count}")
            
            if args.map:
                map_data = generate_map_data(results)
                print(f"\n  GeoJSON generated for {len(map_data['features'])} locations")
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(map_data, f, indent=2)
                    print(f"  Saved to: {args.output}")
            
            if args.json:
                print("\n" + json.dumps(results, indent=2))
        
        else:
            # Single IP lookup
            result = get_ip_location(args.ip)
            
            if 'error' in result:
                print(f"\n  [!] Error: {result['error']}")
                sys.exit(1)
            
            print(f"\n  IP: {result['ip']}")
            print(f"  Location: {result['city']}, {result['region']}, {result['country']}")
            print(f"  Coordinates: {result['lat']}, {result['lon']}")
            print(f"  Timezone: {result['timezone']}")
            print(f"  ISP: {result['isp']}")
            print(f"  Organization: {result['org']}")
            print(f"\n  Flags:")
            print(f"    Mobile: {'Yes' if result['mobile'] else 'No'}")
            print(f"    Proxy/VPN: {'Yes' if result['proxy'] else 'No'}")
            print(f"    Hosting: {'Yes' if result['hosting'] else 'No'}")
            
            if args.json:
                print("\n" + json.dumps(result, indent=2))
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\n  Saved to: {args.output}")
        
        print("\n" + "="*70)
        
    except FileNotFoundError:
        print(f"\n[!] File not found: {args.file}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
