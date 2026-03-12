#!/usr/bin/env python3
"""
MAC ADDRESS LOOKUP
==================

Find vendor information from MAC address.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import re
import argparse
import sys

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Local OUI database (sample entries)
# In production, you would use a complete OUI database
LOCAL_OUI_DB = {
    '00:00:0C': 'Cisco Systems, Inc.',
    '00:00:1A': 'NeXT Computer, Inc.',
    '00:00:1B': 'Novell, Inc.',
    '00:00:1D': 'Cabletron Systems, Inc.',
    '00:0A:95': 'Apple Computer, Inc.',
    '00:0D:93': 'Apple Computer, Inc.',
    '00:03:93': 'Apple Computer, Inc.',
    '00:05:02': 'Apple Computer, Inc.',
    '00:0E:A8': 'Apple Computer, Inc.',
    '00:11:24': 'Apple Inc.',
    '00:16:CB': 'Apple Inc.',
    '00:17:F2': 'Apple Inc.',
    '00:19:E3': 'Apple Inc.',
    '00:1B:63': 'Apple Inc.',
    '00:1C:B3': 'Apple Inc.',
    '00:1D:4F': 'Apple Inc.',
    '00:1E:52': 'Apple Inc.',
    '00:1F:5B': 'Apple Inc.',
    '00:1F:F3': 'Apple Inc.',
    '00:22:41': 'Apple Inc.',
    '00:23:12': 'Apple Inc.',
    '00:23:32': 'Apple Inc.',
    '00:23:6C': 'Apple Inc.',
    '00:23:DF': 'Apple Inc.',
    '00:24:36': 'Apple Inc.',
    '00:25:00': 'Apple Inc.',
    '00:25:4B': 'Apple Inc.',
    '00:25:BC': 'Apple Inc.',
    '00:26:08': 'Apple Inc.',
    '00:26:4A': 'Apple Inc.',
    '00:26:B0': 'Apple Inc.',
    '00:26:BB': 'Apple Inc.',
    '00:26:08': 'Apple Inc.',
    '00:50:56': 'VMware, Inc.',
    '00:0C:29': 'VMware, Inc.',
    '00:05:69': 'VMware, Inc.',
    '00:1C:14': 'VMware, Inc.',
    '08:00:27': 'Oracle VirtualBox',
    '0A:00:27': 'Oracle VirtualBox',
    '00:15:5D': 'Microsoft Corporation',
    '00:16:3E': 'Xensource, Inc.',
    '52:54:00': 'QEMU Virtual NIC',
    '54:52:00': 'QEMU Virtual NIC',
    '00:1A:A0': 'Intel Corporate',
    '00:1B:21': 'Intel Corporate',
    '00:1C:23': 'Intel Corporate',
    '00:1D:09': 'Intel Corporate',
    '00:1E:64': 'Intel Corporate',
    '00:1F:29': 'Intel Corporate',
    '00:1F:5D': 'Intel Corporate',
    '00:21:5C': 'Intel Corporate',
    '00:22:FA': 'Intel Corporate',
    '00:23:14': 'Intel Corporate',
    '00:24:D6': 'Intel Corporate',
    '00:25:3C': 'Intel Corporate',
    '00:26:B7': 'Intel Corporate',
    '00:26:C7': 'Intel Corporate',
    '00:27:0E': 'Intel Corporate',
    '00:27:10': 'Intel Corporate',
    'D4:3B:04': 'Intel Corporate',
    'F0:B4:D2': 'Intel Corporate',
    '00:07:2F': 'Samsung Electronics',
    '00:12:FB': 'Samsung Electronics',
    '00:16:32': 'Samsung Electronics',
    '00:17:C9': 'Samsung Electronics',
    '00:18:AF': 'Samsung Electronics',
    '00:1A:8A': 'Samsung Electronics',
    '00:1E:7D': 'Samsung Electronics',
    '00:1F:27': 'Samsung Electronics',
    '00:21:4E': 'Samsung Electronics',
    '00:22:43': 'Samsung Electronics',
    '00:23:3E': 'Samsung Electronics',
    '00:23:D6': 'Samsung Electronics',
    '00:24:1D': 'Samsung Electronics',
    '00:24:90': 'Samsung Electronics',
    '00:25:38': 'Samsung Electronics',
    '00:25:BC': 'Samsung Electronics',
    'B8:8A:60': 'Samsung Electronics',
    'CC:B1:1A': 'Samsung Electronics',
    'F4:09:D8': 'Samsung Electronics',
    'FC:AA:14': 'Samsung Electronics',
    'DC:A6:32': 'Raspberry Pi Foundation',
    'B8:27:EB': 'Raspberry Pi Foundation',
    '28:CD:C1': 'Raspberry Pi Trading Ltd',
}

def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to uppercase colon format.
    
    Args:
        mac: MAC address in any format
    
    Returns:
        Normalized MAC address
    """
    # Remove all separators and convert to uppercase
    mac = re.sub(r'[:\-.]', '', mac.upper())
    
    if len(mac) < 6:
        return ''
    
    # Format with colons
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

def get_oui(mac: str) -> str:
    """
    Extract OUI (first 3 octets) from MAC address.
    
    Args:
        mac: MAC address
    
    Returns:
        OUI in uppercase colon format
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return ''
    return normalized[:8]

def lookup_local(mac: str) -> dict:
    """
    Look up vendor in local database.
    
    Args:
        mac: MAC address
    
    Returns:
        Dictionary with vendor information
    """
    oui = get_oui(mac)
    vendor = LOCAL_OUI_DB.get(oui)
    
    return {
        'mac': normalize_mac(mac),
        'oui': oui,
        'vendor': vendor,
        'source': 'Local Database'
    }

def lookup_api(mac: str) -> dict:
    """
    Look up vendor using macvendors.com API.
    
    Args:
        mac: MAC address
    
    Returns:
        Dictionary with vendor information
    """
    if not REQUESTS_AVAILABLE:
        return {'error': 'requests library not installed'}
    
    oui = get_oui(mac)
    
    try:
        # Use macvendors.com API
        url = f"https://api.macvendors.com/{oui.replace(':', '-')}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            return {
                'mac': normalize_mac(mac),
                'oui': oui,
                'vendor': response.text.strip(),
                'source': 'MacVendors API'
            }
        elif response.status_code == 404:
            return {
                'mac': normalize_mac(mac),
                'oui': oui,
                'vendor': None,
                'source': 'MacVendors API'
            }
        else:
            return {
                'error': f'API returned status {response.status_code}',
                'source': 'MacVendors API'
            }
    
    except requests.exceptions.Timeout:
        return {'error': 'API request timed out', 'source': 'MacVendors API'}
    except Exception as e:
        return {'error': str(e), 'source': 'MacVendors API'}

def analyze_mac(mac: str) -> dict:
    """
    Analyze MAC address properties.
    
    Args:
        mac: MAC address
    
    Returns:
        Dictionary with MAC analysis
    """
    normalized = normalize_mac(mac)
    if len(normalized.replace(':', '')) != 12:
        return {'error': 'Invalid MAC address'}
    
    first_octet = int(normalized[:2], 16)
    
    return {
        'mac': normalized,
        'oui': get_oui(mac),
        'is_unicast': (first_octet & 0x01) == 0,
        'is_globally_unique': (first_octet & 0x02) == 0,
        'is_locally_administered': (first_octet & 0x02) != 0,
        'type': 'Unicast' if (first_octet & 0x01) == 0 else 'Multicast',
        'administration': 'Globally Unique' if (first_octet & 0x02) == 0 else 'Locally Administered',
    }

def main():
    parser = argparse.ArgumentParser(
        description="MAC Address Lookup - Find vendor from MAC address",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mac_address_lookup.py 00:0C:29:3E:35:5A
  python mac_address_lookup.py 00-0C-29-3E-35-5A
  python mac_address_lookup.py 000C.293E.355A
  python mac_address_lookup.py 00:0C:29 --online
        """
    )
    
    parser.add_argument("mac", help="MAC address to look up")
    parser.add_argument("--online", action="store_true",
                        help="Use online API for lookup")
    parser.add_argument("--analyze", action="store_true",
                        help="Show MAC address analysis")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  MAC ADDRESS LOOKUP - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        mac = args.mac
        
        # Local lookup
        local_result = lookup_local(mac)
        
        print(f"\n  MAC Address: {local_result['mac']}")
        print(f"  OUI: {local_result['oui']}")
        
        if local_result['vendor']:
            print(f"  Vendor: {local_result['vendor']}")
            print(f"  Source: {local_result['source']}")
        else:
            print(f"  Vendor: Not found in local database")
        
        # Online lookup
        if args.online:
            print("\n  Querying online API...")
            online_result = lookup_api(mac)
            
            if 'error' in online_result:
                print(f"  [!] {online_result['error']}")
            elif online_result.get('vendor'):
                print(f"  Vendor: {online_result['vendor']}")
                print(f"  Source: {online_result['source']}")
            else:
                print(f"  Vendor: Not found in online database")
        
        # Analysis
        if args.analyze:
            analysis = analyze_mac(mac)
            print(f"\n  Analysis:")
            print(f"    Type: {analysis['type']}")
            print(f"    Administration: {analysis['administration']}")
            print(f"    Is Unicast: {analysis['is_unicast']}")
            print(f"    Is Globally Unique: {analysis['is_globally_unique']}")
        
        if args.json:
            import json
            result = {
                'mac': local_result['mac'],
                'oui': local_result['oui'],
                'vendor': local_result['vendor'],
            }
            if args.analyze:
                result['analysis'] = analyze_mac(mac)
            print("\n" + json.dumps(result, indent=2))
        
        print("\n" + "="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
