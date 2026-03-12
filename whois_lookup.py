#!/usr/bin/env python3
"""
WHOIS LOOKUP
============

Get domain registration information using whois.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Use responsibly and respect whois server rate limits.

Requirements:
    pip install python-whois

Author: CyberSecurity Tools Hub
"""

import subprocess
import argparse
import sys
import re
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

def whois_lookup_builtin(domain: str) -> dict:
    """
    Perform whois lookup using python-whois library.
    """
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return {"error": str(e)}

def whois_lookup_cmd(domain: str) -> str:
    """
    Perform whois lookup using system command.
    """
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: Whois lookup timed out"
    except FileNotFoundError:
        return "Error: whois command not found. Install with: apt install whois"
    except Exception as e:
        return f"Error: {str(e)}"

def parse_whois_output(output: str) -> dict:
    """Parse whois output into structured data."""
    result = {}
    
    # Common patterns
    patterns = {
        'registrar': r'Registrar:\s*(.+)',
        'creation_date': r'Creation Date:\s*(.+)',
        'expiration_date': r'Registry Expiry Date:\s*(.+)',
        'updated_date': r'Updated Date:\s*(.+)',
        'name_servers': r'Name Server:\s*(.+)',
        'status': r'Status:\s*(.+)',
        'registrant_name': r'Registrant Name:\s*(.+)',
        'registrant_email': r'Registrant Email:\s*(.+)',
        'admin_email': r'Admin Email:\s*(.+)',
    }
    
    for key, pattern in patterns.items():
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            if key == 'name_servers':
                result[key] = [m.strip() for m in matches]
            else:
                result[key] = matches[0].strip()
    
    return result

def print_whois_info(domain: str, info: dict, raw_output: str = None):
    """Pretty print whois information."""
    print("\n" + "="*70)
    print(f"  WHOIS INFORMATION FOR: {domain}")
    print("="*70)
    
    if isinstance(info, dict):
        if 'error' in info:
            print(f"\n  [!] Error: {info['error']}")
            return
        
        # Print structured info
        if info.get('domain_name'):
            print(f"\n  Domain Name: {info['domain_name']}")
        
        if info.get('registrar'):
            print(f"  Registrar: {info['registrar']}")
        
        if info.get('creation_date'):
            dates = info['creation_date']
            if isinstance(dates, list):
                dates = dates[0]
            print(f"  Created: {dates}")
        
        if info.get('expiration_date'):
            dates = info['expiration_date']
            if isinstance(dates, list):
                dates = dates[0]
            print(f"  Expires: {dates}")
        
        if info.get('updated_date'):
            dates = info['updated_date']
            if isinstance(dates, list):
                dates = dates[0]
            print(f"  Last Updated: {dates}")
        
        if info.get('name_servers'):
            ns = info['name_servers']
            if isinstance(ns, list):
                print(f"\n  Name Servers:")
                for n in ns[:5]:
                    print(f"    - {n}")
            else:
                print(f"  Name Servers: {ns}")
        
        if info.get('status'):
            status = info['status']
            if isinstance(status, list):
                print(f"\n  Status:")
                for s in status[:5]:
                    print(f"    - {s}")
            else:
                print(f"  Status: {status}")
        
        if info.get('registrant_name'):
            print(f"\n  Registrant Name: {info['registrant_name']}")
        
        if info.get('registrant_email'):
            print(f"  Registrant Email: {info['registrant_email']}")
        
        if info.get('admin_email'):
            print(f"  Admin Email: {info['admin_email']}")
    
    if raw_output:
        print("\n  Raw Whois Output:")
        print("  " + "-"*66)
        for line in raw_output.split('\n')[:50]:
            if line.strip():
                print(f"  {line}")
        if len(raw_output.split('\n')) > 50:
            print(f"  ... ({len(raw_output.split('\n')) - 50} more lines)")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="Whois Lookup - Get domain registration information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python whois_lookup.py example.com
  python whois_lookup.py google.com --raw
        """
    )
    
    parser.add_argument("domain", help="Domain name to look up")
    parser.add_argument("--raw", action="store_true",
                        help="Show raw whois output")
    parser.add_argument("--cmd", action="store_true",
                        help="Use system whois command")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  Whois Lookup - Public domain information")
    print("!"*60)
    
    try:
        if args.cmd or not WHOIS_AVAILABLE:
            if not WHOIS_AVAILABLE and not args.cmd:
                print("  [!] python-whois not installed, using system command")
            raw_output = whois_lookup_cmd(args.domain)
            parsed = parse_whois_output(raw_output)
            print_whois_info(args.domain, parsed, raw_output if args.raw else None)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(raw_output)
                print(f"\n  Output saved to: {args.output}")
        else:
            info = whois_lookup_builtin(args.domain)
            raw = whois_lookup_cmd(args.domain) if args.raw else None
            print_whois_info(args.domain, info, raw)
            
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    if hasattr(info, '__dict__'):
                        json.dump(info.__dict__, f, indent=2, default=str)
                    else:
                        json.dump(info, f, indent=2, default=str)
                print(f"\n  Output saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
