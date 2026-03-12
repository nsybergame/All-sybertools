#!/usr/bin/env python3
"""
DNS LOOKUP TOOL
===============

Query DNS records for a domain.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Use responsibly and respect DNS server rate limits.

Author: CyberSecurity Tools Hub
"""

import dns.resolver
import argparse
import sys
from typing import List, Dict

# Common DNS record types
RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA', 'DMARC']

def lookup_record(domain: str, record_type: str) -> List[str]:
    """
    Look up DNS records for a domain.
    
    Args:
        domain: Domain name to query
        record_type: Type of DNS record
    
    Returns:
        List of record values
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return ["Domain does not exist"]
    except dns.resolver.NoNameservers:
        return ["No nameservers available"]
    except Exception as e:
        return [f"Error: {str(e)}"]

def get_all_records(domain: str) -> Dict[str, List[str]]:
    """Get all common DNS records for a domain."""
    results = {}
    for record_type in RECORD_TYPES:
        records = lookup_record(domain, record_type)
        if records and not records[0].startswith('Error') and not records[0].startswith('Domain') and not records[0].startswith('No nameservers'):
            results[record_type] = records
    return results

def check_dmarc(domain: str) -> List[str]:
    """Check DMARC record."""
    dmarc_domain = f"_dmarc.{domain}"
    return lookup_record(dmarc_domain, 'TXT')

def reverse_lookup(ip: str) -> List[str]:
    """Perform reverse DNS lookup."""
    try:
        answers = dns.resolver.resolve(dns.reversename.from_address(ip), 'PTR')
        return [str(rdata) for rdata in answers]
    except:
        return ["No PTR record found"]

def print_records(domain: str, records: Dict[str, List[str]]):
    """Pretty print DNS records."""
    print("\n" + "="*70)
    print(f"  DNS RECORDS FOR: {domain}")
    print("="*70)
    
    if not records:
        print("\n  No DNS records found.")
        return
    
    for record_type, values in records.items():
        print(f"\n  {record_type} Records:")
        print("  " + "-"*50)
        for value in values:
            print(f"    {value}")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="DNS Lookup Tool - Query DNS records",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dns_lookup.py example.com                # Get all records
  python dns_lookup.py google.com -t MX           # Get MX records only
  python dns_lookup.py github.com -t A,AAAA,NS    # Get specific records
  python dns_lookup.py -r 8.8.8.8                 # Reverse lookup
  python dns_lookup.py example.com --dmarc        # Check DMARC
        """
    )
    
    parser.add_argument("domain", nargs="?", help="Domain to look up")
    parser.add_argument("-t", "--type", default="all",
                        help="Record type(s) to query (comma-separated)")
    parser.add_argument("-r", "--reverse", help="Reverse DNS lookup for IP")
    parser.add_argument("--dmarc", action="store_true",
                        help="Check DMARC record")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    if not args.domain and not args.reverse:
        parser.print_help()
        sys.exit(1)
    
    try:
        import json
        
        if args.reverse:
            print("\n" + "="*70)
            print(f"  REVERSE DNS LOOKUP FOR: {args.reverse}")
            print("="*70)
            results = reverse_lookup(args.reverse)
            for r in results:
                print(f"  {r}")
            return
        
        if args.dmarc:
            print("\n" + "="*70)
            print(f"  DMARC CHECK FOR: {args.domain}")
            print("="*70)
            dmarc_records = check_dmarc(args.domain)
            if dmarc_records and not dmarc_records[0].startswith('No TXT'):
                print("\n  DMARC Record Found:")
                for r in dmarc_records:
                    print(f"    {r}")
            else:
                print("\n  No DMARC record found.")
            return
        
        # Determine record types to query
        if args.type.lower() == 'all':
            records = get_all_records(args.domain)
        else:
            types = [t.strip().upper() for t in args.type.split(',')]
            records = {}
            for t in types:
                if t in RECORD_TYPES:
                    result = lookup_record(args.domain, t)
                    if result:
                        records[t] = result
        
        print_records(args.domain, records)
        
        # DMARC check
        dmarc = check_dmarc(args.domain)
        if dmarc and not any(x in dmarc[0] for x in ['No TXT', 'Error', 'does not exist']):
            print(f"\n  DMARC Record:")
            print("  " + "-"*50)
            for r in dmarc:
                print(f"    {r}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(records, f, indent=2)
            print(f"\n  Output saved to: {args.output}")
        
    except ImportError:
        print("\n[!] Error: dnspython not installed")
        print("    Install with: pip install dnspython")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
