#!/usr/bin/env python3
"""
SUBDOMAIN SCANNER
=================

Discover subdomains of a website using wordlist and DNS resolution.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only scan domains you own or have explicit permission to test.
Unauthorized subdomain enumeration may be considered reconnaissance for attacks.

Requirements:
    pip install dnspython requests

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import socket
import concurrent.futures
from datetime import datetime
from typing import List, Set

try:
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'blog', 'api', 'dev', 'staging', 'test', 'admin', 'portal', 'secure',
    'vpn', 'remote', 'cdn', 'static', 'assets', 'img', 'images', 'video',
    'shop', 'store', 'app', 'mobile', 'm', 'beta', 'alpha', 'demo', 'sandbox',
    'support', 'help', 'docs', 'wiki', 'forum', 'community', 'news', 'press',
    'careers', 'jobs', 'investor', 'partners', 'affiliate', 'ads', 'marketing',
    'email', 'mx', 'imap', 'pop3', 'webdisk', 'autodiscover', 'autoconfig',
    'cpanel', 'whm', 'plesk', 'zpanel', 'ispconfig', 'centreon', 'nagios',
    'zabbix', 'grafana', 'kibana', 'jenkins', 'gitlab', 'github', 'bitbucket',
    'jira', 'confluence', 'slack', 'mattermost', 'rocketchat', 'discord',
    'erp', 'crm', 'sap', 'oracle', 'mysql', 'postgres', 'mongodb', 'redis',
    'elasticsearch', 'solr', 'rabbitmq', 'kafka', 'zookeeper', 'consul',
    'dashboard', 'console', 'control', 'manage', 'monitor', 'status', 'health',
    'auth', 'login', 'sso', 'oauth', 'saml', 'ldap', 'radius', 'kerberos',
    'db', 'database', 'backup', 'archive', 'log', 'logs', 'analytics',
    'tracking', 'pixel', 'ads', 'adserver', 'analytics', 'metrics', 'data',
    'api1', 'api2', 'api-v1', 'api-v2', 'rest', 'graphql', 'soap', 'wsdl',
    'internal', 'intranet', 'extranet', 'private', 'public', 'external',
    'cloud', 'aws', 'azure', 'gcp', 's3', 'ec2', 'lambda', 'functions',
    'edu', 'learn', 'training', 'course', 'webinar', 'event', 'conference',
    'store', 'shop', 'ecommerce', 'cart', 'checkout', 'payment', 'billing',
    'account', 'profile', 'user', 'users', 'member', 'members', 'client',
]

def resolve_subdomain(subdomain: str, domain: str, timeout: float = 2.0) -> dict:
    """
    Resolve a subdomain to check if it exists.
    
    Args:
        subdomain: Subdomain prefix
        domain: Main domain
        timeout: Resolution timeout
    
    Returns:
        Dictionary with subdomain info or None
    """
    full_domain = f"{subdomain}.{domain}"
    
    try:
        # Try DNS resolution
        if DNSPYTHON_AVAILABLE:
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
        else:
            # Fallback to socket
            ip = socket.gethostbyname(full_domain)
            ips = [ip]
        
        return {
            'subdomain': full_domain,
            'ips': ips,
            'status': 'active'
        }
    except:
        return None

def scan_subdomains(domain: str, wordlist: List[str], threads: int = 50, 
                    timeout: float = 2.0, verbose: bool = False) -> List[dict]:
    """
    Scan for subdomains using a wordlist.
    
    Args:
        domain: Target domain
        wordlist: List of subdomain prefixes to try
        threads: Number of concurrent threads
        timeout: Resolution timeout
        verbose: Print progress
    
    Returns:
        List of found subdomains
    """
    found = []
    
    print(f"\n{'='*70}")
    print(f"  SUBDOMAIN SCANNER - CyberSecurity Tools Hub")
    print(f"{'='*70}")
    print(f"  Target: {domain}")
    print(f"  Wordlist: {len(wordlist)} subdomains")
    print(f"  Threads: {threads}")
    print(f"{'='*70}\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_subdomain, word, domain, timeout): word 
                   for word in wordlist}
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if verbose and completed % 50 == 0:
                print(f"  Progress: {completed}/{len(wordlist)} checked...")
            
            result = future.result()
            if result:
                found.append(result)
                print(f"  [+] Found: {result['subdomain']} -> {', '.join(result['ips'])}")
    
    return sorted(found, key=lambda x: x['subdomain'])

def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[!] Error loading wordlist: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Scanner - Discover subdomains of a website",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_scanner.py example.com
  python subdomain_scanner.py target.com -w wordlist.txt
  python subdomain_scanner.py domain.com -t 100 -v
        """
    )
    
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="DNS timeout in seconds (default: 2.0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress updates")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  WARNING: Only scan domains you own or have permission to test!")
    print("!"*60 + "\n")
    
    try:
        # Load wordlist
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
            if not wordlist:
                print("[!] No valid subdomains in wordlist")
                sys.exit(1)
        else:
            wordlist = COMMON_SUBDOMAINS
            print(f"  Using built-in wordlist ({len(wordlist)} subdomains)")
        
        # Run scan
        start_time = datetime.now()
        found = scan_subdomains(args.domain, wordlist, args.threads, 
                                args.timeout, args.verbose)
        end_time = datetime.now()
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"  SCAN COMPLETE")
        print(f"  Duration: {end_time - start_time}")
        print(f"  Subdomains found: {len(found)}")
        print(f"{'='*70}\n")
        
        if found:
            print("  FOUND SUBDOMAINS:")
            print("  " + "-"*66)
            print(f"  {'Subdomain':<40} {'IP Addresses':<25}")
            print("  " + "-"*66)
            
            for sub in found:
                ips = ', '.join(sub['ips'][:2])
                if len(sub['ips']) > 2:
                    ips += '...'
                print(f"  {sub['subdomain']:<40} {ips:<25}")
        
        # Save results
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    'domain': args.domain,
                    'scan_time': str(end_time - start_time),
                    'found': len(found),
                    'subdomains': found
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
