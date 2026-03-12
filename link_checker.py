#!/usr/bin/env python3
"""
LINK CHECKER
============

Find broken links on a webpage.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Respect website terms of service and rate limits.

Requirements:
    pip install requests beautifulsoup4

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

def get_links_from_page(url: str, timeout: int = 10) -> list:
    """
    Extract all links from a webpage.
    
    Args:
        url: URL to scrape
        timeout: Request timeout
    
    Returns:
        List of link dictionaries
    """
    if not BS4_AVAILABLE:
        print("[!] BeautifulSoup not installed. Install with: pip install beautifulsoup4")
        return []
    
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        links = []
        base_url = urlparse(url)
        
        for tag in soup.find_all(['a', 'link', 'img', 'script', 'source']):
            attr = None
            if tag.name == 'a':
                attr = 'href'
            elif tag.name == 'link':
                attr = 'href'
            elif tag.name == 'img':
                attr = 'src'
            elif tag.name == 'script':
                attr = 'src'
            elif tag.name == 'source':
                attr = 'src'
            
            if attr and tag.get(attr):
                link = tag.get(attr)
                
                # Skip fragments and javascript
                if link.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                
                # Convert relative to absolute URL
                absolute_url = urljoin(url, link)
                
                # Check if same domain
                parsed = urlparse(absolute_url)
                is_internal = parsed.netloc == base_url.netloc
                
                links.append({
                    'url': absolute_url,
                    'text': tag.get_text(strip=True) if tag.name == 'a' else tag.name,
                    'type': tag.name,
                    'internal': is_internal
                })
        
        return links
    
    except Exception as e:
        return [{'error': str(e)}]

def check_link(url: str, timeout: int = 5) -> dict:
    """
    Check if a link is working.
    
    Args:
        url: URL to check
        timeout: Request timeout
    
    Returns:
        Dictionary with link status
    """
    try:
        # Try HEAD request first (faster)
        response = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        status_code = response.status_code
        
        # Some servers don't support HEAD, try GET
        if status_code == 405:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, stream=True)
            status_code = response.status_code
            response.close()
        
        return {
            'url': url,
            'status_code': status_code,
            'status': 'OK' if 200 <= status_code < 400 else 'BROKEN',
            'redirect': response.url if response.url != url else None
        }
    
    except requests.exceptions.Timeout:
        return {'url': url, 'status_code': 0, 'status': 'TIMEOUT'}
    except requests.exceptions.ConnectionError:
        return {'url': url, 'status_code': 0, 'status': 'CONNECTION_ERROR'}
    except requests.exceptions.TooManyRedirects:
        return {'url': url, 'status_code': 0, 'status': 'TOO_MANY_REDIRECTS'}
    except Exception as e:
        return {'url': url, 'status_code': 0, 'status': 'ERROR', 'error': str(e)}

def main():
    parser = argparse.ArgumentParser(
        description="Link Checker - Find broken links on a webpage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python link_checker.py https://example.com
  python link_checker.py https://example.com --external
  python link_checker.py https://example.com -t 20
        """
    )
    
    parser.add_argument("url", help="URL to check")
    parser.add_argument("--external", action="store_true",
                        help="Check external links only")
    parser.add_argument("--internal", action="store_true",
                        help="Check internal links only")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Request timeout in seconds")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    import warnings
    warnings.filterwarnings('ignore')
    
    print("\n" + "="*70)
    print("  LINK CHECKER - CyberSecurity Tools Hub")
    print("="*70)
    
    if not BS4_AVAILABLE:
        print("\n[!] BeautifulSoup required. Install with: pip install beautifulsoup4")
        sys.exit(1)
    
    try:
        print(f"\n  Fetching links from: {args.url}")
        
        # Get all links
        links = get_links_from_page(args.url, args.timeout)
        
        if not links or 'error' in links[0]:
            print(f"\n[!] Error: {links[0].get('error', 'No links found')}")
            sys.exit(1)
        
        # Filter links
        if args.external:
            links = [l for l in links if not l.get('internal')]
        elif args.internal:
            links = [l for l in links if l.get('internal')]
        
        # Remove duplicates
        unique_urls = list(set(l['url'] for l in links))
        
        print(f"  Found {len(unique_urls)} unique links to check\n")
        
        # Check links
        results = {
            'ok': [],
            'broken': [],
            'redirects': []
        }
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_link, url, args.timeout): url for url in unique_urls}
            
            for future in as_completed(futures):
                result = future.result()
                
                if result['status'] == 'OK':
                    results['ok'].append(result)
                    if result.get('redirect'):
                        results['redirects'].append(result)
                else:
                    results['broken'].append(result)
                    print(f"  [✗] BROKEN: {result['url'][:60]} - {result['status']}")
        
        # Print summary
        print(f"\n{'='*70}")
        print("  RESULTS SUMMARY")
        print(f"{'='*70}")
        print(f"\n  Total links checked: {len(unique_urls)}")
        print(f"  ✓ Working: {len(results['ok'])}")
        print(f"  ✗ Broken: {len(results['broken'])}")
        print(f"  ↻ Redirects: {len(results['redirects'])}")
        
        if results['broken']:
            print(f"\n  Broken Links:")
            print("  " + "-"*66)
            for link in results['broken']:
                print(f"    {link['status']}: {link['url']}")
        
        if results['redirects']:
            print(f"\n  Redirects:")
            print("  " + "-"*66)
            for link in results['redirects']:
                print(f"    {link['url'][:50]} -> {link['redirect'][:50]}")
        
        print("\n" + "="*70)
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"  Results saved to: {args.output}\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
