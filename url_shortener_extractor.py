#!/usr/bin/env python3
"""
URL SHORTENER EXTRACTOR
=======================

Extract the original URL from shortened URLs.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
from urllib.parse import urlparse

# Common URL shorteners
SHORTENER_DOMAINS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adfly.at', 'adf.ly', 'bl.ink',
    'short.link', 'rb.gy', 'cutt.ly', 'tiny.cc', 'shorturl.at',
]

def expand_url(short_url: str, timeout: int = 10, max_redirects: int = 20) -> dict:
    """
    Expand a shortened URL to its original destination.
    
    Args:
        short_url: Shortened URL
        timeout: Request timeout
        max_redirects: Maximum redirects to follow
    
    Returns:
        Dictionary with expansion results
    """
    result = {
        'short_url': short_url,
        'original_url': None,
        'redirects': [],
        'final_status': None,
        'error': None
    }
    
    try:
        # Ensure URL has scheme
        if not short_url.startswith(('http://', 'https://')):
            short_url = 'https://' + short_url
        
        session = requests.Session()
        session.max_redirects = max_redirects
        
        response = session.get(
            short_url, 
            timeout=timeout, 
            allow_redirects=True,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (URL Expander)'}
        )
        
        result['original_url'] = response.url
        result['final_status'] = response.status_code
        
        # Track redirect chain
        for resp in response.history:
            result['redirects'].append({
                'url': resp.url,
                'status': resp.status_code
            })
        
        result['redirects'].append({
            'url': response.url,
            'status': response.status_code
        })
        
    except requests.exceptions.TooManyRedirects:
        result['error'] = 'Too many redirects'
    except requests.exceptions.Timeout:
        result['error'] = 'Request timed out'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection failed'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def is_shortener(url: str) -> bool:
    """Check if URL is from a known shortener."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        return domain in SHORTENER_DOMAINS
    except:
        return False

def get_domain_info(url: str) -> dict:
    """Get domain information from URL."""
    try:
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
        }
    except:
        return {}

def main():
    parser = argparse.ArgumentParser(
        description="URL Shortener Extractor - Get original URL from shortened links",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python url_shortener_extractor.py bit.ly/example
  python url_shortener_extractor.py https://tinyurl.com/abc123 -v
        """
    )
    
    parser.add_argument("url", help="Shortened URL to expand")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show redirect chain")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    
    import warnings
    warnings.filterwarnings('ignore')
    
    print("\n" + "="*70)
    print("  URL SHORTENER EXTRACTOR - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        # Check if it's a shortener
        if not is_shortener(args.url):
            print(f"\n  [!] Warning: {args.url} may not be a URL shortener")
        
        print(f"\n  Expanding: {args.url}")
        print("  " + "-"*56)
        
        result = expand_url(args.url, args.timeout)
        
        if result['error']:
            print(f"\n  [!] Error: {result['error']}")
        else:
            print(f"\n  Original URL: {result['original_url']}")
            print(f"  Final Status: {result['final_status']}")
            print(f"  Redirects: {len(result['redirects']) - 1}")
            
            if args.verbose:
                print(f"\n  Redirect Chain:")
                for i, redirect in enumerate(result['redirects']):
                    print(f"    {i+1}. [{redirect['status']}] {redirect['url']}")
            
            # Domain info
            domain_info = get_domain_info(result['original_url'])
            if domain_info:
                print(f"\n  Destination Domain: {domain_info.get('domain', 'N/A')}")
        
        if args.json:
            import json
            print("\n" + json.dumps(result, indent=2))
        
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
