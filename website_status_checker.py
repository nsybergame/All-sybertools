#!/usr/bin/env python3
"""
WEBSITE STATUS CHECKER
======================

Check if a website is up and running.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

def check_website(url: str, timeout: int = 10) -> dict:
    """
    Check if a website is up.
    
    Args:
        url: URL to check
        timeout: Request timeout
    
    Returns:
        Dictionary with status information
    """
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'is_up': False,
        'status_code': None,
        'response_time': None,
        'ssl_valid': True,
        'redirects': [],
        'error': None
    }
    
    try:
        start_time = time.time()
        
        # Make request
        response = requests.get(
            url, 
            timeout=timeout, 
            allow_redirects=True,
            verify=True
        )
        
        end_time = time.time()
        
        result['status_code'] = response.status_code
        result['response_time'] = round((end_time - start_time) * 1000, 2)  # ms
        result['is_up'] = response.status_code < 400
        result['final_url'] = response.url
        
        # Track redirects
        if response.history:
            result['redirects'] = [r.url for r in response.history]
        
        # Get additional info
        result['server'] = response.headers.get('Server', 'Unknown')
        result['content_type'] = response.headers.get('Content-Type', 'Unknown')
        result['content_length'] = len(response.content)
        
    except requests.exceptions.SSLError as e:
        result['error'] = 'SSL Certificate Error'
        result['ssl_valid'] = False
    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection Failed (Site may be down)'
    except requests.exceptions.Timeout:
        result['error'] = 'Request Timeout'
    except requests.exceptions.TooManyRedirects:
        result['error'] = 'Too Many Redirects'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_multiple_websites(urls: list, timeout: int = 10) -> list:
    """Check multiple websites."""
    results = []
    for url in urls:
        result = check_website(url, timeout)
        results.append(result)
    return results

def print_status(result: dict):
    """Pretty print website status."""
    print("\n" + "="*70)
    print("  WEBSITE STATUS CHECK")
    print("="*70)
    
    # Status indicator
    if result['is_up']:
        status_icon = "✓"
        status_text = "ONLINE"
        status_color = "green"
    else:
        status_icon = "✗"
        status_text = "OFFLINE"
        status_color = "red"
    
    print(f"\n  URL: {result['url']}")
    print(f"  Status: {status_icon} {status_text}")
    
    if result.get('status_code'):
        print(f"  HTTP Status: {result['status_code']}")
    
    if result.get('response_time'):
        print(f"  Response Time: {result['response_time']} ms")
    
    if result.get('final_url') and result['final_url'] != result['url']:
        print(f"  Final URL: {result['final_url']}")
    
    if result.get('redirects'):
        print(f"  Redirects: {' -> '.join(result['redirects'])}")
    
    if result.get('server'):
        print(f"  Server: {result['server']}")
    
    if result.get('content_type'):
        print(f"  Content-Type: {result['content_type']}")
    
    if result.get('content_length'):
        print(f"  Content Length: {result['content_length']:,} bytes")
    
    if not result['ssl_valid']:
        print(f"  SSL: ✗ Invalid Certificate")
    elif result['is_up']:
        print(f"  SSL: ✓ Valid")
    
    if result.get('error'):
        print(f"\n  Error: {result['error']}")
    
    print(f"\n  Checked at: {result['timestamp']}")
    print("="*70)

def main():
    parser = argparse.ArgumentParser(
        description="Website Status Checker - Check if a website is up",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python website_status_checker.py google.com
  python website_status_checker.py https://example.com
  python website_status_checker.py site1.com site2.com site3.com
        """
    )
    
    parser.add_argument("urls", nargs="+", help="URL(s) to check")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("-f", "--file", help="File with URLs to check (one per line)")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    import warnings
    warnings.filterwarnings('ignore')
    
    try:
        urls = args.urls
        
        # Load URLs from file if specified
        if args.file:
            with open(args.file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip()]
                urls = file_urls + urls
        
        if len(urls) == 1:
            result = check_website(urls[0], args.timeout)
            
            if args.json:
                import json
                print(json.dumps(result, indent=2))
            else:
                print_status(result)
        else:
            print(f"\n  Checking {len(urls)} websites...\n")
            
            results = check_multiple_websites(urls, args.timeout)
            
            print("="*70)
            print(f"  {'URL':<35} {'Status':<10} {'Time':<10} {'Code':<5}")
            print("="*70)
            
            for result in results:
                url = result['url'][:33] + '..' if len(result['url']) > 35 else result['url']
                status = "✓ ONLINE" if result['is_up'] else "✗ OFFLINE"
                time_str = f"{result.get('response_time', 0):.0f}ms" if result.get('response_time') else "-"
                code = str(result.get('status_code', '-'))
                
                print(f"  {url:<35} {status:<10} {time_str:<10} {code:<5}")
            
            print("="*70)
            
            # Summary
            online = sum(1 for r in results if r['is_up'])
            offline = len(results) - online
            
            print(f"\n  Summary: {online} online, {offline} offline")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results if len(urls) > 1 else result, f, indent=2)
            print(f"\n  Output saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
