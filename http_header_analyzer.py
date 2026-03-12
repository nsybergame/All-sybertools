#!/usr/bin/env python3
"""
HTTP HEADER ANALYZER
====================

Analyze HTTP headers for a website.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Use responsibly and respect website terms of service.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
from datetime import datetime
from urllib.parse import urlparse

# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'Enforces HTTPS connections',
        'severity': 'high',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    'Content-Security-Policy': {
        'description': 'Prevents XSS and injection attacks',
        'severity': 'high',
        'recommendation': 'Add CSP header with appropriate directives'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME type sniffing',
        'severity': 'medium',
        'recommendation': 'Add: X-Content-Type-Options: nosniff'
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks',
        'severity': 'medium',
        'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
    },
    'X-XSS-Protection': {
        'description': 'Enables XSS filter (deprecated but still useful)',
        'severity': 'low',
        'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
    },
    'Referrer-Policy': {
        'description': 'Controls referrer information',
        'severity': 'low',
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
        'description': 'Controls browser features',
        'severity': 'medium',
        'recommendation': 'Add Permissions-Policy with restricted features'
    },
    'Cross-Origin-Opener-Policy': {
        'description': 'Isolates browsing context',
        'severity': 'medium',
        'recommendation': 'Add: Cross-Origin-Opener-Policy: same-origin'
    },
    'Cross-Origin-Resource-Policy': {
        'description': 'Controls cross-origin resource sharing',
        'severity': 'medium',
        'recommendation': 'Add: Cross-Origin-Resource-Policy: same-origin'
    },
}

def analyze_headers(url: str, timeout: int = 10) -> dict:
    """
    Fetch and analyze HTTP headers for a URL.
    
    Args:
        url: URL to analyze
        timeout: Request timeout
    
    Returns:
        Dictionary with headers and analysis
    """
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        headers = dict(response.headers)
        
        # Also try GET if HEAD returns limited headers
        if len(headers) < 5:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, stream=True)
            headers = dict(response.headers)
            response.close()
        
        return {
            'url': response.url,
            'status_code': response.status_code,
            'headers': headers,
            'history': [r.url for r in response.history],
            'server': headers.get('Server', 'Unknown'),
        }
    except requests.exceptions.SSLError:
        return {'error': 'SSL Certificate Error'}
    except requests.exceptions.ConnectionError:
        return {'error': 'Connection Failed'}
    except requests.exceptions.Timeout:
        return {'error': 'Request Timeout'}
    except Exception as e:
        return {'error': str(e)}

def check_security_headers(headers: dict) -> list:
    """Check for presence and configuration of security headers."""
    results = []
    
    for header, info in SECURITY_HEADERS.items():
        present = header in headers
        value = headers.get(header, 'Not Set')
        
        results.append({
            'header': header,
            'present': present,
            'value': value if present else 'Not Set',
            'description': info['description'],
            'severity': info['severity'],
            'recommendation': info['recommendation'] if not present else None
        })
    
    return results

def calculate_security_score(security_results: list) -> int:
    """Calculate security score based on headers."""
    score = 0
    max_score = 0
    
    severity_weights = {'high': 20, 'medium': 10, 'low': 5}
    
    for result in security_results:
        weight = severity_weights.get(result['severity'], 5)
        max_score += weight
        if result['present']:
            score += weight
    
    return int((score / max_score) * 100) if max_score > 0 else 0

def print_analysis(result: dict):
    """Pretty print header analysis."""
    print("\n" + "="*70)
    print("  HTTP HEADER ANALYSIS")
    print("="*70)
    
    if 'error' in result:
        print(f"\n  [!] Error: {result['error']}")
        return
    
    print(f"\n  URL: {result['url']}")
    print(f"  Status Code: {result['status_code']}")
    print(f"  Server: {result['server']}")
    
    if result['history']:
        print(f"  Redirects: {' -> '.join(result['history'])}")
    
    # Print all headers
    print(f"\n  Response Headers ({len(result['headers'])} headers):")
    print("  " + "-"*66)
    for header, value in result['headers'].items():
        # Truncate long values
        display_value = value if len(value) <= 50 else value[:47] + '...'
        print(f"    {header}: {display_value}")
    
    # Security analysis
    security_results = check_security_headers(result['headers'])
    security_score = calculate_security_score(security_results)
    
    print(f"\n  Security Headers Analysis (Score: {security_score}/100):")
    print("  " + "-"*66)
    
    for res in security_results:
        icon = "✓" if res['present'] else "✗"
        severity_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(res['severity'], '⚪')
        
        print(f"\n    {icon} {severity_icon} {res['header']}")
        print(f"       {res['description']}")
        if res['present']:
            print(f"       Value: {res['value'][:50]}")
        else:
            print(f"       Recommendation: {res['recommendation']}")
    
    # Summary
    missing = [r for r in security_results if not r['present']]
    high_missing = [r for r in missing if r['severity'] == 'high']
    
    print(f"\n  Summary:")
    print(f"    - Total headers: {len(result['headers'])}")
    print(f"    - Security score: {security_score}/100")
    print(f"    - Missing high severity headers: {len(high_missing)}")
    
    if security_score >= 80:
        print("    - Rating: Good ✓")
    elif security_score >= 60:
        print("    - Rating: Moderate ⚠️")
    else:
        print("    - Rating: Poor ✗")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="HTTP Header Analyzer - Check website security headers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python http_header_analyzer.py example.com
  python http_header_analyzer.py https://google.com
        """
    )
    
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    import warnings
    warnings.filterwarnings('ignore')
    
    try:
        print(f"\n  Analyzing {args.url}...")
        result = analyze_headers(args.url, args.timeout)
        
        if args.json:
            import json
            output = json.dumps(result, indent=2)
            print(output)
        else:
            print_analysis(result)
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n  Output saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
