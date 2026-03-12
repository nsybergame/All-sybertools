#!/usr/bin/env python3
"""
WEB TECHNOLOGY DETECTOR
=======================

Detect technologies used by websites.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests beautifulsoup4

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
import re

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Technology signatures
TECH_SIGNATURES = {
    # CMS
    'WordPress': [
        r'wp-content',
        r'wp-includes',
        r'WordPress',
    ],
    'Drupal': [
        r'Drupal',
        r'/sites/default/files',
    ],
    'Joomla': [
        r'Joomla',
        r'/media/jui/',
    ],
    'Magento': [
        r'Magento',
        r'/skin/frontend/',
    ],
    'Shopify': [
        r'shopify',
        r'myshopify\.com',
    ],
    
    # Frameworks
    'React': [
        r'react\.js',
        r'react-dom',
        r'_reactRootContainer',
        r'data-reactid',
    ],
    'Vue.js': [
        r'vue\.js',
        r'Vue\.',
        r'__vue__',
    ],
    'Angular': [
        r'angular\.js',
        r'ng-app',
        r'ng-version',
    ],
    'jQuery': [
        r'jquery',
        r'\$\(document\)',
    ],
    'Bootstrap': [
        r'bootstrap\.css',
        r'bootstrap\.js',
    ],
    'Tailwind CSS': [
        r'tailwindcss',
        r'tailwind\.css',
    ],
    'Next.js': [
        r'__NEXT_DATA__',
        r'/_next/',
    ],
    'Express.js': [
        r'X-Powered-By:\s*Express',
    ],
    'Django': [
        r'csrfmiddlewaretoken',
        r'__admin_media_prefix__',
    ],
    'Laravel': [
        r'laravel',
        r'X-Powered-By:\s*Laravel',
    ],
    'Flask': [
        r'flask',
    ],
    
    # Analytics & Tracking
    'Google Analytics': [
        r'google-analytics\.com',
        r'gtag\(',
        r'UA-\d+',
    ],
    'Google Tag Manager': [
        r'googletagmanager\.com',
        r'GTM-',
    ],
    'Facebook Pixel': [
        r'connect\.facebook\.net.*fbevents',
        r'fbq\(',
    ],
    'Hotjar': [
        r'hotjar\.com',
        r'hj\(',
    ],
    
    # Hosting & CDN
    'Cloudflare': [
        r'cloudflare',
        r'cf-ray',
        r'__cfduid',
    ],
    'AWS': [
        r'amazonaws\.com',
        r'aws',
    ],
    'Netlify': [
        r'netlify',
    ],
    'Vercel': [
        r'vercel',
        r'__vercel',
    ],
    'GitHub Pages': [
        r'github\.io',
    ],
    
    # Security
    'reCAPTCHA': [
        r'recaptcha',
        r'g-recaptcha',
    ],
    'hCaptcha': [
        r'hcaptcha',
    ],
    'Cloudflare WAF': [
        r'cf-ray',
    ],
    
    # Databases (usually detected via error pages or headers)
    'MySQL': [
        r'mysql',
    ],
    'PostgreSQL': [
        r'postgresql',
        r'pg_',
    ],
    'MongoDB': [
        r'mongodb',
    ],
    'Redis': [
        r'redis',
    ],
    
    # Other
    'Nginx': [
        r'nginx',
    ],
    'Apache': [
        r'apache',
    ],
    'IIS': [
        r'IIS',
        r'Microsoft-IIS',
    ],
}

def detect_technologies(url: str, timeout: int = 10) -> dict:
    """
    Detect technologies used by a website.
    
    Args:
        url: Website URL
        timeout: Request timeout
    
    Returns:
        Dictionary with detected technologies
    """
    result = {
        'url': url,
        'technologies': {},
        'headers': {},
        'cookies': {},
        'meta_tags': {},
    }
    
    try:
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.get(
            url, 
            timeout=timeout, 
            headers={'User-Agent': 'Mozilla/5.0 (Technology Detector)'},
            verify=False
        )
        
        content = response.text
        headers = dict(response.headers)
        cookies = dict(response.cookies)
        
        result['headers'] = {k.lower(): v for k, v in headers.items()}
        result['cookies'] = cookies
        
        # Parse with BeautifulSoup
        soup = BeautifulSoup(content, 'html.parser') if BS4_AVAILABLE else None
        
        # Extract meta tags
        if soup:
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content_attr = meta.get('content')
                if name and content_attr:
                    result['meta_tags'][name] = content_attr
        
        # Combine all text for pattern matching
        all_text = content + ' '.join([f'{k}: {v}' for k, v in headers.items()])
        
        # Check each technology
        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    if tech not in result['technologies']:
                        result['technologies'][tech] = {
                            'category': get_category(tech),
                            'found': True
                        }
                    break
        
        # Additional header-based detection
        server = headers.get('Server', headers.get('server', ''))
        if server:
            if 'nginx' in server.lower():
                result['technologies']['Nginx'] = {'category': 'Server', 'version': server}
            elif 'apache' in server.lower():
                result['technologies']['Apache'] = {'category': 'Server', 'version': server}
            elif 'microsoft-iis' in server.lower():
                result['technologies']['IIS'] = {'category': 'Server', 'version': server}
        
        powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if powered_by:
            result['technologies']['X-Powered-By'] = {'category': 'Backend', 'value': powered_by}
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def get_category(tech: str) -> str:
    """Get technology category."""
    categories = {
        'CMS': ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify'],
        'Frontend Framework': ['React', 'Vue.js', 'Angular', 'jQuery'],
        'CSS Framework': ['Bootstrap', 'Tailwind CSS'],
        'SSR Framework': ['Next.js'],
        'Backend Framework': ['Express.js', 'Django', 'Laravel', 'Flask'],
        'Analytics': ['Google Analytics', 'Google Tag Manager', 'Facebook Pixel', 'Hotjar'],
        'CDN/Hosting': ['Cloudflare', 'AWS', 'Netlify', 'Vercel', 'GitHub Pages'],
        'Security': ['reCAPTCHA', 'hCaptcha', 'Cloudflare WAF'],
        'Server': ['Nginx', 'Apache', 'IIS'],
    }
    
    for category, techs in categories.items():
        if tech in techs:
            return category
    
    return 'Other'

def main():
    parser = argparse.ArgumentParser(
        description="Web Technology Detector - Detect technologies used by websites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_technology_detector.py https://example.com
  python web_technology_detector.py github.com -j
        """
    )
    
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show more details")
    
    args = parser.parse_args()
    
    import warnings
    warnings.filterwarnings('ignore')
    
    print("\n" + "="*70)
    print("  WEB TECHNOLOGY DETECTOR - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        print(f"\n  Analyzing: {args.url}")
        print("  " + "-"*56)
        
        result = detect_technologies(args.url, args.timeout)
        
        if 'error' in result:
            print(f"\n  [!] Error: {result['error']}")
            sys.exit(1)
        
        # Group by category
        by_category = {}
        for tech, info in result['technologies'].items():
            cat = info.get('category', 'Other')
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(tech)
        
        print("\n  Detected Technologies:")
        for category, techs in sorted(by_category.items()):
            print(f"\n    [{category}]")
            for tech in techs:
                print(f"      ✓ {tech}")
        
        if args.verbose:
            print(f"\n  HTTP Headers:")
            for k, v in list(result['headers'].items())[:10]:
                print(f"    {k}: {v[:50]}{'...' if len(v) > 50 else ''}")
            
            if result['cookies']:
                print(f"\n  Cookies: {len(result['cookies'])}")
            
            if result['meta_tags']:
                print(f"\n  Meta Tags:")
                for k, v in list(result['meta_tags'].items())[:5]:
                    print(f"    {k}: {v[:40]}{'...' if len(v) > 40 else ''}")
        
        if args.json:
            print("\n" + json.dumps(result, indent=2))
        
        print(f"\n  Total: {len(result['technologies'])} technologies detected")
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
