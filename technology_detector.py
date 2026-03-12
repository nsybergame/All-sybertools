#!/usr/bin/env python3
"""
TECHNOLOGY DETECTOR
===================

Detect technologies used by a website.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install requests beautifulsoup4

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
        r'/xmlrpc.php',
    ],
    'Drupal': [
        r'Drupal',
        r'/sites/default/files',
        r'Drupal\.settings',
    ],
    'Joomla': [
        r'Joomla',
        r'/media/jui/',
        r'/administrator/',
    ],
    'Magento': [
        r'Magento',
        r'/skin/frontend/',
        r'/js/mage/',
    ],
    'Shopify': [
        r'Shopify',
        r'cdn\.shopify\.com',
        r'myshopify\.com',
    ],
    
    # Frameworks
    'React': [
        r'react',
        r'react-dom',
        r'_reactRootContainer',
        r'data-reactroot',
    ],
    'Vue.js': [
        r'vue\.js',
        r'Vue\.js',
        r'v-cloak',
        r'data-v-',
    ],
    'Angular': [
        r'ng-version',
        r'angular',
        r'ng-app',
    ],
    'jQuery': [
        r'jquery',
        r'jQuery',
    ],
    'Bootstrap': [
        r'bootstrap',
        r'Bootstrap',
    ],
    'Next.js': [
        r'_next/',
        r'__NEXT_DATA__',
    ],
    'Express': [
        r'Express',
        r'X-Powered-By: Express',
    ],
    'Django': [
        r'csrftoken',
        r'django',
        r'__admin__',
    ],
    'Laravel': [
        r'Laravel',
        r'laravel',
    ],
    'Ruby on Rails': [
        r'Rails',
        r'ruby',
        r'_rails',
    ],
    'ASP.NET': [
        r'asp\.net',
        r'ASP\.NET',
        r'__VIEWSTATE',
    ],
    
    # Servers
    'Nginx': [r'nginx'],
    'Apache': [r'Apache'],
    'IIS': [r'Microsoft-IIS'],
    'Cloudflare': [r'cloudflare', r'cf-ray'],
    
    # Databases (via headers/errors)
    'MySQL': [r'MySQL', r'mysql'],
    'PostgreSQL': [r'PostgreSQL', r'postgres'],
    'MongoDB': [r'MongoDB', r'mongo'],
    
    # Analytics
    'Google Analytics': [r'google-analytics\.com', r'gtag', r'UA-'],
    'Google Tag Manager': [r'googletagmanager\.com', r'GTM-'],
    'Facebook Pixel': [r'connect\.facebook\.net', r'fbq'],
    
    # CDN
    'CloudFront': [r'CloudFront', r'cloudfront'],
    'Akamai': [r'akamai', r'Akamai'],
    'Fastly': [r'Fastly', r'fastly'],
    
    # Security
    'reCAPTCHA': [r'recaptcha', r'g-recaptcha'],
    'hCaptcha': [r'hcaptcha'],
    'Cloudflare WAF': [r'cf-ray', r'__cf_bm'],
}

class TechnologyDetector:
    def __init__(self, url: str, timeout: int = 10):
        self.url = url if url.startswith('http') else 'https://' + url
        self.timeout = timeout
        self.detected = {}
        self.response = None
        self.soup = None
    
    def fetch(self):
        """Fetch the webpage."""
        try:
            self.response = requests.get(
                self.url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Technology Detector)'}
            )
            if BS4_AVAILABLE:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            return True
        except Exception as e:
            print(f"Error fetching page: {e}")
            return False
    
    def detect(self):
        """Detect technologies."""
        if not self.response:
            return {}
        
        content = self.response.text
        headers = dict(self.response.headers)
        
        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                # Check in content
                if re.search(pattern, content, re.IGNORECASE):
                    self.detected[tech] = self.detected.get(tech, [])
                    self.detected[tech].append(f'Pattern found: {pattern}')
                
                # Check in headers
                for header, value in headers.items():
                    if re.search(pattern, f'{header}: {value}', re.IGNORECASE):
                        self.detected[tech] = self.detected.get(tech, [])
                        self.detected[tech].append(f'Header: {header}')
        
        # Check meta tags
        if self.soup:
            for meta in self.soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content_attr = meta.get('content', '').lower()
                
                for tech, patterns in TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, f'{name} {content_attr}', re.IGNORECASE):
                            self.detected[tech] = self.detected.get(tech, [])
                            self.detected[tech].append('Meta tag')
        
        # Check script sources
        if self.soup:
            for script in self.soup.find_all('script'):
                src = script.get('src', '')
                if src:
                    for tech, patterns in TECH_SIGNATURES.items():
                        for pattern in patterns:
                            if re.search(pattern, src, re.IGNORECASE):
                                self.detected[tech] = self.detected.get(tech, [])
                                self.detected[tech].append(f'Script: {src[:50]}')
        
        return self.detected
    
    def get_server_info(self):
        """Get server information from headers."""
        if not self.response:
            return {}
        
        headers = self.response.headers
        
        return {
            'Server': headers.get('Server', 'Unknown'),
            'X-Powered-By': headers.get('X-Powered-By', 'Unknown'),
            'X-AspNet-Version': headers.get('X-AspNet-Version', 'Unknown'),
            'Content-Type': headers.get('Content-Type', 'Unknown'),
        }

def main():
    parser = argparse.ArgumentParser(
        description="Technology Detector - Detect technologies used by websites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python technology_detector.py example.com
  python technology_detector.py https://github.com
        """
    )
    
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not REQUESTS_AVAILABLE:
        print("\n[!] requests required. Install with: pip install requests")
        sys.exit(1)
    
    import warnings
    warnings.filterwarnings('ignore')
    
    try:
        detector = TechnologyDetector(args.url, args.timeout)
        
        print("\n" + "="*70)
        print("  TECHNOLOGY DETECTOR - CyberSecurity Tools Hub")
        print("="*70)
        print(f"\n  Target: {detector.url}")
        
        print("\n  Fetching page...")
        
        if detector.fetch():
            detected = detector.detect()
            server_info = detector.get_server_info()
            
            if args.json:
                import json
                result = {
                    'url': detector.url,
                    'server': server_info,
                    'technologies': detected
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n  Server Information:")
                print("  " + "-"*66)
                for key, value in server_info.items():
                    if value != 'Unknown':
                        print(f"    {key}: {value}")
                
                if detected:
                    print(f"\n  Detected Technologies ({len(detected)}):")
                    print("  " + "-"*66)
                    
                    # Group by category
                    categories = {
                        'CMS': ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify'],
                        'Frameworks': ['React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap', 'Next.js', 'Express', 'Django', 'Laravel', 'Ruby on Rails', 'ASP.NET'],
                        'Servers': ['Nginx', 'Apache', 'IIS', 'Cloudflare'],
                        'Analytics': ['Google Analytics', 'Google Tag Manager', 'Facebook Pixel'],
                        'CDN': ['CloudFront', 'Akamai', 'Fastly'],
                        'Security': ['reCAPTCHA', 'hCaptcha', 'Cloudflare WAF'],
                    }
                    
                    for category, techs in categories.items():
                        found = [t for t in techs if t in detected]
                        if found:
                            print(f"\n    {category}:")
                            for tech in found:
                                print(f"      • {tech}")
                    
                    # Uncategorized
                    categorized = set()
                    for techs in categories.values():
                        categorized.update(techs)
                    
                    uncategorized = [t for t in detected if t not in categorized]
                    if uncategorized:
                        print(f"\n    Other:")
                        for tech in uncategorized:
                            print(f"      • {tech}")
                else:
                    print("\n  No technologies detected.")
            
            print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
