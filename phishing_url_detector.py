#!/usr/bin/env python3
"""
PHISHING URL DETECTOR
=====================

Detect potential phishing URLs.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import re
import argparse
import sys
from urllib.parse import urlparse, unquote
from typing import Dict, List
import ipaddress

# Suspicious keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
    'password', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
    'facebook', 'netflix', 'spotify', 'dropbox', 'linkedin', 'twitter',
    'instagram', 'whatsapp', 'free', 'win', 'winner', 'prize', 'offer',
    'limited', 'urgent', 'alert', 'warning', 'suspended', 'locked',
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.top',
    '.work', '.click', '.link', '.info', '.biz', '.ru', '.cn',
]

# Brand names commonly targeted
BRAND_NAMES = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'netflix', 'spotify', 'dropbox', 'linkedin', 'twitter', 'instagram',
    'whatsapp', 'outlook', 'hotmail', 'gmail', 'yahoo', 'bank',
    'chase', 'wells', 'citi', 'hsbc', 'barclays', 'santander',
]

class PhishingDetector:
    def __init__(self, url: str):
        self.url = url
        self.parsed = urlparse(url if '://' in url else 'http://' + url)
        self.findings = []
        self.score = 0
    
    def analyze(self) -> Dict:
        """Analyze URL for phishing indicators."""
        self._check_ip_address()
        self._check_suspicious_tld()
        self._check_long_url()
        self._check_subdomain_depth()
        self._check_brand_impersonation()
        self._check_suspicious_keywords()
        self._check_encoded_chars()
        self._check_suspicious_chars()
        self._check_https()
        self._check_redirects()
        self._check_at_symbol()
        self._check_port_number()
        
        return {
            'url': self.url,
            'domain': self.parsed.netloc,
            'is_phishing_risk': self.score >= 5,
            'risk_score': self.score,
            'risk_level': self._get_risk_level(),
            'findings': self.findings,
        }
    
    def _check_ip_address(self):
        """Check if domain is an IP address."""
        domain = self.parsed.netloc.split(':')[0]
        try:
            ipaddress.ip_address(domain)
            self.findings.append({
                'type': 'IP_ADDRESS',
                'severity': 'HIGH',
                'message': 'URL uses IP address instead of domain name'
            })
            self.score += 3
        except:
            pass
    
    def _check_suspicious_tld(self):
        """Check for suspicious TLD."""
        domain = self.parsed.netloc.lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                self.findings.append({
                    'type': 'SUSPICIOUS_TLD',
                    'severity': 'MEDIUM',
                    'message': f'Uses suspicious TLD: {tld}'
                })
                self.score += 2
                break
    
    def _check_long_url(self):
        """Check for unusually long URL."""
        if len(self.url) > 100:
            self.findings.append({
                'type': 'LONG_URL',
                'severity': 'MEDIUM',
                'message': f'URL is unusually long ({len(self.url)} characters)'
            })
            self.score += 1
        
        if len(self.parsed.path) > 50:
            self.findings.append({
                'type': 'LONG_PATH',
                'severity': 'LOW',
                'message': 'URL path is unusually long'
            })
            self.score += 1
    
    def _check_subdomain_depth(self):
        """Check for deep subdomain structure."""
        domain = self.parsed.netloc.split(':')[0]
        parts = domain.split('.')
        
        if len(parts) > 4:
            self.findings.append({
                'type': 'DEEP_SUBDOMAIN',
                'severity': 'MEDIUM',
                'message': f'Has {len(parts)} subdomain levels'
            })
            self.score += 2
    
    def _check_brand_impersonation(self):
        """Check for brand name impersonation."""
        domain = self.parsed.netloc.lower()
        path = self.parsed.path.lower()
        
        for brand in BRAND_NAMES:
            if brand in domain:
                # Check if it's the official domain
                official_domains = {
                    'paypal': 'paypal.com',
                    'amazon': 'amazon.com',
                    'apple': 'apple.com',
                    'google': 'google.com',
                    'facebook': 'facebook.com',
                    'microsoft': 'microsoft.com',
                }
                
                official = official_domains.get(brand)
                if official and official not in domain:
                    self.findings.append({
                        'type': 'BRAND_IMPERSONATION',
                        'severity': 'HIGH',
                        'message': f'Possible impersonation of {brand}'
                    })
                    self.score += 3
    
    def _check_suspicious_keywords(self):
        """Check for suspicious keywords."""
        url_lower = self.url.lower()
        found_keywords = []
        
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            self.findings.append({
                'type': 'SUSPICIOUS_KEYWORDS',
                'severity': 'MEDIUM',
                'message': f'Contains suspicious keywords: {", ".join(found_keywords[:5])}'
            })
            self.score += min(len(found_keywords), 3)
    
    def _check_encoded_chars(self):
        """Check for URL-encoded characters."""
        encoded_pattern = r'%[0-9A-Fa-f]{2}'
        encoded_chars = re.findall(encoded_pattern, self.url)
        
        if len(encoded_chars) > 5:
            self.findings.append({
                'type': 'ENCODED_CHARS',
                'severity': 'MEDIUM',
                'message': f'Contains {len(encoded_chars)} encoded characters'
            })
            self.score += 2
    
    def _check_suspicious_chars(self):
        """Check for suspicious characters."""
        if '@' in self.url:
            self.findings.append({
                'type': 'AT_SYMBOL',
                'severity': 'HIGH',
                'message': 'Contains @ symbol which can hide real domain'
            })
            self.score += 3
        
        if '//' in self.parsed.path:
            self.findings.append({
                'type': 'DOUBLE_SLASH',
                'severity': 'MEDIUM',
                'message': 'Contains double slash in path'
            })
            self.score += 1
    
    def _check_https(self):
        """Check for HTTPS."""
        if self.parsed.scheme != 'https':
            self.findings.append({
                'type': 'NO_HTTPS',
                'severity': 'LOW',
                'message': 'Not using HTTPS'
            })
            self.score += 1
    
    def _check_redirects(self):
        """Check for redirect patterns."""
        redirect_patterns = ['redirect', 'url=', 'link=', 'goto', 'return=']
        
        for pattern in redirect_patterns:
            if pattern in self.url.lower():
                self.findings.append({
                    'type': 'REDIRECT_PATTERN',
                    'severity': 'MEDIUM',
                    'message': f'Contains redirect pattern: {pattern}'
                })
                self.score += 2
                break
    
    def _check_at_symbol(self):
        """Check for @ symbol before the first /."""
        url_without_scheme = self.url.replace('://', '', 1)
        if '@' in url_without_scheme.split('/')[0]:
            self.findings.append({
                'type': 'AT_IN_DOMAIN',
                'severity': 'HIGH',
                'message': '@ symbol in domain part - classic phishing technique'
            })
            self.score += 3
    
    def _check_port_number(self):
        """Check for non-standard port."""
        if ':' in self.parsed.netloc:
            port = self.parsed.netloc.split(':')[1]
            if port not in ['80', '443', '8080']:
                self.findings.append({
                    'type': 'NON_STANDARD_PORT',
                    'severity': 'LOW',
                    'message': f'Uses non-standard port: {port}'
                })
                self.score += 1
    
    def _get_risk_level(self) -> str:
        """Get risk level based on score."""
        if self.score >= 10:
            return 'CRITICAL'
        elif self.score >= 7:
            return 'HIGH'
        elif self.score >= 4:
            return 'MEDIUM'
        elif self.score >= 2:
            return 'LOW'
        return 'SAFE'

def main():
    parser = argparse.ArgumentParser(
        description="Phishing URL Detector - Detect potential phishing URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing_url_detector.py "http://google.com.login.verify.example.com"
  python phishing_url_detector.py "https://example.com" -j
        """
    )
    
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    try:
        detector = PhishingDetector(args.url)
        result = detector.analyze()
        
        if args.json:
            import json
            print(json.dumps(result, indent=2))
        else:
            print("\n" + "="*70)
            print("  PHISHING URL DETECTOR")
            print("="*70)
            
            print(f"\n  URL: {result['url']}")
            print(f"  Domain: {result['domain']}")
            print(f"\n  Risk Level: {result['risk_level']}")
            print(f"  Risk Score: {result['score']}/15")
            
            if result['findings']:
                print(f"\n  Findings ({len(result['findings'])}):")
                print("  " + "-"*66)
                
                for finding in result['findings']:
                    severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                    icon = severity_icon.get(finding['severity'], '⚪')
                    print(f"\n    {icon} [{finding['severity']}] {finding['type']}")
                    print(f"       {finding['message']}")
            
            print("\n" + "="*70)
            
            if result['is_phishing_risk']:
                print("\n  ⚠️  WARNING: This URL shows signs of being a PHISHING URL!")
                print("  Exercise caution and verify the source before visiting.\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
