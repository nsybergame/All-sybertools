#!/usr/bin/env python3
"""
COOKIE ANALYZER
===============

Analyze HTTP cookies for security issues.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
from datetime import datetime
from http.cookies import SimpleCookie
from typing import Dict, List
import re

# Security flags to check
SECURITY_FLAGS = {
    'Secure': 'Cookie only sent over HTTPS',
    'HttpOnly': 'Cookie not accessible via JavaScript',
    'SameSite': 'Controls cross-site request behavior',
}

SAME_SITE_VALUES = {
    'Strict': 'Most secure - cookie only sent in first-party context',
    'Lax': 'Moderate - allows some cross-site usage',
    'None': 'Least secure - allows all cross-site usage'
}

class CookieAnalyzer:
    def __init__(self):
        self.cookies = []
    
    def parse_cookie_string(self, cookie_string: str):
        """Parse a cookie string."""
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_string)
        except:
            # Try alternate parsing
            for pair in cookie_string.split(';'):
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    self.cookies.append({
                        'name': key,
                        'value': value,
                        'attributes': {}
                    })
            return
        
        for key, morsel in cookie.items():
            self.cookies.append({
                'name': key,
                'value': morsel.value,
                'attributes': dict(morsel.items()) if morsel.items() else {}
            })
    
    def analyze_cookie(self, cookie: Dict) -> Dict:
        """Analyze a single cookie for security issues."""
        issues = []
        recommendations = []
        
        name = cookie['name'].lower()
        value = cookie['value']
        attrs = cookie.get('attributes', {})
        
        # Check for sensitive cookie names
        sensitive_names = ['session', 'token', 'auth', 'jwt', 'id', 'user', 'pass', 'secret', 'key']
        is_sensitive = any(s in name for s in sensitive_names)
        
        # Check security flags
        has_secure = 'secure' in [k.lower() for k in attrs.keys()]
        has_httponly = 'httponly' in [k.lower() for k in attrs.keys()]
        has_samesite = any('samesite' in k.lower() for k in attrs.keys())
        
        # Security issues
        if is_sensitive:
            if not has_secure:
                issues.append('Sensitive cookie missing Secure flag')
                recommendations.append('Add Secure flag')
            
            if not has_httponly:
                issues.append('Sensitive cookie missing HttpOnly flag')
                recommendations.append('Add HttpOnly flag')
        
        if not has_samesite:
            issues.append('Cookie missing SameSite attribute')
            recommendations.append('Add SameSite=Strict or SameSite=Lax')
        
        # Check for weak SameSite
        for k, v in attrs.items():
            if 'samesite' in k.lower() and v.lower() == 'none':
                issues.append('SameSite=None allows cross-site usage')
                recommendations.append('Consider using SameSite=Strict or Lax')
        
        # Check for sensitive data in value
        sensitive_patterns = [
            (r'\b[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b', 'Possible JWT token'),
            (r'\b\d{13,}\b', 'Possible timestamp'),
            (r'\b[a-f0-9]{32,}\b', 'Possible hash/token'),
        ]
        
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, value):
                issues.append(f'{desc} detected in cookie value')
        
        # Calculate security score
        score = 100
        if issues:
            score -= len(issues) * 15
        score = max(0, score)
        
        return {
            'name': cookie['name'],
            'value_preview': value[:30] + '...' if len(value) > 30 else value,
            'is_sensitive': is_sensitive,
            'secure': has_secure,
            'httponly': has_httponly,
            'samesite': has_samesite,
            'issues': issues,
            'recommendations': list(set(recommendations)),
            'security_score': score,
            'attributes': attrs
        }
    
    def analyze_all(self) -> List[Dict]:
        """Analyze all cookies."""
        return [self.analyze_cookie(cookie) for cookie in self.cookies]

def main():
    parser = argparse.ArgumentParser(
        description="Cookie Analyzer - Analyze HTTP cookies for security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cookie_analyzer.py "session=abc123; HttpOnly; Secure"
  python cookie_analyzer.py -f cookies.txt
        """
    )
    
    parser.add_argument("cookie", nargs="?", help="Cookie string to analyze")
    parser.add_argument("-f", "--file", help="File containing cookie strings")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not args.cookie and not args.file:
        parser.print_help()
        print("\n[!] Please provide a cookie string or file")
        sys.exit(1)
    
    try:
        analyzer = CookieAnalyzer()
        
        if args.file:
            with open(args.file, 'r') as f:
                for line in f:
                    if line.strip():
                        analyzer.parse_cookie_string(line.strip())
        else:
            analyzer.parse_cookie_string(args.cookie)
        
        results = analyzer.analyze_all()
        
        if args.json:
            import json
            print(json.dumps(results, indent=2))
        else:
            print("\n" + "="*70)
            print("  COOKIE SECURITY ANALYSIS")
            print("="*70)
            
            for i, result in enumerate(results, 1):
                print(f"\n  Cookie #{i}: {result['name']}")
                print("  " + "-"*66)
                print(f"    Value: {result['value_preview']}")
                print(f"    Sensitive: {'Yes' if result['is_sensitive'] else 'No'}")
                print(f"    Secure: {'✓' if result['secure'] else '✗'}")
                print(f"    HttpOnly: {'✓' if result['httponly'] else '✗'}")
                print(f"    SameSite: {'✓' if result['samesite'] else '✗'}")
                print(f"    Security Score: {result['security_score']}/100")
                
                if result['issues']:
                    print(f"\n    Issues:")
                    for issue in result['issues']:
                        print(f"      ⚠ {issue}")
                
                if result['recommendations']:
                    print(f"\n    Recommendations:")
                    for rec in result['recommendations']:
                        print(f"      → {rec}")
            
            # Summary
            total_score = sum(r['security_score'] for r in results) / len(results) if results else 0
            print(f"\n{'='*70}")
            print(f"  OVERALL SECURITY SCORE: {total_score:.1f}/100")
            print("="*70)
            
            if total_score >= 80:
                print("  Rating: Good ✓")
            elif total_score >= 60:
                print("  Rating: Moderate ⚠️")
            else:
                print("  Rating: Poor ✗")
        
    except FileNotFoundError:
        print(f"\n[!] File not found: {args.file}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
