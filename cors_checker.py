#!/usr/bin/env python3
"""
CORS CHECKER
============

Check Cross-Origin Resource Sharing (CORS) configuration.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only test websites you own or have permission to test.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import argparse
import sys

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Test origins for CORS
TEST_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'null',
    'https://example.com.evil.com',
]

class CORSChecker:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings = []
    
    def check_cors(self, origin: str) -> dict:
        """
        Check CORS headers for a specific origin.
        
        Args:
            origin: Origin to test
        
        Returns:
            Dictionary with CORS findings
        """
        headers = {'Origin': origin}
        
        try:
            # Try GET request
            response = requests.get(
                self.target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            cors_headers = {}
            
            # Check for CORS headers
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            acah = response.headers.get('Access-Control-Allow-Headers')
            acam = response.headers.get('Access-Control-Allow-Methods')
            
            cors_headers['Access-Control-Allow-Origin'] = acao
            cors_headers['Access-Control-Allow-Credentials'] = acac
            cors_headers['Access-Control-Allow-Headers'] = acah
            cors_headers['Access-Control-Allow-Methods'] = acam
            
            return {
                'origin': origin,
                'status_code': response.status_code,
                'cors_headers': cors_headers,
                'vulnerable': False
            }
        
        except Exception as e:
            return {
                'origin': origin,
                'error': str(e),
                'vulnerable': False
            }
    
    def check_preflight(self, origin: str, method: str = 'GET') -> dict:
        """Check CORS preflight request."""
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': method,
            'Access-Control-Request-Headers': 'Content-Type,Authorization'
        }
        
        try:
            response = requests.options(
                self.target_url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            return {
                'status_code': response.status_code,
                'allow_origin': response.headers.get('Access-Control-Allow-Origin'),
                'allow_methods': response.headers.get('Access-Control-Allow-Methods'),
                'allow_headers': response.headers.get('Access-Control-Allow-Headers'),
            }
        except:
            return {}
    
    def analyze(self) -> list:
        """Run full CORS analysis."""
        results = []
        
        for origin in TEST_ORIGINS:
            result = self.check_cors(origin)
            
            # Check for vulnerabilities
            acao = result.get('cors_headers', {}).get('Access-Control-Allow-Origin')
            acac = result.get('cors_headers', {}).get('Access-Control-Allow-Credentials')
            
            if acao == origin or acao == 'null':
                if acac == 'true':
                    result['vulnerable'] = True
                    result['vulnerability'] = 'CORS misconfiguration allows credential theft'
                elif acao == origin:
                    result['vulnerable'] = True
                    result['vulnerability'] = 'CORS reflects arbitrary origin'
            
            if acao == '*':
                result['warning'] = 'Wildcard origin allowed'
            
            results.append(result)
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description="CORS Checker - Check CORS configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cors_checker.py https://example.com
  python cors_checker.py https://target.com --origin https://evil.com
        """
    )
    
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("--origin", help="Specific origin to test")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not REQUESTS_AVAILABLE:
        print("\n[!] requests required. Install with: pip install requests")
        sys.exit(1)
    
    import warnings
    warnings.filterwarnings('ignore')
    
    try:
        checker = CORSChecker(args.url, args.timeout)
        
        print("\n" + "="*70)
        print("  CORS CHECKER - CyberSecurity Tools Hub")
        print("="*70)
        print(f"\n  Target: {args.url}")
        
        if args.origin:
            # Test specific origin
            results = [checker.check_cors(args.origin)]
        else:
            # Test all origins
            print("\n  Testing multiple origins...\n")
            results = checker.analyze()
        
        if args.json:
            import json
            print(json.dumps(results, indent=2))
        else:
            print(f"\n  CORS Test Results:")
            print("  " + "-"*66)
            
            for result in results:
                print(f"\n  Origin: {result['origin']}")
                cors = result.get('cors_headers', {})
                
                for header, value in cors.items():
                    if value:
                        print(f"    {header}: {value}")
                
                if result.get('vulnerable'):
                    print(f"\n    🔴 VULNERABLE: {result.get('vulnerability')}")
                elif result.get('warning'):
                    print(f"\n    ⚠️  WARNING: {result['warning']}")
                else:
                    print(f"\n    ✓ No CORS misconfiguration detected")
        
        # Summary
        vulnerable = [r for r in results if r.get('vulnerable')]
        if vulnerable:
            print(f"\n{'='*70}")
            print(f"  VULNERABILITY FOUND!")
            print(f"  {len(vulnerable)} origin(s) can access the resource")
            print("="*70)
            print("\n  Recommendations:")
            print("  - Validate origin against whitelist")
            print("  - Don't use Access-Control-Allow-Origin: * with credentials")
            print("  - Use proper origin validation instead of reflection")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
