#!/usr/bin/env python3
"""
EMAIL VALIDATOR
===============

Validate email addresses and check if they exist.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install dnspython requests

Author: CyberSecurity Tools Hub
"""

import re
import argparse
import sys
import socket

try:
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

def validate_syntax(email: str) -> dict:
    """
    Validate email syntax.
    
    Args:
        email: Email address to validate
    
    Returns:
        Dictionary with validation results
    """
    # RFC 5322 compliant regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    return {
        'email': email,
        'valid_syntax': bool(re.match(pattern, email)),
        'local_part': email.split('@')[0] if '@' in email else None,
        'domain': email.split('@')[1] if '@' in email else None,
    }

def check_mx_records(domain: str) -> dict:
    """
    Check MX records for domain.
    
    Args:
        domain: Domain to check
    
    Returns:
        Dictionary with MX records
    """
    if not DNSPYTHON_AVAILABLE:
        return {'error': 'dnspython not installed'}
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        records = []
        for mx in mx_records:
            records.append({
                'preference': mx.preference,
                'exchange': str(mx.exchange),
            })
        return {
            'has_mx': True,
            'records': sorted(records, key=lambda x: x['preference'])
        }
    except dns.resolver.NoAnswer:
        return {'has_mx': False, 'records': []}
    except dns.resolver.NXDOMAIN:
        return {'error': 'Domain does not exist'}
    except Exception as e:
        return {'error': str(e)}

def check_disposable_email(domain: str) -> bool:
    """Check if email is from a disposable email provider."""
    disposable_domains = [
        'tempmail.com', 'guerrillamail.com', '10minutemail.com',
        'mailinator.com', 'throwaway.email', 'fakeinbox.com',
        'temp-mail.org', 'dispostable.com', 'mailnesia.com',
        'tempail.com', 'mohmal.com', 'yopmail.com',
    ]
    return domain.lower() in disposable_domains

def validate_email(email: str, check_mx: bool = True) -> dict:
    """
    Validate email address completely.
    
    Args:
        email: Email to validate
        check_mx: Whether to check MX records
    
    Returns:
        Dictionary with validation results
    """
    result = validate_syntax(email)
    
    if not result['valid_syntax']:
        result['valid'] = False
        result['reason'] = 'Invalid syntax'
        return result
    
    domain = result['domain']
    
    # Check disposable
    result['is_disposable'] = check_disposable_email(domain)
    
    # Check MX records
    if check_mx and DNSPYTHON_AVAILABLE:
        mx_result = check_mx_records(domain)
        result['mx_check'] = mx_result
        
        if mx_result.get('has_mx'):
            result['valid'] = True
            result['reason'] = 'Valid email with MX records'
        elif 'error' in mx_result:
            result['valid'] = False
            result['reason'] = mx_result['error']
        else:
            result['valid'] = False
            result['reason'] = 'No MX records found'
    else:
        result['valid'] = True
        result['reason'] = 'Syntax valid'
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Email Validator - Validate email addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python email_validator.py test@example.com
  python email_validator.py user@gmail.com --no-mx
        """
    )
    
    parser.add_argument("email", help="Email address to validate")
    parser.add_argument("--no-mx", action="store_true", help="Skip MX record check")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  EMAIL VALIDATOR - CyberSecurity Tools Hub")
    print("="*60)
    
    try:
        result = validate_email(args.email, check_mx=not args.no_mx)
        
        if args.json:
            import json
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  Email: {result['email']}")
            print(f"  Valid Syntax: {result['valid_syntax']}")
            
            if result.get('domain'):
                print(f"  Domain: {result['domain']}")
                print(f"  Local Part: {result['local_part']}")
            
            print(f"  Disposable: {'Yes' if result.get('is_disposable') else 'No'}")
            
            if 'mx_check' in result:
                mx = result['mx_check']
                if mx.get('has_mx'):
                    print(f"\n  MX Records:")
                    for record in mx.get('records', [])[:5]:
                        print(f"    {record['preference']} {record['exchange']}")
                else:
                    print(f"\n  MX Check: No MX records")
            
            print(f"\n  Result: {result.get('reason', 'Unknown')}")
            print(f"  Status: {'✓ VALID' if result.get('valid') else '✗ INVALID'}")
        
        print("\n" + "="*60)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
