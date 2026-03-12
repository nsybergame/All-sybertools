#!/usr/bin/env python3
"""
CREDENTIAL CHECKER
==================

Check if credentials have been exposed in known data breaches.
Uses HaveIBeenPwned API (k-anonymity model - safe to use).

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Your passwords are NEVER sent to any server in plain text.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import hashlib
import argparse
import sys
import requests

def check_password_breach(password: str) -> dict:
    """
    Check if password has been exposed in known data breaches.
    Uses HaveIBeenPwned k-anonymity API - only first 5 chars of hash are sent.
    
    Args:
        password: Password to check
    
    Returns:
        Dictionary with breach status
    """
    # Hash password with SHA-1
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Split hash into prefix (5 chars) and suffix
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    result = {
        'password_length': len(password),
        'hash_prefix': prefix,
        'breached': False,
        'occurrences': 0,
    }
    
    try:
        # Query HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            # Parse response
            hashes = response.text.split('\n')
            
            for line in hashes:
                parts = line.strip().split(':')
                if len(parts) == 2:
                    hash_suffix, count = parts
                    if hash_suffix == suffix:
                        result['breached'] = True
                        result['occurrences'] = int(count)
                        break
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_email_breach(email: str, api_key: str = None) -> dict:
    """
    Check if email has been in breaches (requires API key).
    
    Args:
        email: Email to check
        api_key: HaveIBeenPwned API key
    
    Returns:
        Dictionary with breach status
    """
    result = {
        'email': email,
        'breached': False,
        'breach_count': 0,
        'breaches': [],
    }
    
    if not api_key:
        result['error'] = 'API key required for email checks'
        result['message'] = 'Get free API key at: https://haveibeenpwned.com/API/Key'
        return result
    
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            'hibp-api-key': api_key,
            'user-agent': 'CyberSecurity-Tools-Hub'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        
        if response.status_code == 200:
            breaches = response.json()
            result['breached'] = True
            result['breach_count'] = len(breaches)
            result['breaches'] = [
                {'name': b.get('Name'), 'date': b.get('BreachDate')}
                for b in breaches[:10]  # Show first 10
            ]
        elif response.status_code == 404:
            result['breached'] = False
            result['breach_count'] = 0
        elif response.status_code == 401:
            result['error'] = 'Invalid API key'
        elif response.status_code == 429:
            result['error'] = 'Rate limited - try again later'
        else:
            result['error'] = f'API returned status {response.status_code}'
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Credential Checker - Check if credentials are compromised",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SECURITY NOTE:
Password checks use k-anonymity - your password is NEVER sent to any server.
Only the first 5 characters of the password's SHA-1 hash are sent.

Examples:
  python credential_checker.py -p "password123"
  python credential_checker.py -e user@example.com --api-key YOUR_KEY
        """
    )
    
    parser.add_argument("-p", "--password", help="Password to check for breaches")
    parser.add_argument("-e", "--email", help="Email to check for breaches")
    parser.add_argument("--api-key", help="HaveIBeenPwned API key for email checks")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    
    if not args.password and not args.email:
        parser.print_help()
        print("\n[!] Please provide --password or --email")
        sys.exit(1)
    
    print("\n" + "="*70)
    print("  CREDENTIAL CHECKER - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        if args.password:
            print("\n  [SECURE] Checking password using k-anonymity API...")
            print("  Your password is NEVER sent to any server.")
            
            result = check_password_breach(args.password)
            
            print(f"\n  Password Length: {result['password_length']} characters")
            print(f"  Hash Prefix: {result['hash_prefix']}...")
            
            if result.get('error'):
                print(f"\n  [!] Error: {result['error']}")
            elif result['breached']:
                print(f"\n  ✗ BREACHED! Found {result['occurrences']:,} times in data breaches!")
                print("  Recommendation: Change this password immediately!")
            else:
                print(f"\n  ✓ Good news! Password not found in known breaches.")
                print("  (This doesn't mean it's secure, just not publicly known)")
        
        if args.email:
            print(f"\n  Checking email: {args.email}")
            
            result = check_email_breach(args.email, args.api_key)
            
            if result.get('error'):
                print(f"\n  [!] {result['error']}")
                if result.get('message'):
                    print(f"  {result['message']}")
            elif result['breached']:
                print(f"\n  ⚠️ BREACHED! Found in {result['breach_count']} data breaches:")
                for breach in result['breaches']:
                    print(f"    - {breach['name']} ({breach['date']})")
            else:
                print(f"\n  ✓ Good news! Email not found in known breaches.")
        
        if args.json:
            import json
            output = {}
            if args.password:
                output['password'] = check_password_breach(args.password)
            if args.email:
                output['email'] = check_email_breach(args.email, args.api_key)
            print("\n" + json.dumps(output, indent=2))
        
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
