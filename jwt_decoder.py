#!/usr/bin/env python3
"""
JSON WEB TOKEN (JWT) DECODER
============================

Decode and inspect JWT tokens.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Do not use to forge tokens or bypass authentication.

Author: CyberSecurity Tools Hub
"""

import base64
import json
import argparse
import sys
import hmac
import hashlib
from datetime import datetime

def base64url_decode(data: str) -> str:
    """Decode base64url encoded string."""
    # Add padding if necessary
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def base64url_encode(data: str) -> str:
    """Encode string to base64url."""
    encoded = base64.b64encode(data.encode()).decode()
    return encoded.replace('+', '-').replace('/', '_').rstrip('=')

def decode_jwt(token: str) -> dict:
    """
    Decode JWT token without verification.
    
    Args:
        token: JWT token string
    
    Returns:
        Dictionary with decoded parts
    """
    result = {
        'token': token,
        'valid': False,
        'header': None,
        'payload': None,
        'signature': None,
        'error': None
    }
    
    try:
        parts = token.split('.')
        
        if len(parts) != 3:
            result['error'] = 'Invalid JWT format (should have 3 parts)'
            return result
        
        # Decode header
        result['header'] = json.loads(base64url_decode(parts[0]))
        
        # Decode payload
        result['payload'] = json.loads(base64url_decode(parts[1]))
        
        # Store signature (encoded)
        result['signature'] = parts[2]
        
        result['valid'] = True
        
    except json.JSONDecodeError as e:
        result['error'] = f'Invalid JSON: {e}'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def verify_jwt(token: str, secret: str, algorithm: str = 'HS256') -> dict:
    """
    Verify JWT signature.
    
    Args:
        token: JWT token string
        secret: Secret key
        algorithm: Signing algorithm
    
    Returns:
        Dictionary with verification result
    """
    result = {
        'verified': False,
        'algorithm': algorithm,
        'error': None
    }
    
    try:
        parts = token.split('.')
        if len(parts) != 3:
            result['error'] = 'Invalid JWT format'
            return result
        
        # Get header to check algorithm
        header = json.loads(base64url_decode(parts[0]))
        algo = header.get('alg', algorithm)
        
        if algo not in ['HS256', 'HS384', 'HS512']:
            result['error'] = f'Unsupported algorithm: {algo}'
            return result
        
        # Map algorithms to hash functions
        hash_map = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }
        
        # Calculate expected signature
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(
            secret.encode(),
            signing_input,
            hash_map[algo]
        ).digest()
        
        expected_sig_b64 = base64url_encode(expected_sig.decode('latin-1'))
        
        # Compare signatures
        if expected_sig_b64 == parts[2]:
            result['verified'] = True
        else:
            result['error'] = 'Signature verification failed'
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_token_expiry(payload: dict) -> dict:
    """Check if token is expired."""
    result = {
        'expired': False,
        'expires_at': None,
        'issued_at': None,
        'time_remaining': None
    }
    
    now = datetime.utcnow().timestamp()
    
    if 'exp' in payload:
        exp = payload['exp']
        result['expires_at'] = datetime.fromtimestamp(exp).isoformat()
        result['expired'] = now > exp
        if not result['expired']:
            result['time_remaining'] = int(exp - now)
    
    if 'iat' in payload:
        result['issued_at'] = datetime.fromtimestamp(payload['iat']).isoformat()
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="JWT Decoder - Decode and inspect JWT tokens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_decoder.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  python jwt_decoder.py <token> --verify --secret "mysecret"
  python jwt_decoder.py <token> --check-expiry
        """
    )
    
    parser.add_argument("token", help="JWT token to decode")
    parser.add_argument("--verify", action="store_true",
                        help="Verify token signature")
    parser.add_argument("--secret", help="Secret key for verification")
    parser.add_argument("--check-expiry", action="store_true",
                        help="Check token expiry")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  JWT DECODER - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        result = decode_jwt(args.token)
        
        if result['error']:
            print(f"\n  [!] Error: {result['error']}")
            sys.exit(1)
        
        print(f"\n  Token valid: ✓")
        
        # Print header
        print(f"\n  HEADER:")
        print("  " + "-"*50)
        for key, value in result['header'].items():
            print(f"    {key}: {value}")
        
        # Print payload
        print(f"\n  PAYLOAD:")
        print("  " + "-"*50)
        for key, value in result['payload'].items():
            print(f"    {key}: {value}")
        
        # Print signature
        print(f"\n  SIGNATURE:")
        print("  " + "-"*50)
        print(f"    {result['signature'][:40]}...")
        
        # Check expiry
        if args.check_expiry:
            expiry = check_token_expiry(result['payload'])
            print(f"\n  EXPIRY INFO:")
            print("  " + "-"*50)
            if expiry['issued_at']:
                print(f"    Issued at: {expiry['issued_at']}")
            if expiry['expires_at']:
                print(f"    Expires at: {expiry['expires_at']}")
                print(f"    Status: {'EXPIRED' if expiry['expired'] else 'Valid'}")
                if expiry['time_remaining']:
                    print(f"    Time remaining: {expiry['time_remaining']} seconds")
        
        # Verify signature
        if args.verify:
            if not args.secret:
                print("\n  [!] --secret required for verification")
            else:
                algo = result['header'].get('alg', 'HS256')
                verify_result = verify_jwt(args.token, args.secret, algo)
                print(f"\n  SIGNATURE VERIFICATION:")
                print("  " + "-"*50)
                if verify_result['verified']:
                    print(f"    Status: ✓ Verified")
                else:
                    print(f"    Status: ✗ Failed")
                    if verify_result['error']:
                        print(f"    Error: {verify_result['error']}")
        
        if args.json:
            output = {
                'header': result['header'],
                'payload': result['payload'],
                'signature': result['signature']
            }
            if args.check_expiry:
                output['expiry'] = check_token_expiry(result['payload'])
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
