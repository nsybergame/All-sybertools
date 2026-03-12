#!/usr/bin/env python3
"""
SSL CERTIFICATE CHECKER
=======================

Verify SSL certificate of a website.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install pyopenssl cryptography

Author: CyberSecurity Tools Hub
"""

import socket
import argparse
import sys
from datetime import datetime

try:
    from OpenSSL import SSL, crypto
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

def get_ssl_certificate(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Get SSL certificate information for a hostname.
    
    Args:
        hostname: Domain name
        port: Port number
        timeout: Connection timeout
    
    Returns:
        Dictionary with certificate information
    """
    if not OPENSSL_AVAILABLE:
        return {'error': 'pyopenssl not installed'}
    
    try:
        # Create SSL context
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Wrap socket with SSL
        ssl_sock = SSL.Connection(context, sock)
        ssl_sock.connect((hostname, port))
        
        try:
            ssl_sock.do_handshake()
        except SSL.Error as e:
            pass
        
        # Get certificate
        cert = ssl_sock.get_peer_certificate()
        ssl_sock.close()
        sock.close()
        
        if not cert:
            return {'error': 'No certificate found'}
        
        # Parse certificate
        cert_dict = {
            'hostname': hostname,
            'port': port,
            'valid': True,
            'subject': dict(cert.get_subject().get_components()),
            'issuer': dict(cert.get_issuer().get_components()),
            'serial_number': cert.get_serial_number(),
            'version': cert.get_version(),
            'not_before': cert.get_notBefore().decode(),
            'not_after': cert.get_notAfter().decode(),
            'signature_algorithm': cert.get_signature_algorithm().decode(),
            'extensions': [],
        }
        
        # Get extensions
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            try:
                cert_dict['extensions'].append({
                    'name': ext.get_short_name().decode(),
                    'value': str(ext)
                })
            except:
                pass
        
        # Check validity dates
        not_before = datetime.strptime(cert_dict['not_before'], '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert_dict['not_after'], '%Y%m%d%H%M%SZ')
        now = datetime.utcnow()
        
        cert_dict['not_before_date'] = not_before.strftime('%Y-%m-%d %H:%M:%S UTC')
        cert_dict['not_after_date'] = not_after.strftime('%Y-%m-%d %H:%M:%S UTC')
        
        if now < not_before:
            cert_dict['valid'] = False
            cert_dict['error'] = 'Certificate not yet valid'
        elif now > not_after:
            cert_dict['valid'] = False
            cert_dict['error'] = 'Certificate has expired'
        
        # Days until expiry
        cert_dict['days_until_expiry'] = (not_after - now).days
        
        # Check expiration
        if cert_dict['days_until_expiry'] <= 0:
            cert_dict['status'] = 'EXPIRED'
        elif cert_dict['days_until_expiry'] <= 7:
            cert_dict['status'] = 'EXPIRING_SOON'
        elif cert_dict['days_until_expiry'] <= 30:
            cert_dict['status'] = 'WARNING'
        else:
            cert_dict['status'] = 'VALID'
        
        return cert_dict
    
    except socket.timeout:
        return {'error': 'Connection timeout'}
    except socket.gaierror:
        return {'error': 'DNS resolution failed'}
    except SSL.Error as e:
        return {'error': f'SSL Error: {str(e)}'}
    except Exception as e:
        return {'error': str(e)}

def print_cert_info(cert: dict):
    """Pretty print certificate information."""
    print("\n" + "="*70)
    print("  SSL CERTIFICATE INFORMATION")
    print("="*70)
    
    if 'error' in cert:
        print(f"\n  [!] Error: {cert['error']}")
        return
    
    # Status
    status = cert.get('status', 'UNKNOWN')
    if status == 'VALID':
        icon = "✓"
    elif status in ['WARNING', 'EXPIRING_SOON']:
        icon = "⚠️"
    else:
        icon = "✗"
    
    print(f"\n  Status: {icon} {status}")
    print(f"  Hostname: {cert['hostname']}:{cert['port']}")
    
    # Subject
    print(f"\n  Subject:")
    subject = cert.get('subject', {})
    for key in [b'CN', b'O', b'OU', b'L', b'ST', b'C']:
        if key in subject:
            print(f"    {key.decode()}: {subject[key].decode()}")
    
    # Issuer
    print(f"\n  Issuer:")
    issuer = cert.get('issuer', {})
    for key in [b'CN', b'O', b'C']:
        if key in issuer:
            print(f"    {key.decode()}: {issuer[key].decode()}")
    
    # Validity
    print(f"\n  Validity:")
    print(f"    Not Before: {cert.get('not_before_date', 'N/A')}")
    print(f"    Not After:  {cert.get('not_after_date', 'N/A')}")
    print(f"    Days Until Expiry: {cert.get('days_until_expiry', 'N/A')}")
    
    # Certificate details
    print(f"\n  Certificate Details:")
    print(f"    Serial Number: {cert.get('serial_number', 'N/A')}")
    print(f"    Version: {cert.get('version', 'N/A')}")
    print(f"    Signature Algorithm: {cert.get('signature_algorithm', 'N/A')}")
    
    # Extensions
    san_ext = None
    for ext in cert.get('extensions', []):
        if ext['name'] == 'subjectAltName':
            san_ext = ext['value']
            break
    
    if san_ext:
        print(f"\n  Subject Alternative Names:")
        for name in san_ext.split(', '):
            print(f"    - {name}")
    
    print("\n" + "="*70)
    
    # Recommendations
    if cert.get('days_until_expiry', 999) <= 30:
        print("\n  ⚠️  WARNING: Certificate will expire soon!")
        print("      Consider renewing the certificate.")
    elif cert.get('days_until_expiry', 999) <= 0:
        print("\n  ✗ ERROR: Certificate has EXPIRED!")
        print("    Immediate action required!")

def main():
    parser = argparse.ArgumentParser(
        description="SSL Certificate Checker - Verify website SSL certificate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssl_certificate_checker.py google.com
  python ssl_certificate_checker.py example.com -p 8443
        """
    )
    
    parser.add_argument("hostname", help="Hostname to check")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Port number (default: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Connection timeout in seconds")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save output to file")
    
    args = parser.parse_args()
    
    if not OPENSSL_AVAILABLE:
        print("\n[!] pyopenssl required. Install with: pip install pyopenssl cryptography")
        sys.exit(1)
    
    try:
        print(f"\n  Checking SSL certificate for {args.hostname}...")
        cert = get_ssl_certificate(args.hostname, args.port, args.timeout)
        
        if args.json:
            import json
            print(json.dumps(cert, indent=2, default=str))
        else:
            print_cert_info(cert)
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(cert, f, indent=2, default=str)
            print(f"\n  Output saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
