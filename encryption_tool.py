#!/usr/bin/env python3
"""
ENCRYPTION/DECRYPTION TOOL
==========================

Encrypt and decrypt files and text using various algorithms.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install cryptography

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import getpass

def generate_key(password: str, salt: bytes = None) -> tuple:
    """
    Generate encryption key from password.
    
    Args:
        password: Password string
        salt: Salt bytes (generated if None)
    
    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_text(plaintext: str, password: str) -> str:
    """
    Encrypt text using password.
    
    Args:
        plaintext: Text to encrypt
        password: Encryption password
    
    Returns:
        Encrypted string (base64 encoded)
    """
    key, salt = generate_key(password)
    fernet = Fernet(key)
    
    encrypted = fernet.encrypt(plaintext.encode())
    
    # Combine salt and encrypted data
    combined = salt + encrypted
    
    return base64.urlsafe_b64encode(combined).decode()

def decrypt_text(ciphertext: str, password: str) -> str:
    """
    Decrypt text using password.
    
    Args:
        ciphertext: Encrypted text (base64 encoded)
        password: Decryption password
    
    Returns:
        Decrypted string
    """
    # Decode combined data
    combined = base64.urlsafe_b64decode(ciphertext.encode())
    
    # Extract salt and encrypted data
    salt = combined[:16]
    encrypted = combined[16:]
    
    key, _ = generate_key(password, salt)
    fernet = Fernet(key)
    
    decrypted = fernet.decrypt(encrypted)
    
    return decrypted.decode()

def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Encrypt a file.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file
        password: Encryption password
    
    Returns:
        Dictionary with result info
    """
    result = {
        'input': input_path,
        'output': output_path,
        'success': False,
        'error': None
    }
    
    try:
        key, salt = generate_key(password)
        fernet = Fernet(key)
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted = fernet.encrypt(data)
        
        # Write salt + encrypted data
        with open(output_path, 'wb') as f:
            f.write(salt + encrypted)
        
        result['success'] = True
        result['original_size'] = len(data)
        result['encrypted_size'] = len(encrypted) + 16
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Decrypt a file.
    
    Args:
        input_path: Path to encrypted file
        output_path: Path to output file
        password: Decryption password
    
    Returns:
        Dictionary with result info
    """
    result = {
        'input': input_path,
        'output': output_path,
        'success': False,
        'error': None
    }
    
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        
        # Extract salt and encrypted data
        salt = data[:16]
        encrypted = data[16:]
        
        key, _ = generate_key(password, salt)
        fernet = Fernet(key)
        
        decrypted = fernet.decrypt(encrypted)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        
        result['success'] = True
        result['decrypted_size'] = len(decrypted)
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def generate_fernet_key() -> str:
    """Generate a random Fernet key."""
    return Fernet.generate_key().decode()

def main():
    parser = argparse.ArgumentParser(
        description="Encryption/Decryption Tool - Secure file and text encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Text encryption
  python encryption_tool.py -e -t "secret message" -p "password"
  python encryption_tool.py -d -t "encrypted_base64" -p "password"
  
  # File encryption
  python encryption_tool.py -e -f document.txt -o encrypted.bin -p "password"
  python encryption_tool.py -d -f encrypted.bin -o decrypted.txt -p "password"
  
  # Generate key
  python encryption_tool.py --generate-key
        """
    )
    
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt mode")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Decrypt mode")
    parser.add_argument("-t", "--text", help="Text to encrypt/decrypt")
    parser.add_argument("-f", "--file", help="File to encrypt/decrypt")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-p", "--password", help="Encryption password")
    parser.add_argument("--generate-key", action="store_true",
                        help="Generate a random encryption key")
    parser.add_argument("--hide-password", action="store_true",
                        help="Prompt for password (hidden input)")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  ENCRYPTION/DECRYPTION TOOL - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        # Generate key mode
        if args.generate_key:
            key = generate_fernet_key()
            print(f"\n  Generated Key: {key}")
            print("\n  ⚠️ Store this key securely! It cannot be recovered.")
            print("="*70)
            return
        
        # Get password
        password = args.password
        if not password:
            if args.hide_password:
                password = getpass.getpass("  Enter password: ")
            else:
                print("\n  [!] Password required. Use -p or --hide-password")
                sys.exit(1)
        
        # Text mode
        if args.text:
            if args.encrypt:
                result = encrypt_text(args.text, password)
                print(f"\n  Encrypted: {result}")
            elif args.decrypt:
                result = decrypt_text(args.text, password)
                print(f"\n  Decrypted: {result}")
            else:
                print("\n  [!] Specify --encrypt or --decrypt")
                sys.exit(1)
        
        # File mode
        elif args.file:
            if not args.output:
                args.output = args.file + ('.enc' if args.encrypt else '.dec')
            
            if args.encrypt:
                print(f"\n  Encrypting: {args.file}")
                result = encrypt_file(args.file, args.output, password)
            elif args.decrypt:
                print(f"\n  Decrypting: {args.file}")
                result = decrypt_file(args.file, args.output, password)
            else:
                print("\n  [!] Specify --encrypt or --decrypt")
                sys.exit(1)
            
            if result['success']:
                print(f"  ✓ Output: {args.output}")
                print(f"  Size: {result.get('decrypted_size', result.get('encrypted_size', 0))} bytes")
            else:
                print(f"  ✗ Error: {result['error']}")
        
        else:
            parser.print_help()
        
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
