#!/usr/bin/env python3
"""
HASH GENERATOR
==============

Generate various hash values for text or files.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import hashlib
import argparse
import sys
import os

SUPPORTED_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'sha3_224': hashlib.sha3_224,
    'sha3_256': hashlib.sha3_256,
    'sha3_384': hashlib.sha3_384,
    'sha3_512': hashlib.sha3_512,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s,
}

def hash_text(text: str, algorithm: str = 'sha256') -> str:
    """
    Hash text using specified algorithm.
    
    Args:
        text: Text to hash
        algorithm: Hash algorithm name
    
    Returns:
        Hexadecimal hash string
    """
    algorithm = algorithm.lower().replace('-', '_')
    
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hasher = SUPPORTED_ALGORITHMS[algorithm]()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def hash_file(filepath: str, algorithm: str = 'sha256', chunk_size: int = 65536) -> str:
    """
    Hash file using specified algorithm.
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm name
        chunk_size: Size of chunks to read
    
    Returns:
        Hexadecimal hash string
    """
    algorithm = algorithm.lower().replace('-', '_')
    
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hasher = SUPPORTED_ALGORITHMS[algorithm]()
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    
    return hasher.hexdigest()

def hash_all_algorithms(text: str = None, filepath: str = None) -> dict:
    """Generate all supported hashes for text or file."""
    results = {}
    
    for name, algo_func in SUPPORTED_ALGORITHMS.items():
        try:
            if filepath:
                results[name] = hash_file(filepath, name)
            elif text is not None:
                results[name] = hash_text(text, name)
        except Exception as e:
            results[name] = f"Error: {str(e)}"
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Hash Generator - Generate hash values for text or files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hash_generator.py -t "Hello World"              # SHA256 hash
  python hash_generator.py -t "secret" -a md5            # MD5 hash
  python hash_generator.py -f document.pdf               # Hash file
  python hash_generator.py -t "data" --all               # All algorithms
        """
    )
    
    parser.add_argument("-t", "--text", help="Text to hash")
    parser.add_argument("-f", "--file", help="File to hash")
    parser.add_argument("-a", "--algorithm", default="sha256",
                        help=f"Hash algorithm (default: sha256)")
    parser.add_argument("--all", action="store_true",
                        help="Generate all supported hashes")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List supported algorithms")
    
    args = parser.parse_args()
    
    if args.list:
        print("\n  Supported Hash Algorithms:")
        print("  " + "-"*40)
        for name in SUPPORTED_ALGORITHMS:
            print(f"    - {name}")
        print()
        return
    
    if not args.text and not args.file:
        parser.print_help()
        print("\n[!] Please provide text (-t) or file (-f) to hash")
        sys.exit(1)
    
    try:
        print("\n" + "="*70)
        print("  HASH GENERATOR - CyberSecurity Tools Hub")
        print("="*70)
        
        if args.all:
            print(f"\n  Generating all hashes for: ", end="")
            if args.file:
                print(f"file '{args.file}'")
                if os.path.exists(args.file):
                    size = os.path.getsize(args.file)
                    print(f"  File size: {size:,} bytes")
                results = hash_all_algorithms(filepath=args.file)
            else:
                print(f"text ({len(args.text)} chars)")
                results = hash_all_algorithms(text=args.text)
            
            print("\n  " + "-"*66)
            print(f"  {'Algorithm':<15} {'Hash'}")
            print("  " + "-"*66)
            
            for name, hash_value in results.items():
                if hash_value.startswith('Error'):
                    print(f"  {name:<15} {hash_value}")
                else:
                    print(f"  {name:<15} {hash_value}")
        
        else:
            algorithm = args.algorithm.lower().replace('-', '_')
            
            if algorithm not in SUPPORTED_ALGORITHMS:
                print(f"\n[!] Unsupported algorithm: {algorithm}")
                print(f"    Supported: {', '.join(SUPPORTED_ALGORITHMS.keys())}")
                sys.exit(1)
            
            if args.file:
                if not os.path.exists(args.file):
                    print(f"\n[!] File not found: {args.file}")
                    sys.exit(1)
                
                print(f"\n  File: {args.file}")
                print(f"  Size: {os.path.getsize(args.file):,} bytes")
                print(f"  Algorithm: {algorithm.upper()}")
                
                hash_value = hash_file(args.file, algorithm)
            else:
                print(f"\n  Text: {args.text[:50]}{'...' if len(args.text) > 50 else ''}")
                print(f"  Algorithm: {algorithm.upper()}")
                
                hash_value = hash_text(args.text, algorithm)
            
            print("\n  " + "-"*66)
            print(f"  {algorithm.upper()}: {hash_value}")
            print("  " + "-"*66)
        
        print("\n" + "="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
