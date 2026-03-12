#!/usr/bin/env python3
"""
FILE HASH CALCULATOR
====================

Calculate hash values for files.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import hashlib
import argparse
import sys
import os
from datetime import datetime

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

def calculate_file_hash(filepath: str, algorithm: str = 'sha256', chunk_size: int = 65536) -> str:
    """
    Calculate hash of a file.
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm
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

def calculate_all_hashes(filepath: str) -> dict:
    """
    Calculate all supported hashes for a file.
    
    Args:
        filepath: Path to file
    
    Returns:
        Dictionary with all hashes
    """
    # Calculate all hashes in one pass for efficiency
    hashes = {name: algo() for name, algo in SUPPORTED_ALGORITHMS.items()}
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            for hasher in hashes.values():
                hasher.update(chunk)
    
    return {name: hasher.hexdigest() for name, hasher in hashes.items()}

def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def verify_hash(filepath: str, expected_hash: str) -> dict:
    """
    Verify file against expected hash.
    
    Args:
        filepath: Path to file
        expected_hash: Expected hash value
    
    Returns:
        Dictionary with verification result
    """
    # Auto-detect algorithm by hash length
    hash_length = len(expected_hash)
    
    length_to_algo = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512',
    }
    
    algorithm = length_to_algo.get(hash_length, 'sha256')
    
    actual_hash = calculate_file_hash(filepath, algorithm)
    match = actual_hash.lower() == expected_hash.lower()
    
    return {
        'algorithm': algorithm,
        'expected': expected_hash.lower(),
        'actual': actual_hash.lower(),
        'match': match,
    }

def main():
    parser = argparse.ArgumentParser(
        description="File Hash Calculator - Calculate hash values for files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python file_hash_calculator.py document.pdf
  python file_hash_calculator.py file.exe --all
  python file_hash_calculator.py file.zip -a sha512
  python file_hash_calculator.py file.iso --verify abc123...
        """
    )
    
    parser.add_argument("file", help="File to hash")
    parser.add_argument("-a", "--algorithm", default="sha256",
                        help=f"Hash algorithm (default: sha256)")
    parser.add_argument("--all", action="store_true",
                        help="Calculate all supported hashes")
    parser.add_argument("--verify", help="Verify against expected hash")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only output the hash")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"\n[!] File not found: {args.file}")
        sys.exit(1)
    
    try:
        file_size = os.path.getsize(args.file)
        
        if args.verify:
            print(f"\n  Verifying file: {args.file}")
            result = verify_hash(args.file, args.verify)
            
            print(f"\n  Algorithm: {result['algorithm'].upper()}")
            print(f"  Expected:  {result['expected']}")
            print(f"  Actual:    {result['actual']}")
            print(f"\n  Result: {'✓ MATCH' if result['match'] else '✗ MISMATCH'}")
        
        elif args.all:
            if args.quiet:
                hashes = calculate_all_hashes(args.file)
                for name, hash_val in hashes.items():
                    print(f"{name}: {hash_val}")
            else:
                print("\n" + "="*70)
                print(f"  FILE HASH CALCULATOR")
                print("="*70)
                print(f"\n  File: {args.file}")
                print(f"  Size: {format_size(file_size)}")
                print(f"\n  Hashes:")
                print("  " + "-"*66)
                
                hashes = calculate_all_hashes(args.file)
                for name, hash_val in hashes.items():
                    print(f"    {name:<12} {hash_val}")
                
                print("\n" + "="*70)
        
        else:
            hash_value = calculate_file_hash(args.file, args.algorithm)
            
            if args.quiet:
                print(hash_value)
            else:
                print("\n" + "="*70)
                print("  FILE HASH CALCULATOR")
                print("="*70)
                print(f"\n  File: {args.file}")
                print(f"  Size: {format_size(file_size)}")
                print(f"  Algorithm: {args.algorithm.upper()}")
                print(f"\n  Hash: {hash_value}")
                print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
