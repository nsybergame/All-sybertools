#!/usr/bin/env python3
"""
HASH CRACKER (DICTIONARY)
=========================

Educational tool for cracking hashes using dictionary attack.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only use on hashes you own or have explicit permission to crack.
Using this for unauthorized access is ILLEGAL.

Author: CyberSecurity Tools Hub
"""

import hashlib
import argparse
import sys
import os
from typing import Optional

SUPPORTED_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
}

# Small built-in wordlist for demonstration
BUILTIN_WORDLIST = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
    'princess', 'welcome', 'shadow', 'superman', 'michael', 'football',
    'password1', 'password123', 'admin', 'letmein', 'login', 'starwars',
    'passw0rd', 'hello', 'charlie', 'donald', 'password2', 'asdfgh',
    'qwertyuiop', 'solo', '654321', '7777777', 'amanda', 'jordan',
    'harley', 'ranger', 'hunter', 'thomas', 'robert', 'soccer',
    'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'test',
    'secret', 'root', 'toor', 'guest', 'default', 'changeme',
]

def hash_text(text: str, algorithm: str) -> str:
    """Hash text using specified algorithm."""
    hasher = SUPPORTED_ALGORITHMS[algorithm]()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def detect_algorithm(hash_value: str) -> Optional[str]:
    """Try to detect hash algorithm based on length."""
    length = len(hash_value)
    
    length_map = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512',
    }
    
    return length_map.get(length)

def crack_hash(hash_value: str, algorithm: str, wordlist: list, verbose: bool = False) -> Optional[str]:
    """
    Attempt to crack hash using dictionary attack.
    
    Args:
        hash_value: Hash to crack
        algorithm: Hash algorithm
        wordlist: List of passwords to try
        verbose: Show progress
    
    Returns:
        Cracked password or None
    """
    hash_value = hash_value.lower()
    
    for i, word in enumerate(wordlist):
        if verbose and i % 1000 == 0:
            print(f"\r  Tried {i:,} passwords...", end='', flush=True)
        
        # Try the word as-is
        if hash_text(word, algorithm) == hash_value:
            return word
        
        # Try common variations
        variations = [
            word.upper(),
            word.capitalize(),
            word + '1',
            word + '123',
            word + '!@#',
            word[::-1],  # reversed
        ]
        
        for var in variations:
            if hash_text(var, algorithm) == hash_value:
                return var
    
    if verbose:
        print()  # New line after progress
    
    return None

def load_wordlist(filepath: str) -> list:
    """Load wordlist from file."""
    words = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.append(word)
    except Exception as e:
        print(f"[!] Error loading wordlist: {e}")
    return words

def main():
    parser = argparse.ArgumentParser(
        description="Hash Cracker (Dictionary) - Educational tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Unauthorized hash cracking is ILLEGAL.

Examples:
  python hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -a md5
  python hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 --detect
  python hash_cracker.py -H <hash> -w rockyou.txt -v
        """
    )
    
    parser.add_argument("-H", "--hash", required=True,
                        help="Hash value to crack")
    parser.add_argument("-a", "--algorithm",
                        choices=list(SUPPORTED_ALGORITHMS.keys()),
                        help="Hash algorithm")
    parser.add_argument("--detect", action="store_true",
                        help="Auto-detect algorithm")
    parser.add_argument("-w", "--wordlist",
                        help="Path to wordlist file")
    parser.add_argument("--builtin", action="store_true",
                        help="Use built-in wordlist (small, for demo)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  WARNING: FOR EDUCATIONAL PURPOSES ONLY!")
    print("  Unauthorized hash cracking is ILLEGAL!")
    print("!"*60 + "\n")
    
    try:
        hash_value = args.hash.strip().lower()
        
        # Determine algorithm
        if args.detect or not args.algorithm:
            detected = detect_algorithm(hash_value)
            if detected:
                algorithm = detected
                print(f"  Auto-detected algorithm: {algorithm.upper()}")
            else:
                print("[!] Could not detect algorithm. Please specify with -a")
                sys.exit(1)
        else:
            algorithm = args.algorithm
        
        # Load wordlist
        if args.wordlist:
            if not os.path.exists(args.wordlist):
                print(f"[!] Wordlist not found: {args.wordlist}")
                sys.exit(1)
            wordlist = load_wordlist(args.wordlist)
            print(f"  Loaded {len(wordlist):,} words from wordlist")
        elif args.builtin:
            wordlist = BUILTIN_WORDLIST
            print(f"  Using built-in wordlist ({len(wordlist)} words)")
        else:
            wordlist = BUILTIN_WORDLIST
            print(f"  Using built-in wordlist ({len(wordlist)} words)")
            print("  Tip: Use -w to specify a wordlist file for better results")
        
        print(f"\n  Cracking {algorithm.upper()} hash: {hash_value[:32]}...")
        print("  " + "-"*56)
        
        # Crack
        result = crack_hash(hash_value, algorithm, wordlist, args.verbose)
        
        if result:
            print(f"\n  ✓ PASSWORD FOUND: {result}")
            print("\n" + "="*60)
        else:
            print(f"\n  ✗ Password not found in wordlist")
            print("  Try a larger wordlist or different algorithm")
            print("\n" + "="*60)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
