#!/usr/bin/env python3
"""
SHA-256 Hash Cracker
====================
A comprehensive tool for cracking SHA-256 hashes using various methods.

Features:
- Dictionary Attack: Uses wordlist to find matches
- Brute Force Attack: Tries all possible combinations
- Hash Generation: Generate SHA-256 hash from text
- Progress Display: Shows real-time cracking progress

Usage:
    python sha256_cracker.py --hash <hash> --wordlist <wordlist_file>
    python sha256_cracker.py --hash <hash> --bruteforce --length <max_length>
    python sha256_cracker.py --generate <text>

Author: Security Research Tool
License: Educational Use Only
"""

import hashlib
import argparse
import sys
import itertools
import string
import time
from datetime import datetime
from typing import Optional, Generator


class SHA256Cracker:
    """SHA-256 Hash Cracker with multiple attack methods."""
    
    def __init__(self, target_hash: str):
        """
        Initialize the cracker with a target hash.
        
        Args:
            target_hash: The SHA-256 hash to crack (64 hex characters)
        """
        self.target_hash = target_hash.lower().strip()
        self.attempts = 0
        self.start_time = None
        
        # Validate hash format
        if len(self.target_hash) != 64 or not all(c in '0123456789abcdef' for c in self.target_hash):
            raise ValueError("Invalid SHA-256 hash format. Hash must be 64 hexadecimal characters.")
    
    def _hash_text(self, text: str) -> str:
        """
        Generate SHA-256 hash of a text string.
        
        Args:
            text: Input string to hash
            
        Returns:
            Hexadecimal string of the SHA-256 hash
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    def _progress_callback(self, password: str, found: bool = False) -> None:
        """
        Display progress during cracking attempts.
        
        Args:
            password: Current password being tested
            found: Whether the password was found
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        status = "FOUND!" if found else "Testing"
        sys.stdout.write(f"\r[{status}] Attempts: {self.attempts:,} | Rate: {rate:,.0f} hash/s | Current: {password[:20]:<20}")
        sys.stdout.flush()
    
    def dictionary_attack(self, wordlist_path: str, verbose: bool = True) -> Optional[str]:
        """
        Perform a dictionary attack using a wordlist file.
        
        Args:
            wordlist_path: Path to the wordlist file
            verbose: Whether to show progress
            
        Returns:
            The cracked password if found, None otherwise
        """
        self.attempts = 0
        self.start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"Starting Dictionary Attack")
        print(f"Target Hash: {self.target_hash}")
        print(f"Wordlist: {wordlist_path}")
        print(f"{'='*60}\n")
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    self.attempts += 1
                    
                    if self._hash_text(password) == self.target_hash:
                        if verbose:
                            self._progress_callback(password, found=True)
                        self._print_result(password, True)
                        return password
                    
                    if verbose and self.attempts % 1000 == 0:
                        self._progress_callback(password)
                        
        except FileNotFoundError:
            print(f"Error: Wordlist file '{wordlist_path}' not found.")
            return None
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return None
        
        if verbose:
            print(f"\n\nDictionary attack completed. Password not found in wordlist.")
        return None
    
    def brute_force_attack(self, max_length: int = 4, charset: str = None, verbose: bool = True) -> Optional[str]:
        """
        Perform a brute force attack trying all possible combinations.
        
        Args:
            max_length: Maximum password length to try
            charset: Character set to use (default: lowercase letters + digits)
            verbose: Whether to show progress
            
        Returns:
            The cracked password if found, None otherwise
        """
        self.attempts = 0
        self.start_time = time.time()
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"\n{'='*60}")
        print(f"Starting Brute Force Attack")
        print(f"Target Hash: {self.target_hash}")
        print(f"Max Length: {max_length}")
        print(f"Charset: {charset} ({len(charset)} characters)")
        print(f"{'='*60}\n")
        
        # Calculate total combinations
        total = sum(len(charset) ** i for i in range(1, max_length + 1))
        print(f"Total combinations to try: {total:,}")
        print(f"Estimated time at 100k hash/s: {total/100000:.1f} seconds\n")
        
        for length in range(1, max_length + 1):
            if verbose:
                print(f"\nTrying length {length}...")
            
            for candidate in itertools.product(charset, repeat=length):
                password = ''.join(candidate)
                self.attempts += 1
                
                if self._hash_text(password) == self.target_hash:
                    if verbose:
                        self._progress_callback(password, found=True)
                    self._print_result(password, True)
                    return password
                
                if verbose and self.attempts % 50000 == 0:
                    self._progress_callback(password)
        
        if verbose:
            print(f"\n\nBrute force attack completed. Password not found.")
        return None
    
    def hybrid_attack(self, wordlist_path: str, rules: list = None, verbose: bool = True) -> Optional[str]:
        """
        Perform a hybrid attack combining dictionary with rule-based mutations.
        
        Args:
            wordlist_path: Path to the wordlist file
            rules: List of mutation rules to apply
            verbose: Whether to show progress
            
        Returns:
            The cracked password if found, None otherwise
        """
        self.attempts = 0
        self.start_time = time.time()
        
        if rules is None:
            rules = [
                lambda x: x,                          # Original
                lambda x: x.upper(),                  # Uppercase
                lambda x: x.capitalize(),             # Capitalize
                lambda x: x + "123",                  # Append 123
                lambda x: x + "!",                    # Append !
                lambda x: "123" + x,                  # Prepend 123
                lambda x: x[::-1],                    # Reverse
                lambda x: x.replace('a', '@'),        # Leet speak
                lambda x: x.replace('e', '3'),        # Leet speak
                lambda x: x + x,                      # Double
            ]
        
        print(f"\n{'='*60}")
        print(f"Starting Hybrid Attack (Dictionary + Rules)")
        print(f"Target Hash: {self.target_hash}")
        print(f"Wordlist: {wordlist_path}")
        print(f"Rules: {len(rules)} mutation rules")
        print(f"{'='*60}\n")
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    base_word = line.strip()
                    
                    for rule in rules:
                        try:
                            password = rule(base_word)
                            self.attempts += 1
                            
                            if self._hash_text(password) == self.target_hash:
                                if verbose:
                                    self._progress_callback(password, found=True)
                                self._print_result(password, True)
                                return password
                            
                            if verbose and self.attempts % 1000 == 0:
                                self._progress_callback(password)
                        except:
                            continue
                            
        except FileNotFoundError:
            print(f"Error: Wordlist file '{wordlist_path}' not found.")
            return None
        
        if verbose:
            print(f"\n\nHybrid attack completed. Password not found.")
        return None
    
    def _print_result(self, password: str, found: bool) -> None:
        """
        Print the result of the cracking attempt.
        
        Args:
            password: The found password
            found: Whether the password was found
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n\n{'='*60}")
        if found:
            print(f"PASSWORD FOUND!")
            print(f"{'='*60}")
            print(f"Password: {password}")
            print(f"Hash: {self.target_hash}")
            print(f"Attempts: {self.attempts:,}")
            print(f"Time: {elapsed:.2f} seconds")
            print(f"Average Rate: {self.attempts/elapsed:,.0f} hash/s")
        else:
            print(f"Password not found after {self.attempts:,} attempts")
        print(f"{'='*60}\n")
    
    @staticmethod
    def generate_hash(text: str) -> str:
        """
        Generate SHA-256 hash from text.
        
        Args:
            text: Input text to hash
            
        Returns:
            SHA-256 hash as hexadecimal string
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()


def create_sample_wordlist(path: str = "wordlist.txt") -> None:
    """
    Create a sample wordlist for testing.
    
    Args:
        path: Path to save the wordlist
    """
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football", "password1",
        "hello", "welcome", "admin", "login", "starwars",
        "pass", "test", "guest", "root", "toor",
        "changeme", "default", "1234", "12345", "123",
        "secret", "secure", "private", "public", "user"
    ]
    
    with open(path, 'w') as f:
        for password in common_passwords:
            f.write(password + '\n')
    
    print(f"Sample wordlist created at: {path}")
    print(f"Contains {len(common_passwords)} common passwords")


def main():
    """Main function to handle command line arguments and execute cracking."""
    parser = argparse.ArgumentParser(
        description="SHA-256 Hash Cracker - Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a hash
  python sha256_cracker.py --generate "password123"
  
  # Dictionary attack
  python sha256_cracker.py --hash <hash> --wordlist wordlist.txt
  
  # Brute force attack (up to 4 characters)
  python sha256_cracker.py --hash <hash> --bruteforce --length 4
  
  # Create sample wordlist
  python sha256_cracker.py --create-wordlist
        """
    )
    
    # Main operation modes
    parser.add_argument('--hash', '-H', type=str, help='Target SHA-256 hash to crack')
    parser.add_argument('--generate', '-g', type=str, help='Generate SHA-256 hash from text')
    parser.add_argument('--create-wordlist', action='store_true', help='Create a sample wordlist file')
    
    # Attack options
    parser.add_argument('--wordlist', '-w', type=str, help='Path to wordlist file for dictionary attack')
    parser.add_argument('--bruteforce', '-b', action='store_true', help='Perform brute force attack')
    parser.add_argument('--hybrid', action='store_true', help='Perform hybrid attack (dictionary + rules)')
    
    # Brute force options
    parser.add_argument('--length', '-l', type=int, default=4, help='Max password length for brute force (default: 4)')
    parser.add_argument('--charset', '-c', type=str, help='Custom charset for brute force (default: a-z0-9)')
    
    # Output options
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress progress output')
    
    args = parser.parse_args()
    
    # Handle generate mode
    if args.generate:
        hash_result = SHA256Cracker.generate_hash(args.generate)
        print(f"\nInput: {args.generate}")
        print(f"SHA-256: {hash_result}\n")
        return
    
    # Handle create wordlist
    if args.create_wordlist:
        create_sample_wordlist()
        return
    
    # Require hash for cracking operations
    if not args.hash:
        parser.print_help()
        print("\nError: --hash is required for cracking operations")
        sys.exit(1)
    
    try:
        cracker = SHA256Cracker(args.hash)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Determine attack method
    if args.wordlist and args.hybrid:
        cracker.hybrid_attack(args.wordlist, verbose=not args.quiet)
    elif args.wordlist:
        cracker.dictionary_attack(args.wordlist, verbose=not args.quiet)
    elif args.bruteforce:
        cracker.brute_force_attack(
            max_length=args.length,
            charset=args.charset,
            verbose=not args.quiet
        )
    else:
        print("Please specify an attack method:")
        print("  --wordlist <file>  : Dictionary attack")
        print("  --bruteforce       : Brute force attack")
        print("  --hybrid           : Hybrid attack (requires --wordlist)")
        sys.exit(1)


if __name__ == "__main__":
    main()
