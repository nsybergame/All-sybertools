#!/usr/bin/env python3
"""
PASSWORD GENERATOR
==================

Generate strong, secure passwords with customizable options.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Use generated passwords responsibly.

Author: CyberSecurity Tools Hub
"""

import random
import string
import argparse
import sys
import secrets

def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_similar: bool = False,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generate a secure random password.
    
    Args:
        length: Password length
        uppercase: Include uppercase letters
        lowercase: Include lowercase letters
        digits: Include digits
        symbols: Include special symbols
        exclude_similar: Exclude similar characters (l, 1, I, O, 0)
        exclude_ambiguous: Exclude ambiguous symbols
    
    Returns:
        Generated password string
    """
    # Character sets
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digit = string.digits
    symbol = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Characters to exclude
    similar_chars = 'l1IO0'
    ambiguous_symbols = '{}[]()/\\\'"`~,;:.<>'
    
    # Apply exclusions
    if exclude_similar:
        upper = ''.join(c for c in upper if c not in similar_chars)
        lower = ''.join(c for c in lower if c not in similar_chars)
        digit = ''.join(c for c in digit if c not in similar_chars)
    
    if exclude_ambiguous:
        symbol = ''.join(c for c in symbol if c not in ambiguous_symbols)
    
    # Build character pool
    char_pool = ''
    required_chars = []
    
    if uppercase:
        char_pool += upper
        if upper:
            required_chars.append(secrets.choice(upper))
    if lowercase:
        char_pool += lower
        if lower:
            required_chars.append(secrets.choice(lower))
    if digits:
        char_pool += digit
        if digit:
            required_chars.append(secrets.choice(digit))
    if symbols:
        char_pool += symbol
        if symbol:
            required_chars.append(secrets.choice(symbol))
    
    if not char_pool:
        char_pool = lower + digit  # fallback
    
    # Generate password
    remaining_length = length - len(required_chars)
    if remaining_length < 0:
        remaining_length = 0
    
    password_chars = required_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]
    
    # Shuffle using secrets for cryptographic randomness
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)

def generate_passphrase(word_count: int = 4, separator: str = '-', min_word_length: int = 3) -> str:
    """
    Generate a passphrase using random words.
    
    Args:
        word_count: Number of words
        separator: Word separator
        min_word_length: Minimum word length
    
    Returns:
        Generated passphrase
    """
    # Common English words (simplified list)
    words = [
        'apple', 'banana', 'cherry', 'dragon', 'elephant', 'forest',
        'galaxy', 'horizon', 'island', 'jungle', 'kitchen', 'lemon',
        'mountain', 'notebook', 'ocean', 'planet', 'quantum', 'rainbow',
        'sunset', 'thunder', 'umbrella', 'violet', 'window', 'yellow',
        'zebra', 'bridge', 'crystal', 'diamond', 'energy', 'flower',
        'garden', 'harmony', 'impulse', 'journey', 'kingdom', 'library',
        'miracle', 'network', 'orange', 'phoenix', 'quality', 'rocket',
        'shadow', 'tornado', 'universe', 'victory', 'whisper', 'xenon',
        'yellow', 'zeppelin', 'anchor', 'beacon', 'cosmos', 'destiny',
        'eclipse', 'falcon', 'guitar', 'hero', 'impact', 'jade'
    ]
    
    selected_words = [secrets.choice(words).capitalize() for _ in range(word_count)]
    return separator.join(selected_words)

def calculate_entropy(password: str) -> float:
    """Calculate password entropy in bits."""
    char_pool_size = 0
    
    if any(c in string.ascii_lowercase for c in password):
        char_pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        char_pool_size += 26
    if any(c in string.digits for c in password):
        char_pool_size += 10
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        char_pool_size += 32
    
    if char_pool_size == 0:
        return 0
    
    import math
    return len(password) * math.log2(char_pool_size)

def main():
    parser = argparse.ArgumentParser(
        description="Password Generator - Generate secure passwords",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_generator.py                    # 16 char password
  python password_generator.py -l 20 -n 5         # 5 passwords of 20 chars
  python password_generator.py --passphrase       # Generate passphrase
  python password_generator.py -l 12 --no-symbols # 12 chars without symbols
        """
    )
    
    parser.add_argument("-l", "--length", type=int, default=16,
                        help="Password length (default: 16)")
    parser.add_argument("-n", "--number", type=int, default=1,
                        help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-uppercase", action="store_true",
                        help="Exclude uppercase letters")
    parser.add_argument("--no-lowercase", action="store_true",
                        help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true",
                        help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_true",
                        help="Exclude special symbols")
    parser.add_argument("--exclude-similar", action="store_true",
                        help="Exclude similar characters (l, 1, I, O, 0)")
    parser.add_argument("--exclude-ambiguous", action="store_true",
                        help="Exclude ambiguous symbols")
    parser.add_argument("--passphrase", action="store_true",
                        help="Generate passphrase instead")
    parser.add_argument("--words", type=int, default=4,
                        help="Number of words for passphrase (default: 4)")
    parser.add_argument("--separator", default="-",
                        help="Passphrase word separator (default: -)")
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  PASSWORD GENERATOR - CyberSecurity Tools Hub")
    print("="*60)
    
    try:
        if args.passphrase:
            print(f"\n  Generating {args.number} passphrase(s) with {args.words} words:\n")
            for i in range(args.number):
                passphrase = generate_passphrase(args.words, args.separator)
                entropy = calculate_entropy(passphrase)
                print(f"  {i+1}. {passphrase}")
                print(f"     Entropy: {entropy:.1f} bits\n")
        else:
            print(f"\n  Generating {args.number} password(s) of {args.length} characters:\n")
            
            for i in range(args.number):
                password = generate_password(
                    length=args.length,
                    uppercase=not args.no_uppercase,
                    lowercase=not args.no_lowercase,
                    digits=not args.no_digits,
                    symbols=not args.no_symbols,
                    exclude_similar=args.exclude_similar,
                    exclude_ambiguous=args.exclude_ambiguous
                )
                entropy = calculate_entropy(password)
                
                print(f"  {i+1}. {password}")
                print(f"     Length: {len(password)} | Entropy: {entropy:.1f} bits")
                
                # Show character types used
                types = []
                if any(c.isupper() for c in password):
                    types.append("uppercase")
                if any(c.islower() for c in password):
                    types.append("lowercase")
                if any(c.isdigit() for c in password):
                    types.append("digits")
                if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
                    types.append("symbols")
                print(f"     Contains: {', '.join(types)}\n")
        
        print("="*60)
        print("  TIP: Store passwords securely in a password manager!")
        print("="*60 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
