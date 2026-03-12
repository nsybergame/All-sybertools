#!/usr/bin/env python3
"""
PASSWORD STRENGTH CHECKER
=========================

Analyze password strength and provide feedback.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Do not use for malicious purposes.

Author: CyberSecurity Tools Hub
"""

import re
import math
import argparse
import sys
from typing import Tuple, List

# Common weak passwords
COMMON_PASSWORDS = {
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
    'princess', 'welcome', 'shadow', 'superman', 'michael', 'football',
    'password1', 'password123', 'admin', 'letmein', 'login', 'starwars',
    'passw0rd', 'hello', 'charlie', 'donald', 'password2', 'asdfgh',
    'qwertyuiop', 'solo', '654321', '7777777', 'fuckyou', 'amanda',
    'jordan', 'harley', 'ranger', 'hunter', 'thomas', 'robert', 'soccer',
    'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'fuckme'
}

def calculate_entropy(password: str) -> float:
    """Calculate password entropy in bits."""
    char_pool = 0
    
    if re.search(r'[a-z]', password):
        char_pool += 26
    if re.search(r'[A-Z]', password):
        char_pool += 26
    if re.search(r'[0-9]', password):
        char_pool += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        char_pool += 32
    if re.search(r'\s', password):
        char_pool += 1
    
    if char_pool == 0:
        return 0
    
    return len(password) * math.log2(char_pool)

def check_password_strength(password: str) -> Tuple[int, str, List[str]]:
    """
    Check password strength and return score, rating, and suggestions.
    
    Args:
        password: Password to analyze
    
    Returns:
        Tuple of (score, rating, suggestions)
    """
    score = 0
    suggestions = []
    
    # Length checks
    if len(password) < 8:
        suggestions.append("❌ Password too short (minimum 8 characters)")
        score -= 10
    elif len(password) < 12:
        suggestions.append("⚠️ Consider using at least 12 characters")
        score += 10
    elif len(password) >= 16:
        suggestions.append("✓ Good length (16+ characters)")
        score += 25
    else:
        score += 15
    
    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
    has_space = ' ' in password
    
    if not has_lower:
        suggestions.append("❌ Add lowercase letters")
    else:
        score += 5
    
    if not has_upper:
        suggestions.append("❌ Add uppercase letters")
    else:
        score += 5
    
    if not has_digit:
        suggestions.append("❌ Add numbers")
    else:
        score += 5
    
    if not has_symbol:
        suggestions.append("❌ Add special characters (!@#$%^&*)")
    else:
        score += 10
    
    if has_space:
        suggestions.append("✓ Contains spaces (good for passphrases)")
        score += 5
    
    # Variety bonus
    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    if variety_count >= 4:
        suggestions.append("✓ Excellent character variety")
        score += 10
    
    # Pattern checks
    if re.search(r'(.)\1{2,}', password):
        suggestions.append("⚠️ Avoid repeated characters")
        score -= 5
    
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        suggestions.append("⚠️ Avoid sequential letters")
        score -= 5
    
    if re.search(r'(012|123|234|345|456|567|678|789)', password):
        suggestions.append("⚠️ Avoid sequential numbers")
        score -= 5
    
    if re.search(r'(qwerty|asdf|zxcv)', password.lower()):
        suggestions.append("⚠️ Avoid keyboard patterns")
        score -= 5
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append("❌ This is a commonly used password!")
        score -= 30
    
    # Check if password contains common words
    common_patterns = ['password', 'admin', 'user', 'login', 'welcome', 'hello']
    for pattern in common_patterns:
        if pattern in password.lower():
            suggestions.append(f"⚠️ Avoid common word: '{pattern}'")
            score -= 5
    
    # Dictionary words check
    words = re.findall(r'[a-zA-Z]+', password.lower())
    if any(len(w) > 4 and w in COMMON_PASSWORDS for w in words):
        suggestions.append("⚠️ Contains dictionary words")
        score -= 5
    
    # Entropy calculation
    entropy = calculate_entropy(password)
    if entropy >= 60:
        suggestions.append(f"✓ High entropy: {entropy:.1f} bits")
        score += 15
    elif entropy >= 40:
        suggestions.append(f"⚠️ Moderate entropy: {entropy:.1f} bits")
        score += 5
    else:
        suggestions.append(f"❌ Low entropy: {entropy:.1f} bits")
        score -= 5
    
    # Normalize score
    score = max(0, min(100, score + 50))
    
    # Determine rating
    if score >= 80:
        rating = "Very Strong"
    elif score >= 60:
        rating = "Strong"
    elif score >= 40:
        rating = "Moderate"
    elif score >= 20:
        rating = "Weak"
    else:
        rating = "Very Weak"
    
    return score, rating, suggestions

def get_crack_time(password: str) -> str:
    """Estimate time to crack password."""
    entropy = calculate_entropy(password)
    
    # Assume 10 billion guesses per second (modern GPU)
    guesses_per_second = 10_000_000_000
    combinations = 2 ** entropy
    seconds = combinations / guesses_per_second / 2  # Average
    
    if seconds < 1:
        return "Instant"
    elif seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.0f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.0f} days"
    elif seconds < 31536000 * 100:
        return f"{seconds/31536000:.0f} years"
    elif seconds < 31536000 * 1000000:
        return f"{seconds/31536000/1000:.0f} thousand years"
    else:
        return "Centuries+"

def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker - Analyze password security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_strength_checker.py                    # Interactive mode
  python password_strength_checker.py -p "MyP@ssw0rd"    # Check specific password
        """
    )
    
    parser.add_argument("-p", "--password", help="Password to check")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only show rating")
    
    args = parser.parse_args()
    
    try:
        password = args.password
        if not password:
            print("\n  Enter password to check: ", end="")
            import getpass
            password = getpass.getpass()
        
        score, rating, suggestions = check_password_strength(password)
        crack_time = get_crack_time(password)
        entropy = calculate_entropy(password)
        
        if args.quiet:
            print(f"{rating} ({score}/100)")
            return
        
        print("\n" + "="*60)
        print("  PASSWORD STRENGTH ANALYSIS")
        print("="*60)
        
        # Strength bar
        bar_length = 40
        filled = int(bar_length * score / 100)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        # Color indicator
        if score >= 80:
            color_indicator = "🟢"
        elif score >= 60:
            color_indicator = "🟡"
        elif score >= 40:
            color_indicator = "🟠"
        else:
            color_indicator = "🔴"
        
        print(f"\n  Strength: {color_indicator} {rating}")
        print(f"  Score: {score}/100")
        print(f"  [{bar}]")
        
        print(f"\n  Length: {len(password)} characters")
        print(f"  Entropy: {entropy:.1f} bits")
        print(f"  Est. crack time: {crack_time}")
        
        print(f"\n  Analysis:")
        for suggestion in suggestions:
            print(f"    {suggestion}")
        
        print("\n" + "="*60)
        print("  TIP: Use a password manager for best security!")
        print("="*60 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
