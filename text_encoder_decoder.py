#!/usr/bin/env python3
"""
TEXT ENCODER/DECODER
====================

Encode and decode text in various formats.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import base64
import argparse
import sys
import urllib.parse
import binascii
from typing import Tuple, Optional

def base64_encode(text: str) -> str:
    """Encode text to Base64."""
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str) -> Tuple[str, bool]:
    """Decode Base64 text."""
    try:
        return base64.b64decode(text).decode(), True
    except:
        return "Invalid Base64", False

def hex_encode(text: str) -> str:
    """Encode text to Hexadecimal."""
    return text.encode().hex()

def hex_decode(text: str) -> Tuple[str, bool]:
    """Decode Hexadecimal text."""
    try:
        return bytes.fromhex(text).decode(), True
    except:
        return "Invalid Hex", False

def url_encode(text: str) -> str:
    """URL encode text."""
    return urllib.parse.quote(text, safe='')

def url_decode(text: str) -> Tuple[str, bool]:
    """URL decode text."""
    try:
        return urllib.parse.unquote(text), True
    except:
        return "Invalid URL encoding", False

def rot13_encode(text: str) -> str:
    """ROT13 encode/decode (symmetric)."""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

def ascii_encode(text: str) -> str:
    """Convert text to ASCII codes."""
    return ' '.join(str(ord(c)) for c in text)

def ascii_decode(text: str) -> Tuple[str, bool]:
    """Convert ASCII codes to text."""
    try:
        codes = [int(c) for c in text.split()]
        return ''.join(chr(c) for c in codes), True
    except:
        return "Invalid ASCII codes", False

def binary_encode(text: str) -> str:
    """Convert text to binary."""
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_decode(text: str) -> Tuple[str, bool]:
    """Convert binary to text."""
    try:
        binary_values = text.split()
        return ''.join(chr(int(b, 2)) for b in binary_values), True
    except:
        return "Invalid binary", False

def reverse_text(text: str) -> str:
    """Reverse text."""
    return text[::-1]

def leetspeak_encode(text: str) -> str:
    """Convert to leetspeak."""
    leet_map = {
        'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5',
        't': '7', 'l': '1', 'b': '8', 'g': '9', 'z': '2'
    }
    result = []
    for char in text.lower():
        result.append(leet_map.get(char, char))
    return ''.join(result)

ENCODINGS = {
    'base64': (base64_encode, base64_decode),
    'hex': (hex_encode, hex_decode),
    'url': (url_encode, url_decode),
    'rot13': (rot13_encode, rot13_encode),  # ROT13 is symmetric
    'ascii': (ascii_encode, ascii_decode),
    'binary': (binary_encode, binary_decode),
    'reverse': (reverse_text, reverse_text),
    'leetspeak': (leetspeak_encode, None),
}

def detect_encoding(text: str) -> list:
    """Try to detect possible encodings."""
    detected = []
    
    # Check Base64
    try:
        if len(text) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text):
            decoded, success = base64_decode(text)
            if success and decoded.isprintable():
                detected.append(('base64', decoded))
    except:
        pass
    
    # Check Hex
    try:
        if all(c in '0123456789abcdefABCDEF' for c in text) and len(text) % 2 == 0:
            decoded, success = hex_decode(text)
            if success and decoded.isprintable():
                detected.append(('hex', decoded))
    except:
        pass
    
    # Check URL encoding
    if '%' in text:
        decoded, success = url_decode(text)
        if success:
            detected.append(('url', decoded))
    
    # Check binary
    if all(c in '01 ' for c in text):
        decoded, success = binary_decode(text)
        if success:
            detected.append(('binary', decoded))
    
    # Check ASCII codes
    if all(c.isdigit() or c.isspace() for c in text):
        decoded, success = ascii_decode(text)
        if success and decoded.isprintable():
            detected.append(('ascii', decoded))
    
    return detected

def main():
    parser = argparse.ArgumentParser(
        description="Text Encoder/Decoder - Encode and decode text in various formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported encodings:
  base64    - Base64 encoding
  hex       - Hexadecimal encoding
  url       - URL encoding
  rot13     - ROT13 cipher
  ascii     - ASCII codes
  binary    - Binary representation
  reverse   - Reverse text
  leetspeak - Convert to leetspeak

Examples:
  python text_encoder_decoder.py -e base64 -t "Hello World"
  python text_encoder_decoder.py -d base64 -t "SGVsbG8gV29ybGQ="
  python text_encoder_decoder.py --detect -t "SGVsbG8gV29ybGQ="
  python text_encoder_decoder.py --all -t "secret"
        """
    )
    
    parser.add_argument("-e", "--encode", choices=list(ENCODINGS.keys()),
                        help="Encode text")
    parser.add_argument("-d", "--decode", choices=list(ENCODINGS.keys()),
                        help="Decode text")
    parser.add_argument("-t", "--text", help="Text to encode/decode")
    parser.add_argument("--detect", action="store_true",
                        help="Detect possible encodings")
    parser.add_argument("--all", action="store_true",
                        help="Try all encodings")
    parser.add_argument("-f", "--file", help="Read text from file")
    
    args = parser.parse_args()
    
    if not args.text and not args.file:
        parser.print_help()
        print("\n[!] Please provide text with -t or file with -f")
        sys.exit(1)
    
    try:
        # Get text
        if args.file:
            with open(args.file, 'r') as f:
                text = f.read()
        else:
            text = args.text
        
        print("\n" + "="*70)
        print("  TEXT ENCODER/DECODER - CyberSecurity Tools Hub")
        print("="*70)
        
        if args.detect:
            print(f"\n  Input: {text[:50]}{'...' if len(text) > 50 else ''}")
            print("\n  Detected possible encodings:")
            print("  " + "-"*66)
            
            detected = detect_encoding(text)
            if detected:
                for encoding, decoded in detected:
                    print(f"    {encoding}: {decoded[:50]}{'...' if len(decoded) > 50 else ''}")
            else:
                print("    No known encoding detected")
        
        elif args.all:
            print(f"\n  Input: {text}")
            print("\n  All encodings:")
            print("  " + "-"*66)
            
            for name, (encoder, decoder) in ENCODINGS.items():
                if encoder:
                    encoded = encoder(text)
                    print(f"\n  {name.upper()}:")
                    print(f"    Encoded: {encoded[:100]}{'...' if len(encoded) > 100 else ''}")
                    
                    if decoder:
                        decoded, success = decoder(encoded)
                        if success:
                            print(f"    Decoded: {decoded}")
        
        elif args.encode:
            encoder, _ = ENCODINGS[args.encode]
            result = encoder(text)
            print(f"\n  Encoding: {args.encode.upper()}")
            print(f"  Input: {text[:100]}{'...' if len(text) > 100 else ''}")
            print(f"\n  Result:")
            print(f"  {result}")
        
        elif args.decode:
            _, decoder = ENCODINGS[args.decode]
            if decoder:
                result, success = decoder(text)
                if success:
                    print(f"\n  Decoding: {args.decode.upper()}")
                    print(f"  Input: {text[:100]}{'...' if len(text) > 100 else ''}")
                    print(f"\n  Result:")
                    print(f"  {result}")
                else:
                    print(f"\n  [!] Error: {result}")
            else:
                print(f"\n  [!] Decoding not supported for {args.decode}")
        
        else:
            parser.print_help()
        
        print("\n" + "="*70 + "\n")
        
    except FileNotFoundError:
        print(f"\n[!] File not found: {args.file}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
