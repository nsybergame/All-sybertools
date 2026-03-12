#!/usr/bin/env python3
"""
BINARY CONVERTER
================

Convert text to binary and vice versa.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import argparse
import sys

def text_to_binary(text: str, separator: str = ' ') -> str:
    """
    Convert text to binary representation.
    
    Args:
        text: Text to convert
        separator: Separator between binary values
    
    Returns:
        Binary string
    """
    binary_values = []
    for char in text:
        binary_values.append(format(ord(char), '08b'))
    return separator.join(binary_values)

def binary_to_text(binary: str) -> str:
    """
    Convert binary to text.
    
    Args:
        binary: Binary string (with or without separators)
    
    Returns:
        Decoded text
    """
    # Remove any separators
    binary = binary.replace(' ', '').replace('\n', '').replace('\t', '')
    
    # Split into 8-bit chunks
    text = []
    for i in range(0, len(binary), 8):
        chunk = binary[i:i+8]
        if len(chunk) == 8:
            text.append(chr(int(chunk, 2)))
    
    return ''.join(text)

def text_to_hex(text: str, separator: str = ' ') -> str:
    """Convert text to hexadecimal."""
    hex_values = []
    for char in text:
        hex_values.append(format(ord(char), '02x'))
    return separator.join(hex_values)

def hex_to_text(hex_str: str) -> str:
    """Convert hexadecimal to text."""
    hex_str = hex_str.replace(' ', '').replace('\n', '')
    text = []
    for i in range(0, len(hex_str), 2):
        chunk = hex_str[i:i+2]
        if len(chunk) == 2:
            text.append(chr(int(chunk, 16)))
    return ''.join(text)

def text_to_octal(text: str, separator: str = ' ') -> str:
    """Convert text to octal."""
    octal_values = []
    for char in text:
        octal_values.append(format(ord(char), '03o'))
    return separator.join(octal_values)

def octal_to_text(octal: str) -> str:
    """Convert octal to text."""
    octal = octal.replace(' ', '').replace('\n', '')
    text = []
    for i in range(0, len(octal), 3):
        chunk = octal[i:i+3]
        if len(chunk) == 3:
            text.append(chr(int(chunk, 8)))
    return ''.join(text)

def text_to_decimal(text: str, separator: str = ' ') -> str:
    """Convert text to decimal (ASCII codes)."""
    decimal_values = []
    for char in text:
        decimal_values.append(str(ord(char)))
    return separator.join(decimal_values)

def decimal_to_text(decimal: str) -> str:
    """Convert decimal (ASCII codes) to text."""
    decimal = decimal.replace('\n', ' ').replace('\t', ' ')
    values = [int(d) for d in decimal.split() if d.strip()]
    return ''.join(chr(d) for d in values)

def analyze_text(text: str) -> dict:
    """Analyze text and return various representations."""
    return {
        'original': text,
        'binary': text_to_binary(text),
        'hex': text_to_hex(text),
        'octal': text_to_octal(text),
        'decimal': text_to_decimal(text),
        'length': len(text),
        'bits': len(text) * 8,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Binary Converter - Convert text to binary and vice versa",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python binary_converter.py -t "Hello"
  python binary_converter.py -b "01001000 01100101 01101100 01101100 01101111"
  python binary_converter.py -t "Secret" --all
  python binary_converter.py -x "48 65 6c 6c 6f" --from-hex
        """
    )
    
    parser.add_argument("-t", "--text", help="Text to convert")
    parser.add_argument("-b", "--binary", help="Binary to convert to text")
    parser.add_argument("-x", "--hex", help="Hexadecimal to convert")
    parser.add_argument("-o", "--octal", help="Octal to convert")
    parser.add_argument("-d", "--decimal", help="Decimal (ASCII codes) to convert")
    parser.add_argument("--from-hex", action="store_true", help="Convert hex to text")
    parser.add_argument("--from-octal", action="store_true", help="Convert octal to text")
    parser.add_argument("--from-decimal", action="store_true", help="Convert decimal to text")
    parser.add_argument("--all", action="store_true", help="Show all representations")
    parser.add_argument("-s", "--separator", default=" ", help="Separator for output")
    
    args = parser.parse_args()
    
    if not any([args.text, args.binary, args.hex, args.octal, args.decimal]):
        parser.print_help()
        print("\n[!] Please provide text or value to convert")
        sys.exit(1)
    
    try:
        print("\n" + "="*70)
        print("  BINARY CONVERTER - CyberSecurity Tools Hub")
        print("="*70)
        
        if args.text:
            text = args.text
            
            if args.all:
                analysis = analyze_text(text)
                print(f"\n  Original: {text}")
                print(f"  Length: {analysis['length']} characters ({analysis['bits']} bits)")
                print(f"\n  Binary:   {analysis['binary']}")
                print(f"  Hex:      {analysis['hex']}")
                print(f"  Octal:    {analysis['octal']}")
                print(f"  Decimal:  {analysis['decimal']}")
            else:
                binary = text_to_binary(text, args.separator)
                print(f"\n  Text: {text}")
                print(f"\n  Binary:\n  {binary}")
        
        elif args.binary:
            text = binary_to_text(args.binary)
            print(f"\n  Binary: {args.binary[:50]}{'...' if len(args.binary) > 50 else ''}")
            print(f"\n  Text:\n  {text}")
        
        elif args.hex:
            if args.from_hex:
                text = hex_to_text(args.hex)
                print(f"\n  Hex: {args.hex[:50]}{'...' if len(args.hex) > 50 else ''}")
                print(f"\n  Text:\n  {text}")
            else:
                hex_val = text_to_hex(args.hex, args.separator)
                print(f"\n  Text: {args.hex}")
                print(f"\n  Hex:\n  {hex_val}")
        
        elif args.octal:
            if args.from_octal:
                text = octal_to_text(args.octal)
                print(f"\n  Octal: {args.octal[:50]}{'...' if len(args.octal) > 50 else ''}")
                print(f"\n  Text:\n  {text}")
            else:
                octal_val = text_to_octal(args.octal, args.separator)
                print(f"\n  Text: {args.octal}")
                print(f"\n  Octal:\n  {octal_val}")
        
        elif args.decimal:
            if args.from_decimal:
                text = decimal_to_text(args.decimal)
                print(f"\n  Decimal: {args.decimal[:50]}{'...' if len(args.decimal) > 50 else ''}")
                print(f"\n  Text:\n  {text}")
            else:
                decimal_val = text_to_decimal(args.decimal, args.separator)
                print(f"\n  Text: {args.decimal}")
                print(f"\n  Decimal:\n  {decimal_val}")
        
        print("\n" + "="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
