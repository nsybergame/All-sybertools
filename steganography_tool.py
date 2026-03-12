#!/usr/bin/env python3
"""
STEGANOGRAPHY TOOL
==================

Hide and extract messages in images (LSB steganography).

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install Pillow

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import os

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

def text_to_binary(text: str) -> str:
    """Convert text to binary string."""
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary: str) -> str:
    """Convert binary string to text."""
    text = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if byte:
            text.append(chr(int(byte, 2)))
    return ''.join(text)

def encode_message(image_path: str, message: str, output_path: str) -> bool:
    """
    Hide a message in an image using LSB steganography.
    
    Args:
        image_path: Path to source image
        message: Message to hide
        output_path: Path to save output image
    
    Returns:
        True if successful
    """
    if not PILLOW_AVAILABLE:
        print("Pillow not installed. Install with: pip install Pillow")
        return False
    
    try:
        # Open image
        img = Image.open(image_path)
        
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = img.load()
        width, height = img.size
        
        # Add delimiter
        delimiter = '#####END#####'
        full_message = message + delimiter
        binary_message = text_to_binary(full_message)
        
        # Check if image can hold the message
        max_bits = width * height * 3
        if len(binary_message) > max_bits:
            print(f"Error: Image too small. Max characters: {max_bits // 8}")
            return False
        
        # Encode message
        bit_index = 0
        for y in range(height):
            for x in range(width):
                if bit_index >= len(binary_message):
                    break
                
                r, g, b = pixels[x, y]
                
                # Modify LSB of each channel
                if bit_index < len(binary_message):
                    r = (r & ~1) | int(binary_message[bit_index])
                    bit_index += 1
                
                if bit_index < len(binary_message):
                    g = (g & ~1) | int(binary_message[bit_index])
                    bit_index += 1
                
                if bit_index < len(binary_message):
                    b = (b & ~1) | int(binary_message[bit_index])
                    bit_index += 1
                
                pixels[x, y] = (r, g, b)
            
            if bit_index >= len(binary_message):
                break
        
        # Save image
        img.save(output_path, 'PNG')
        return True
    
    except Exception as e:
        print(f"Error: {e}")
        return False

def decode_message(image_path: str) -> str:
    """
    Extract hidden message from an image.
    
    Args:
        image_path: Path to image
    
    Returns:
        Extracted message
    """
    if not PILLOW_AVAILABLE:
        return "Error: Pillow not installed"
    
    try:
        img = Image.open(image_path)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = img.load()
        width, height = img.size
        
        # Extract LSBs
        binary_message = []
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                binary_message.append(str(r & 1))
                binary_message.append(str(g & 1))
                binary_message.append(str(b & 1))
        
        # Convert to text
        binary_string = ''.join(binary_message)
        message = binary_to_text(binary_string)
        
        # Find delimiter
        delimiter = '#####END#####'
        if delimiter in message:
            return message.split(delimiter)[0]
        
        return message[:1000]  # Return first 1000 chars if no delimiter
    
    except Exception as e:
        return f"Error: {e}"

def get_image_info(image_path: str) -> dict:
    """Get information about an image."""
    if not PILLOW_AVAILABLE:
        return {'error': 'Pillow not installed'}
    
    try:
        img = Image.open(image_path)
        
        max_message_size = (img.width * img.height * 3) // 8
        
        return {
            'path': image_path,
            'size': f"{img.width}x{img.height}",
            'mode': img.mode,
            'format': img.format,
            'max_message_chars': max_message_size,
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    parser = argparse.ArgumentParser(
        description="Steganography Tool - Hide and extract messages in images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python steganography_tool.py encode -i image.png -m "Secret message" -o output.png
  python steganography_tool.py decode -i output.png
  python steganography_tool.py info -i image.png
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Encode command
    encode_parser = subparsers.add_parser('encode', help='Hide message in image')
    encode_parser.add_argument('-i', '--image', required=True, help='Source image')
    encode_parser.add_argument('-m', '--message', required=True, help='Message to hide')
    encode_parser.add_argument('-o', '--output', required=True, help='Output image path')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Extract message from image')
    decode_parser.add_argument('-i', '--image', required=True, help='Image to decode')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Get image info')
    info_parser.add_argument('-i', '--image', required=True, help='Image file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if not PILLOW_AVAILABLE:
        print("\n[!] Pillow required. Install with: pip install Pillow")
        sys.exit(1)
    
    try:
        print("\n" + "="*70)
        print("  STEGANOGRAPHY TOOL - CyberSecurity Tools Hub")
        print("="*70)
        
        if args.command == 'encode':
            if not os.path.exists(args.image):
                print(f"\n[!] Image not found: {args.image}")
                sys.exit(1)
            
            print(f"\n  Encoding message in image...")
            print(f"  Source: {args.image}")
            print(f"  Message: {args.message[:50]}{'...' if len(args.message) > 50 else ''}")
            
            if encode_message(args.image, args.message, args.output):
                print(f"\n  ✓ Message encoded successfully!")
                print(f"  Output: {args.output}")
            else:
                print(f"\n  ✗ Failed to encode message")
        
        elif args.command == 'decode':
            if not os.path.exists(args.image):
                print(f"\n[!] Image not found: {args.image}")
                sys.exit(1)
            
            print(f"\n  Decoding message from image...")
            print(f"  Image: {args.image}")
            
            message = decode_message(args.image)
            
            print(f"\n  Extracted Message:")
            print("  " + "-"*66)
            print(f"  {message}")
            print("  " + "-"*66)
        
        elif args.command == 'info':
            if not os.path.exists(args.image):
                print(f"\n[!] Image not found: {args.image}")
                sys.exit(1)
            
            info = get_image_info(args.image)
            
            print(f"\n  Image Information:")
            print("  " + "-"*66)
            for key, value in info.items():
                print(f"    {key}: {value}")
        
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
