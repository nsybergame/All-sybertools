#!/usr/bin/env python3
"""
QR CODE GENERATOR
=================

Generate QR codes from text or URLs.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install qrcode[pil]

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import os

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

def generate_qr(
    data: str,
    output_file: str = None,
    error_correction: str = 'M',
    box_size: int = 10,
    border: int = 4,
    fill_color: str = 'black',
    back_color: str = 'white'
):
    """
    Generate QR code.
    
    Args:
        data: Data to encode
        output_file: Output file path
        error_correction: Error correction level (L, M, Q, H)
        box_size: Size of each box in pixels
        border: Border size in boxes
        fill_color: QR code color
        back_color: Background color
    
    Returns:
        QR code image object
    """
    if not QRCODE_AVAILABLE:
        raise ImportError("qrcode library not installed. Install with: pip install qrcode[pil]")
    
    # Error correction levels
    ec_levels = {
        'L': ERROR_CORRECT_L,  # 7%
        'M': ERROR_CORRECT_M,  # 15%
        'Q': ERROR_CORRECT_Q,  # 25%
        'H': ERROR_CORRECT_H,  # 30%
    }
    
    # Create QR code
    qr = qrcode.QRCode(
        version=1,  # Auto-determine version
        error_correction=ec_levels.get(error_correction.upper(), ERROR_CORRECT_M),
        box_size=box_size,
        border=border,
    )
    
    qr.add_data(data)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color=fill_color, back_color=back_color)
    
    # Save or return
    if output_file:
        img.save(output_file)
        return output_file
    
    return img

def print_ascii_qr(data: str):
    """Print QR code as ASCII art to terminal."""
    if not QRCODE_AVAILABLE:
        print("[!] qrcode library not installed")
        return
    
    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.make()
    
    # Print as ASCII
    qr.print_ascii(invert=True)

def generate_wifi_qr(ssid: str, password: str, security: str = 'WPA', hidden: bool = False) -> str:
    """Generate WiFi configuration string for QR code."""
    hidden_str = 'H:true;' if hidden else ''
    return f'WIFI:T:{security};S:{ssid};P:{password};{hidden_str};'

def generate_vcard_qr(name: str, phone: str = '', email: str = '', org: str = '', url: str = '') -> str:
    """Generate vCard string for QR code."""
    vcard = 'BEGIN:VCARD\nVERSION:3.0\n'
    vcard += f'FN:{name}\n'
    if phone:
        vcard += f'TEL:{phone}\n'
    if email:
        vcard += f'EMAIL:{email}\n'
    if org:
        vcard += f'ORG:{org}\n'
    if url:
        vcard += f'URL:{url}\n'
    vcard += 'END:VCARD'
    return vcard

def main():
    parser = argparse.ArgumentParser(
        description="QR Code Generator - Generate QR codes from text or URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python qr_code_generator.py -d "Hello World" -o qr.png
  python qr_code_generator.py -d "https://example.com" --ascii
  python qr_code_generator.py --wifi -s "MyWiFi" -p "password123" -o wifi.png
  python qr_code_generator.py --vcard -n "John Doe" -e "john@example.com" -o contact.png
        """
    )
    
    parser.add_argument("-d", "--data", help="Data to encode in QR code")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-e", "--error-correction", choices=['L', 'M', 'Q', 'H'], default='M',
                        help="Error correction level (L=7%%, M=15%%, Q=25%%, H=30%%)")
    parser.add_argument("-s", "--box-size", type=int, default=10, help="Box size in pixels")
    parser.add_argument("-b", "--border", type=int, default=4, help="Border size in boxes")
    parser.add_argument("--fill-color", default="black", help="QR code color")
    parser.add_argument("--back-color", default="white", help="Background color")
    parser.add_argument("--ascii", action="store_true", help="Print as ASCII art")
    
    # Special modes
    parser.add_argument("--wifi", action="store_true", help="Generate WiFi QR code")
    parser.add_argument("--ssid", help="WiFi SSID")
    parser.add_argument("--password", help="WiFi password")
    parser.add_argument("--security", default="WPA", choices=['WPA', 'WEP', 'nopass'],
                        help="WiFi security type")
    
    parser.add_argument("--vcard", action="store_true", help="Generate vCard QR code")
    parser.add_argument("-n", "--name", help="Contact name for vCard")
    parser.add_argument("--phone", help="Contact phone for vCard")
    parser.add_argument("--email", help="Contact email for vCard")
    parser.add_argument("--org", help="Organization for vCard")
    
    args = parser.parse_args()
    
    if not QRCODE_AVAILABLE:
        print("\n[!] qrcode library required. Install with: pip install qrcode[pil]")
        sys.exit(1)
    
    try:
        data = args.data
        
        # Handle special modes
        if args.wifi:
            if not args.ssid or not args.password:
                print("[!] WiFi mode requires --ssid and --password")
                sys.exit(1)
            data = generate_wifi_qr(args.ssid, args.password, args.security)
            print(f"\n  WiFi QR Code: SSID={args.ssid}, Security={args.security}")
        
        elif args.vcard:
            if not args.name:
                print("[!] vCard mode requires --name")
                sys.exit(1)
            data = generate_vcard_qr(args.name, args.phone or '', args.email or '', 
                                     args.org or '', args.data or '')
            print(f"\n  vCard QR Code: {args.name}")
        
        if not data:
            parser.print_help()
            print("\n[!] Please provide data to encode with -d")
            sys.exit(1)
        
        print("\n" + "="*70)
        print("  QR CODE GENERATOR - CyberSecurity Tools Hub")
        print("="*70)
        
        print(f"\n  Data: {data[:50]}{'...' if len(data) > 50 else ''}")
        print(f"  Error Correction: {args.error_correction}")
        
        if args.ascii:
            print("\n  QR Code (ASCII):")
            print_ascii_qr(data)
        elif args.output:
            generate_qr(
                data,
                output_file=args.output,
                error_correction=args.error_correction,
                box_size=args.box_size,
                border=args.border,
                fill_color=args.fill_color,
                back_color=args.back_color
            )
            print(f"\n  ✓ QR code saved to: {args.output}")
            
            # Also print ASCII
            print("\n  Preview:")
            print_ascii_qr(data)
        else:
            print("\n  QR Code (ASCII):")
            print_ascii_qr(data)
            print("\n  Tip: Use -o filename.png to save as image")
        
        print("\n" + "="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
