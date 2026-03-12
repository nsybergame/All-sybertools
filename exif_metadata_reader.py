#!/usr/bin/env python3
"""
EXIF METADATA READER
====================

Extract EXIF metadata from images.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install Pillow

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import os
from datetime import datetime

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

def get_exif_data(image_path: str) -> dict:
    """
    Extract EXIF data from an image.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Dictionary with EXIF data
    """
    if not PILLOW_AVAILABLE:
        return {'error': 'Pillow not installed. Install with: pip install Pillow'}
    
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        
        if exif_data is None:
            return {'error': 'No EXIF data found'}
        
        decoded = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            
            if tag == 'GPSInfo':
                gps_data = {}
                for gps_id in value:
                    gps_tag = GPSTAGS.get(gps_id, gps_id)
                    gps_data[gps_tag] = value[gps_id]
                decoded[tag] = gps_data
            elif isinstance(value, bytes):
                decoded[tag] = value.hex()[:50] + '...' if len(value) > 25 else value.hex()
            elif isinstance(value, tuple) and len(value) == 2:
                decoded[tag] = f"{value[0]}/{value[1]}"
            else:
                decoded[tag] = str(value) if value else None
        
        return decoded
    
    except Exception as e:
        return {'error': str(e)}

def get_gps_coordinates(exif_data: dict) -> dict:
    """
    Extract GPS coordinates from EXIF data.
    
    Args:
        exif_data: EXIF data dictionary
    
    Returns:
        Dictionary with GPS coordinates
    """
    if 'GPSInfo' not in exif_data:
        return {'error': 'No GPS data found'}
    
    gps_info = exif_data['GPSInfo']
    
    try:
        # Extract latitude
        if 'GPSLatitude' in gps_info and 'GPSLatitudeRef' in gps_info:
            lat = gps_info['GPSLatitude']
            lat_ref = gps_info['GPSLatitudeRef']
            
            lat_deg = float(lat[0][0]) / float(lat[0][1]) if isinstance(lat[0], tuple) else float(lat[0])
            lat_min = float(lat[1][0]) / float(lat[1][1]) if isinstance(lat[1], tuple) else float(lat[1])
            lat_sec = float(lat[2][0]) / float(lat[2][1]) if isinstance(lat[2], tuple) else float(lat[2])
            
            latitude = lat_deg + (lat_min / 60.0) + (lat_sec / 3600.0)
            if lat_ref == 'S':
                latitude = -latitude
        else:
            latitude = None
        
        # Extract longitude
        if 'GPSLongitude' in gps_info and 'GPSLongitudeRef' in gps_info:
            lon = gps_info['GPSLongitude']
            lon_ref = gps_info['GPSLongitudeRef']
            
            lon_deg = float(lon[0][0]) / float(lon[0][1]) if isinstance(lon[0], tuple) else float(lon[0])
            lon_min = float(lon[1][0]) / float(lon[1][1]) if isinstance(lon[1], tuple) else float(lon[1])
            lon_sec = float(lon[2][0]) / float(lon[2][1]) if isinstance(lon[2], tuple) else float(lon[2])
            
            longitude = lon_deg + (lon_min / 60.0) + (lon_sec / 3600.0)
            if lon_ref == 'W':
                longitude = -longitude
        else:
            longitude = None
        
        if latitude and longitude:
            return {
                'latitude': round(latitude, 6),
                'longitude': round(longitude, 6),
                'google_maps': f"https://maps.google.com/?q={latitude},{longitude}"
            }
        else:
            return {'error': 'Could not parse GPS coordinates'}
    
    except Exception as e:
        return {'error': str(e)}

def print_exif_data(exif_data: dict, image_path: str):
    """Pretty print EXIF data."""
    print("\n" + "="*70)
    print("  EXIF METADATA READER")
    print("="*70)
    
    if 'error' in exif_data:
        print(f"\n  [!] {exif_data['error']}")
        return
    
    print(f"\n  Image: {image_path}")
    
    # Important fields
    important_fields = [
        'Make', 'Model', 'DateTime', 'DateTimeOriginal',
        'ExposureTime', 'FNumber', 'ISOSpeedRatings',
        'FocalLength', 'Software', 'Artist'
    ]
    
    print(f"\n  Camera Information:")
    print("  " + "-"*66)
    for field in important_fields:
        if field in exif_data and exif_data[field]:
            print(f"    {field}: {exif_data[field]}")
    
    # GPS data
    if 'GPSInfo' in exif_data:
        gps = get_gps_coordinates(exif_data)
        print(f"\n  GPS Location:")
        print("  " + "-"*66)
        if 'error' in gps:
            print(f"    {gps['error']}")
        else:
            print(f"    Latitude: {gps['latitude']}")
            print(f"    Longitude: {gps['longitude']}")
            print(f"    Google Maps: {gps['google_maps']}")
    
    # All EXIF data
    print(f"\n  All EXIF Data:")
    print("  " + "-"*66)
    for key, value in exif_data.items():
        if value and key != 'GPSInfo':
            val_str = str(value)[:60]
            print(f"    {key}: {val_str}")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="EXIF Metadata Reader - Extract metadata from images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python exif_metadata_reader.py image.jpg
  python exif_metadata_reader.py photo.png -j
        """
    )
    
    parser.add_argument("image", help="Image file to analyze")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("--gps", action="store_true", help="Show GPS location only")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print(f"\n[!] File not found: {args.image}")
        sys.exit(1)
    
    if not PILLOW_AVAILABLE:
        print("\n[!] Pillow required. Install with: pip install Pillow")
        sys.exit(1)
    
    try:
        exif_data = get_exif_data(args.image)
        
        if args.json:
            import json
            print(json.dumps(exif_data, indent=2, default=str))
        elif args.gps:
            gps = get_gps_coordinates(exif_data)
            if 'error' in gps:
                print(f"\n  {gps['error']}")
            else:
                print(f"\n  Location: {gps['latitude']}, {gps['longitude']}")
                print(f"  Google Maps: {gps['google_maps']}\n")
        else:
            print_exif_data(exif_data, args.image)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
