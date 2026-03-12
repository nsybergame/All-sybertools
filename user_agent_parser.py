#!/usr/bin/env python3
"""
USER AGENT PARSER
=================

Parse and analyze browser user agent strings.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Requirements:
    pip install user-agents (optional, for better detection)

Author: CyberSecurity Tools Hub
"""

import re
import argparse
import sys
import json

# Browser patterns
BROWSER_PATTERNS = {
    'Edge': r'Edg(?:e|A|iOS)?/(\d+(?:\.\d+)?)',
    'Opera': r'(?:OPR|Opera)/(\d+(?:\.\d+)?)',
    'Vivaldi': r'Vivaldi/(\d+(?:\.\d+)?)',
    'Brave': r'Brave/(\d+(?:\.\d+)?)',
    'Firefox': r'Firefox/(\d+(?:\.\d+)?)',
    'Samsung Internet': r'SamsungBrowser/(\d+(?:\.\d+)?)',
    'UC Browser': r'UCBrowser/(\d+(?:\.\d+)?)',
    'Internet Explorer': r'(?:MSIE |Trident/.*rv:)(\d+(?:\.\d+)?)',
    'Safari': r'Safari/(\d+(?:\.\d+)?)',
    'Chrome': r'Chrome/(\d+(?:\.\d+)?)',
}

# OS patterns
OS_PATTERNS = {
    'Windows 11': r'Windows NT 11\.0',
    'Windows 10': r'Windows NT 10\.0',
    'Windows 8.1': r'Windows NT 6\.3',
    'Windows 8': r'Windows NT 6\.2',
    'Windows 7': r'Windows NT 6\.1',
    'Windows Vista': r'Windows NT 6\.0',
    'Windows XP': r'Windows NT 5\.[12]',
    'Windows 2000': r'Windows NT 5\.0',
    'macOS': r'Mac OS X (\d+[._]\d+(?:[._]\d+)?)',
    'iOS': r'(?:iPhone|iPad|iPod).*OS (\d+[._]\d+)',
    'Android': r'Android (\d+(?:\.\d+)?)',
    'Linux': r'Linux',
    'Ubuntu': r'Ubuntu',
    'Chrome OS': r'CrOS',
    'FreeBSD': r'FreeBSD',
    'OpenBSD': r'OpenBSD',
}

# Device patterns
DEVICE_PATTERNS = {
    'iPhone': r'iPhone',
    'iPad': r'iPad',
    'iPod': r'iPod',
    'Android Phone': r'Android.*Mobile',
    'Android Tablet': r'Android(?!.*Mobile)',
    'Windows Phone': r'Windows Phone',
    'Kindle': r'Kindle',
    'PlayStation': r'PlayStation',
    'Xbox': r'Xbox',
    'Smart TV': r'(?:SmartTV|AppleTV|GoogleTV|HbbTV)',
}

# Bot patterns
BOT_PATTERNS = {
    'Googlebot': r'Googlebot',
    'Bingbot': r'bingbot',
    'Slurp': r'Slurp',
    'DuckDuckBot': r'DuckDuckBot',
    'Baiduspider': r'Baiduspider',
    'YandexBot': r'YandexBot',
    'Sogou': r'Sogou',
    'Exabot': r'Exabot',
    'Facebook': r'facebookexternalhit',
    'Twitter': r'Twitterbot',
    'LinkedIn': r'LinkedInBot',
    'Pinterest': r'Pinterest',
    'WhatsApp': r'WhatsApp',
    'Telegram': r'TelegramBot',
    'Discord': r'Discordbot',
}

# Known crawlers and scanners
SCANNER_PATTERNS = {
    'Nmap': r'Nmap',
    'Nikto': r'Nikto',
    'SQLMap': r'sqlmap',
    'Masscan': r'Masscan',
    'ZAP': r'ZAP',
    'Burp': r'Burp',
    'Nessus': r'Nessus',
    'Acunetix': r'Acunetix',
    'DirBuster': r'DirBuster',
}

def parse_user_agent(ua_string: str) -> dict:
    """
    Parse user agent string.
    
    Args:
        ua_string: User agent string
    
    Returns:
        Dictionary with parsed information
    """
    result = {
        'user_agent': ua_string,
        'browser': {'name': 'Unknown', 'version': None},
        'os': {'name': 'Unknown', 'version': None},
        'device': {'type': 'Desktop', 'model': None},
        'is_bot': False,
        'bot_name': None,
        'is_scanner': False,
        'scanner_name': None,
        'is_mobile': False,
        'is_tablet': False,
    }
    
    # Check for bots
    for bot_name, pattern in BOT_PATTERNS.items():
        if re.search(pattern, ua_string, re.IGNORECASE):
            result['is_bot'] = True
            result['bot_name'] = bot_name
            break
    
    # Check for scanners
    for scanner_name, pattern in SCANNER_PATTERNS.items():
        if re.search(pattern, ua_string, re.IGNORECASE):
            result['is_scanner'] = True
            result['scanner_name'] = scanner_name
            break
    
    # Detect browser
    for browser, pattern in BROWSER_PATTERNS.items():
        match = re.search(pattern, ua_string)
        if match:
            result['browser']['name'] = browser
            result['browser']['version'] = match.group(1).replace('_', '.')
            break
    
    # Detect OS
    for os_name, pattern in OS_PATTERNS.items():
        match = re.search(pattern, ua_string)
        if match:
            result['os']['name'] = os_name
            if match.groups():
                result['os']['version'] = match.group(1).replace('_', '.')
            break
    
    # Detect device
    for device, pattern in DEVICE_PATTERNS.items():
        if re.search(pattern, ua_string, re.IGNORECASE):
            result['device']['type'] = device
            break
    
    # Mobile/Tablet detection
    result['is_mobile'] = 'Mobile' in ua_string and 'Android' in ua_string
    result['is_tablet'] = bool(re.search(r'(Tablet|iPad)', ua_string, re.IGNORECASE))
    
    # Override device type for mobile/tablet
    if result['is_tablet']:
        result['device']['type'] = 'Tablet'
    elif result['is_mobile']:
        result['device']['type'] = 'Mobile'
    
    return result

def print_parsed_info(result: dict):
    """Pretty print parsed user agent information."""
    print("\n" + "="*70)
    print("  USER AGENT ANALYSIS")
    print("="*70)
    
    print(f"\n  User Agent: {result['user_agent'][:67]}...")
    
    print(f"\n  Browser:")
    print(f"    Name: {result['browser']['name']}")
    if result['browser']['version']:
        print(f"    Version: {result['browser']['version']}")
    
    print(f"\n  Operating System:")
    print(f"    Name: {result['os']['name']}")
    if result['os']['version']:
        print(f"    Version: {result['os']['version']}")
    
    print(f"\n  Device:")
    print(f"    Type: {result['device']['type']}")
    print(f"    Mobile: {'Yes' if result['is_mobile'] else 'No'}")
    print(f"    Tablet: {'Yes' if result['is_tablet'] else 'No'}")
    
    if result['is_bot']:
        print(f"\n  ⚠️ Bot Detected: {result['bot_name']}")
    
    if result['is_scanner']:
        print(f"\n  🔴 Security Scanner Detected: {result['scanner_name']}")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="User Agent Parser - Parse and analyze user agent strings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python user_agent_parser.py "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  python user_agent_parser.py -f user_agents.txt
  cat access.log | python user_agent_parser.py --stdin
        """
    )
    
    parser.add_argument("user_agent", nargs="?", help="User agent string to parse")
    parser.add_argument("-f", "--file", help="File with user agent strings (one per line)")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("--bots", action="store_true", help="Only show bots")
    parser.add_argument("--scanners", action="store_true", help="Only show scanners")
    
    args = parser.parse_args()
    
    try:
        user_agents = []
        
        if args.user_agent:
            user_agents = [args.user_agent]
        elif args.file:
            with open(args.file, 'r') as f:
                user_agents = [line.strip() for line in f if line.strip()]
        elif args.stdin:
            for line in sys.stdin:
                if line.strip():
                    user_agents.append(line.strip())
        else:
            parser.print_help()
            print("\n[!] Please provide a user agent string")
            sys.exit(1)
        
        results = []
        
        for ua in user_agents:
            result = parse_user_agent(ua)
            
            # Filter
            if args.bots and not result['is_bot']:
                continue
            if args.scanners and not result['is_scanner']:
                continue
            
            results.append(result)
            
            if len(user_agents) == 1:
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print_parsed_info(result)
        
        if len(user_agents) > 1:
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print("\n" + "="*70)
                print(f"  Analyzed {len(results)} user agents")
                print("="*70)
                
                # Statistics
                browsers = {}
                os_list = {}
                bots = 0
                scanners = 0
                
                for r in results:
                    b = r['browser']['name']
                    browsers[b] = browsers.get(b, 0) + 1
                    o = r['os']['name']
                    os_list[o] = os_list.get(o, 0) + 1
                    if r['is_bot']:
                        bots += 1
                    if r['is_scanner']:
                        scanners += 1
                
                print(f"\n  Browsers:")
                for b, count in sorted(browsers.items(), key=lambda x: -x[1])[:10]:
                    print(f"    {b}: {count}")
                
                print(f"\n  Operating Systems:")
                for o, count in sorted(os_list.items(), key=lambda x: -x[1])[:10]:
                    print(f"    {o}: {count}")
                
                if bots > 0:
                    print(f"\n  Bots detected: {bots}")
                if scanners > 0:
                    print(f"\n  Scanners detected: {scanners}")
                
                print("\n" + "="*70)
        
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
