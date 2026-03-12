#!/usr/bin/env python3
"""
SOCIAL MEDIA OSINT
==================

Gather public information from social media profiles.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only accesses PUBLIC information.
Respect platform terms of service and privacy.

Requirements:
    pip install requests beautifulsoup4

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
import re
import json
from datetime import datetime

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

class SocialMediaOSINT:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
    
    def check_username_availability(self, username: str) -> dict:
        """
        Check username availability on multiple platforms.
        
        Args:
            username: Username to check
        
        Returns:
            Dictionary with availability status
        """
        platforms = {
            'github': f'https://github.com/{username}',
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'youtube': f'https://youtube.com/@{username}',
            'tiktok': f'https://tiktok.com/@{username}',
            'pinterest': f'https://pinterest.com/{username}',
            'medium': f'https://medium.com/@{username}',
            'devto': f'https://dev.to/{username}',
        }
        
        results = {}
        
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=10, allow_redirects=False)
                
                # Different platforms have different indicators
                if response.status_code == 200:
                    status = 'FOUND'
                elif response.status_code == 404:
                    status = 'NOT_FOUND'
                elif response.status_code in [301, 302]:
                    status = 'REDIRECT'
                else:
                    status = 'UNKNOWN'
                
                results[platform] = {
                    'url': url,
                    'status': status,
                    'status_code': response.status_code
                }
                
            except Exception as e:
                results[platform] = {
                    'url': url,
                    'status': 'ERROR',
                    'error': str(e)
                }
        
        return results
    
    def extract_emails_from_page(self, url: str) -> list:
        """Extract email addresses from a webpage."""
        if not BS4_AVAILABLE:
            return []
        
        emails = set()
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find emails in text
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails.update(re.findall(email_pattern, response.text))
            
            # Find emails in mailto links
            for link in soup.find_all('a', href=True):
                if link['href'].startswith('mailto:'):
                    email = link['href'].replace('mailto:', '').split('?')[0]
                    emails.add(email)
        
        except:
            pass
        
        return list(emails)
    
    def extract_social_links_from_page(self, url: str) -> dict:
        """Extract social media links from a webpage."""
        if not BS4_AVAILABLE:
            return {}
        
        social_domains = {
            'twitter': ['twitter.com', 'x.com'],
            'facebook': ['facebook.com', 'fb.com'],
            'instagram': ['instagram.com'],
            'linkedin': ['linkedin.com'],
            'youtube': ['youtube.com', 'youtu.be'],
            'github': ['github.com'],
            'tiktok': ['tiktok.com'],
            'telegram': ['t.me', 'telegram.org'],
            'discord': ['discord.gg', 'discord.com'],
        }
        
        links = {platform: [] for platform in social_domains}
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                
                for platform, domains in social_domains.items():
                    for domain in domains:
                        if domain in href:
                            links[platform].append(link['href'])
                            break
        
        except:
            pass
        
        return {k: list(set(v)) for k, v in links.items() if v}
    
    def get_website_info(self, domain: str) -> dict:
        """Get basic website information."""
        result = {
            'domain': domain,
            'title': None,
            'description': None,
            'emails': [],
            'social_links': {},
        }
        
        if not BS4_AVAILABLE:
            return result
        
        try:
            if not domain.startswith(('http://', 'https://')):
                url = 'https://' + domain
            else:
                url = domain
            
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Title
            title_tag = soup.find('title')
            if title_tag:
                result['title'] = title_tag.text.strip()
            
            # Description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                result['description'] = meta_desc.get('content')
            
            # Emails
            result['emails'] = self.extract_emails_from_page(url)
            
            # Social links
            result['social_links'] = self.extract_social_links_from_page(url)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result

def main():
    parser = argparse.ArgumentParser(
        description="Social Media OSINT - Gather public information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DISCLAIMER:
This tool only accesses PUBLIC information.
Respect privacy and platform terms of service.

Examples:
  python social_media_osint.py --check-username johndoe
  python social_media_osint.py --website example.com
  python social_media_osint.py --emails https://example.com
        """
    )
    
    parser.add_argument("--check-username", help="Check username across platforms")
    parser.add_argument("--website", help="Get website information")
    parser.add_argument("--emails", help="Extract emails from URL")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  SOCIAL MEDIA OSINT - CyberSecurity Tools Hub")
    print("="*70)
    print("\n  ⚠️  DISCLAIMER: Only accesses PUBLIC information")
    
    try:
        osint = SocialMediaOSINT()
        
        if args.check_username:
            print(f"\n  Checking username: {args.check_username}")
            print("  " + "-"*56)
            
            results = osint.check_username_availability(args.check_username)
            
            for platform, data in results.items():
                status_icon = {
                    'FOUND': '✓',
                    'NOT_FOUND': '✗',
                    'REDIRECT': '→',
                    'UNKNOWN': '?',
                    'ERROR': '!'
                }.get(data['status'], '?')
                
                print(f"    {status_icon} {platform:<12} [{data['status_code']}] {data['url']}")
        
        elif args.website:
            print(f"\n  Analyzing: {args.website}")
            print("  " + "-"*56)
            
            info = osint.get_website_info(args.website)
            
            if info.get('title'):
                print(f"\n  Title: {info['title']}")
            if info.get('description'):
                print(f"  Description: {info['description'][:100]}...")
            if info.get('emails'):
                print(f"\n  Emails found:")
                for email in info['emails']:
                    print(f"    - {email}")
            if info.get('social_links'):
                print(f"\n  Social Links:")
                for platform, links in info['social_links'].items():
                    for link in links:
                        print(f"    {platform}: {link}")
        
        elif args.emails:
            print(f"\n  Extracting emails from: {args.emails}")
            print("  " + "-"*56)
            
            emails = osint.extract_emails_from_page(args.emails)
            
            if emails:
                print(f"\n  Found {len(emails)} email(s):")
                for email in emails:
                    print(f"    - {email}")
            else:
                print("\n  No emails found.")
        
        else:
            parser.print_help()
        
        if args.json:
            print("\n" + json.dumps(osint.results, indent=2, default=str))
        
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
