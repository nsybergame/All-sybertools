#!/usr/bin/env python3
"""
DIRECTORY BRUTE FORCER
======================

Discover hidden directories and files on web servers.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only use on servers you own or have explicit permission to test.
Unauthorized directory enumeration is ILLEGAL.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin

# Common directory/file wordlist
COMMON_PATHS = [
    'admin', 'login', 'dashboard', 'panel', 'control', 'manage', 'backend',
    'api', 'v1', 'v2', 'api/v1', 'api/v2', 'graphql', 'rest',
    'backup', 'backups', 'old', 'new', 'test', 'dev', 'staging', 'prod',
    'config', 'conf', 'settings', 'setup', 'install', 'init',
    'uploads', 'upload', 'files', 'images', 'img', 'assets', 'static',
    'docs', 'documentation', 'api-docs', 'swagger', 'redoc',
    'logs', 'log', 'error', 'debug', 'trace', 'dump',
    'tmp', 'temp', 'cache', 'session', 'sessions',
    'user', 'users', 'account', 'accounts', 'profile', 'profiles',
    'download', 'downloads', 'export', 'import', 'upload',
    'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
    'administrator', 'joomla', 'drupal', 'cms', 'site',
    '.git', '.svn', '.env', '.htaccess', '.htpasswd',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'security.txt',
    'phpinfo.php', 'info.php', 'test.php', 'debug.php',
    'index.php.bak', 'index.html.bak', 'web.config', 'server-status',
    'admin.php', 'admin.asp', 'admin.aspx', 'admin.jsp',
    'login.php', 'signin', 'register', 'signup', 'auth',
    'console', 'shell', 'cmd', 'exec', 'run', 'system',
    'private', 'secret', 'hidden', 'internal', 'protected',
    'data', 'database', 'db', 'sql', 'mysql', 'postgres',
    'email', 'mail', 'smtp', 'ftp', 'sftp', 'ssh',
]

EXTENSIONS = ['', '.php', '.html', '.asp', '.aspx', '.jsp', '.txt', '.json', '.xml', '.bak']

def check_path(base_url: str, path: str, timeout: int = 5, extensions: list = None) -> list:
    """
    Check if a path exists on the server.
    
    Args:
        base_url: Base URL
        path: Path to check
        timeout: Request timeout
        extensions: File extensions to try
    
    Returns:
        List of found paths with status codes
    """
    results = []
    extensions = extensions or ['']
    
    for ext in extensions:
        full_path = path + ext if not path.endswith(ext) else path
        url = urljoin(base_url, full_path)
        
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            
            # Interesting status codes
            if response.status_code in [200, 301, 302, 401, 403]:
                results.append({
                    'path': full_path,
                    'url': url,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'redirect': response.headers.get('Location', '')
                })
        
        except:
            pass
    
    return results

def scan_directories(base_url: str, wordlist: list, threads: int = 10, 
                     timeout: int = 5, extensions: list = None, verbose: bool = False) -> list:
    """
    Scan for directories and files.
    
    Args:
        base_url: Target URL
        wordlist: List of paths to check
        threads: Number of concurrent threads
        timeout: Request timeout
        extensions: File extensions to try
        verbose: Show progress
    
    Returns:
        List of found paths
    """
    found = []
    
    print(f"\n{'='*70}")
    print(f"  DIRECTORY BRUTE FORCER - CyberSecurity Tools Hub")
    print(f"{'='*70}")
    print(f"  Target: {base_url}")
    print(f"  Paths to check: {len(wordlist)}")
    print(f"  Extensions: {extensions}")
    print(f"  Threads: {threads}")
    print(f"{'='*70}\n")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, base_url, path, timeout, extensions): path 
                   for path in wordlist}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if verbose and completed % 50 == 0:
                print(f"  Progress: {completed}/{len(wordlist)} paths checked...")
            
            results = future.result()
            for result in results:
                found.append(result)
                status_text = {
                    200: 'OK',
                    301: 'Redirect',
                    302: 'Redirect',
                    401: 'Unauthorized',
                    403: 'Forbidden'
                }.get(result['status_code'], str(result['status_code']))
                
                print(f"  [+] {result['status_code']} ({status_text}): {result['path']} [{result['size']} bytes]")
    
    return sorted(found, key=lambda x: x['status_code'])

def load_wordlist(filepath: str) -> list:
    """Load wordlist from file."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[!] Error loading wordlist: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description="Directory Brute Forcer - Discover hidden directories and files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only scan servers you own or have permission to test.

Examples:
  python directory_brute_forcer.py https://example.com
  python directory_brute_forcer.py https://target.com -w wordlist.txt
  python directory_brute_forcer.py https://target.com -e .php,.html,.txt
        """
    )
    
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-e", "--extensions", default=".php,.html,.txt,.json",
                        help="File extensions to try (comma-separated)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress updates")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    print("\n" + "!"*60)
    print("  WARNING: FOR EDUCATIONAL PURPOSES ONLY!")
    print("  Only scan servers you own or have permission to test!")
    print("!"*60 + "\n")
    
    import warnings
    warnings.filterwarnings('ignore')
    
    try:
        # Load wordlist
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
            if not wordlist:
                sys.exit(1)
        else:
            wordlist = COMMON_PATHS
            print(f"  Using built-in wordlist ({len(wordlist)} paths)")
        
        # Parse extensions
        extensions = [''] + [e if e.startswith('.') else f'.{e}' for e in args.extensions.split(',')]
        
        # Run scan
        start_time = datetime.now()
        found = scan_directories(args.url, wordlist, args.threads, args.timeout, extensions, args.verbose)
        end_time = datetime.now()
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"  SCAN COMPLETE")
        print(f"  Duration: {end_time - start_time}")
        print(f"  Paths found: {len(found)}")
        print(f"{'='*70}\n")
        
        if found:
            print("  RESULTS:")
            print("  " + "-"*66)
            print(f"  {'Status':<8} {'Path':<40} {'Size':<10}")
            print("  " + "-"*66)
            
            for item in found:
                print(f"  {item['status_code']:<8} {item['path']:<40} {item['size']:<10}")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    'target': args.url,
                    'scan_time': str(end_time - start_time),
                    'found': len(found),
                    'results': found
                }, f, indent=2)
            print(f"\n  Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
