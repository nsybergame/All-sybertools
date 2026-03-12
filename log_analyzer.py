#!/usr/bin/env python3
"""
LOG ANALYZER
============

Analyze security logs for suspicious activity.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import re
import argparse
import sys
from datetime import datetime
from collections import Counter, defaultdict
from typing import List, Dict

# Common log patterns
LOG_PATTERNS = {
    'apache_combined': r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
    'apache_common': r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\S+)',
    'nginx': r'(?P<ip>\S+) - \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
}

# Suspicious patterns
SUSPICIOUS_PATTERNS = {
    'sql_injection': [
        r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)",
        r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')",
        r"(?i)(\%27|\'|\-\-)",
    ],
    'xss': [
        r"(?i)<script[^>]*>",
        r"(?i)javascript:",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
    ],
    'path_traversal': [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
    ],
    'command_injection': [
        r"(?i)(;|\||`|&)\s*(ls|cat|whoami|id|pwd|uname)",
        r"(?i)(cmd\.exe|powershell|bash)",
    ],
    'scanner': [
        r"(?i)(nikto|nmap|sqlmap|masscan|zap|burp|acunetix|nessus|dirbuster)",
        r"(?i)(scanner|crawler|spider)",
    ],
}

# Suspicious paths
SUSPICIOUS_PATHS = [
    '/admin', '/wp-admin', '/wp-login.php', '/phpmyadmin', '/.env',
    '/.git', '/config', '/backup', '/database', '/shell',
]

# Suspicious user agents
SUSPICIOUS_USER_AGENTS = [
    'nikto', 'nmap', 'sqlmap', 'masscan', 'burp', 'zap', 'acunetix',
    'nessus', 'dirbuster', 'gobuster', 'wfuzz', 'scanner', 'curl',
]

class LogAnalyzer:
    def __init__(self, logfile: str, log_format: str = 'auto'):
        self.logfile = logfile
        self.log_format = log_format
        self.entries = []
        self.suspicious_entries = []
        self.stats = {
            'total_entries': 0,
            'unique_ips': set(),
            'status_codes': Counter(),
            'methods': Counter(),
            'paths': Counter(),
            'attacks': defaultdict(list),
        }
    
    def detect_format(self, line: str) -> str:
        """Auto-detect log format."""
        for fmt, pattern in LOG_PATTERNS.items():
            if re.match(pattern, line):
                return fmt
        return 'apache_combined'
    
    def parse_line(self, line: str, pattern: str) -> Dict:
        """Parse a log line."""
        match = re.match(LOG_PATTERNS.get(pattern, LOG_PATTERNS['apache_combined']), line)
        if match:
            return match.groupdict()
        return None
    
    def analyze(self):
        """Analyze log file."""
        print(f"\n  Analyzing log file: {self.logfile}")
        print("  " + "-"*56)
        
        with open(self.logfile, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline()
            f.seek(0)
            
            # Auto-detect format
            if self.log_format == 'auto':
                self.log_format = self.detect_format(first_line)
                print(f"  Detected log format: {self.log_format}")
            
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                entry = self.parse_line(line, self.log_format)
                if not entry:
                    continue
                
                self.entries.append(entry)
                self.stats['total_entries'] += 1
                self.stats['unique_ips'].add(entry.get('ip', ''))
                self.stats['status_codes'][entry.get('status', '0')] += 1
                self.stats['methods'][entry.get('method', 'UNKNOWN')] += 1
                
                # Check for suspicious activity
                self.check_entry(entry)
        
        return self.entries
    
    def check_entry(self, entry: Dict):
        """Check entry for suspicious activity."""
        flags = []
        path = entry.get('path', '')
        user_agent = entry.get('user_agent', '')
        ip = entry.get('ip', '')
        
        # Check for attack patterns in path
        for attack_type, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, path):
                    flags.append(f"{attack_type} detected in path")
                    self.stats['attacks'][attack_type].append(entry)
        
        # Check suspicious paths
        for suspicious_path in SUSPICIOUS_PATHS:
            if suspicious_path.lower() in path.lower():
                flags.append(f"Access to suspicious path: {suspicious_path}")
        
        # Check suspicious user agents
        for suspicious_ua in SUSPICIOUS_USER_AGENTS:
            if suspicious_ua.lower() in user_agent.lower():
                flags.append(f"Suspicious user agent: {suspicious_ua}")
        
        # Check for high error rate from single IP
        status = entry.get('status', '200')
        if status.startswith('4') or status.startswith('5'):
            self.stats['error_ips'] = self.stats.get('error_ips', Counter())
            self.stats['error_ips'][ip] += 1
        
        if flags:
            self.suspicious_entries.append({
                'entry': entry,
                'flags': flags
            })
    
    def get_report(self) -> Dict:
        """Generate analysis report."""
        return {
            'total_entries': self.stats['total_entries'],
            'unique_ips': len(self.stats['unique_ips']),
            'status_codes': dict(self.stats['status_codes'].most_common(10)),
            'methods': dict(self.stats['methods']),
            'attacks': {k: len(v) for k, v in self.stats['attacks'].items()},
            'suspicious_count': len(self.suspicious_entries),
            'top_ips': dict(Counter(self.stats['unique_ips']).most_common(10)) if self.stats['unique_ips'] else {},
        }

def print_report(analyzer: LogAnalyzer):
    """Print analysis report."""
    report = analyzer.get_report()
    
    print("\n" + "="*70)
    print("  LOG ANALYSIS REPORT")
    print("="*70)
    
    print(f"\n  Summary:")
    print(f"    Total entries: {report['total_entries']:,}")
    print(f"    Unique IPs: {report['unique_ips']}")
    print(f"    Suspicious entries: {report['suspicious_count']}")
    
    print(f"\n  HTTP Status Codes:")
    for code, count in report['status_codes'].items():
        print(f"    {code}: {count:,}")
    
    print(f"\n  HTTP Methods:")
    for method, count in report['methods'].items():
        print(f"    {method}: {count:,}")
    
    if report['attacks']:
        print(f"\n  Detected Attacks:")
        for attack_type, count in report['attacks'].items():
            print(f"    {attack_type}: {count} attempts")
    
    if analyzer.suspicious_entries:
        print(f"\n  Top Suspicious Entries (showing first 20):")
        print("  " + "-"*66)
        
        for item in analyzer.suspicious_entries[:20]:
            entry = item['entry']
            flags = item['flags']
            print(f"\n    IP: {entry.get('ip', 'N/A')}")
            print(f"    Path: {entry.get('path', 'N/A')}")
            print(f"    Flags: {', '.join(flags[:3])}")
    
    if analyzer.stats.get('error_ips'):
        print(f"\n  IPs with Most Errors:")
        for ip, count in analyzer.stats['error_ips'].most_common(10):
            print(f"    {ip}: {count} errors")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer - Analyze security logs for suspicious activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py /var/log/apache2/access.log
  python log_analyzer.py access.log --format nginx
        """
    )
    
    parser.add_argument("logfile", help="Log file to analyze")
    parser.add_argument("-f", "--format", default="auto",
                        choices=['auto', 'apache_common', 'apache_combined', 'nginx'],
                        help="Log format (default: auto-detect)")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument("--suspicious-only", action="store_true",
                        help="Only show suspicious entries")
    
    args = parser.parse_args()
    
    try:
        analyzer = LogAnalyzer(args.logfile, args.format)
        analyzer.analyze()
        
        if args.suspicious_only:
            print(f"\n  Suspicious entries: {len(analyzer.suspicious_entries)}\n")
            for item in analyzer.suspicious_entries:
                print(f"  {item['entry'].get('ip', 'N/A')}: {item['flags']}")
        else:
            print_report(analyzer)
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    'stats': analyzer.get_report(),
                    'suspicious_entries': [
                        {'entry': e['entry'], 'flags': e['flags']}
                        for e in analyzer.suspicious_entries
                    ]
                }, f, indent=2, default=str)
            print(f"\n  Report saved to: {args.output}")
        
    except FileNotFoundError:
        print(f"\n[!] File not found: {args.logfile}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
