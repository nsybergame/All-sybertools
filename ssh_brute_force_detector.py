#!/usr/bin/env python3
"""
SSH BRUTE FORCE DETECTOR
========================

Detect SSH brute force attempts from log files.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.

Author: CyberSecurity Tools Hub
"""

import re
import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List

# Common SSH log patterns
SSH_PATTERNS = {
    'failed_password': r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
    'invalid_user': r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
    'break_in_attempt': r'POSSIBLE BREAK-IN ATTEMPT!.*from (\d+\.\d+\.\d+\.\d+)',
    'connection_closed': r'Connection closed by (\d+\.\d+\.\d+\.\d+)',
    'reverse_mapping': r'reverse mapping checking getaddrinfo for .* failed - POSSIBLE BREAK-IN ATTEMPT!',
}

class SSHBruteForceDetector:
    def __init__(self, logfile: str):
        self.logfile = logfile
        self.failed_attempts = []
        self.ip_stats = defaultdict(lambda: {'attempts': 0, 'users': set(), 'timestamps': []})
        self.user_stats = defaultdict(lambda: {'attempts': 0, 'ips': set()})
    
    def parse_log(self):
        """Parse SSH log file."""
        print(f"\n  Parsing log file: {self.logfile}")
        
        with open(self.logfile, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                self._parse_line(line.strip())
    
    def _parse_line(self, line: str):
        """Parse a single log line."""
        # Try to match failed password pattern
        match = re.search(SSH_PATTERNS['failed_password'], line)
        if match:
            user, ip, port = match.groups()
            self._record_attempt(user, ip, line)
            return
        
        # Try to match invalid user pattern
        match = re.search(SSH_PATTERNS['invalid_user'], line)
        if match:
            user, ip = match.groups()
            self._record_attempt(user, ip, line)
            return
    
    def _record_attempt(self, user: str, ip: str, line: str):
        """Record a failed login attempt."""
        self.failed_attempts.append({
            'user': user,
            'ip': ip,
            'line': line,
            'timestamp': datetime.now().isoformat()
        })
        
        self.ip_stats[ip]['attempts'] += 1
        self.ip_stats[ip]['users'].add(user)
        self.ip_stats[ip]['timestamps'].append(datetime.now().isoformat())
        
        self.user_stats[user]['attempts'] += 1
        self.user_stats[user]['ips'].add(ip)
    
    def analyze(self, threshold: int = 5) -> Dict:
        """Analyze failed login attempts."""
        suspicious_ips = []
        suspicious_users = []
        
        # Find suspicious IPs
        for ip, stats in self.ip_stats.items():
            if stats['attempts'] >= threshold:
                suspicious_ips.append({
                    'ip': ip,
                    'attempts': stats['attempts'],
                    'users_tried': list(stats['users']),
                    'risk': 'HIGH' if stats['attempts'] >= 20 else 'MEDIUM'
                })
        
        # Find suspicious users
        for user, stats in self.user_stats.items():
            if stats['attempts'] >= threshold:
                suspicious_users.append({
                    'user': user,
                    'attempts': stats['attempts'],
                    'unique_ips': len(stats['ips'])
                })
        
        return {
            'total_attempts': len(self.failed_attempts),
            'unique_ips': len(self.ip_stats),
            'unique_users': len(self.user_stats),
            'suspicious_ips': sorted(suspicious_ips, key=lambda x: -x['attempts']),
            'suspicious_users': sorted(suspicious_users, key=lambda x: -x['attempts']),
            'threshold': threshold
        }
    
    def get_recommendations(self, suspicious_ips: list) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if suspicious_ips:
            recommendations.append("Consider blocking the following IPs with fail2ban or firewall:")
            for ip_data in suspicious_ips[:10]:
                recommendations.append(f"  - {ip_data['ip']} ({ip_data['attempts']} attempts)")
        
        recommendations.extend([
            "\nGeneral recommendations:",
            "1. Enable fail2ban to automatically block brute force attempts",
            "2. Use key-based authentication instead of passwords",
            "3. Change the default SSH port (22)",
            "4. Disable root login: PermitRootLogin no",
            "5. Use AllowUsers to restrict which users can SSH",
            "6. Enable 2FA for SSH access",
        ])
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(
        description="SSH Brute Force Detector - Detect SSH attacks from logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssh_brute_force_detector.py /var/log/auth.log
  python ssh_brute_force_detector.py auth.log --threshold 10
        """
    )
    
    parser.add_argument("logfile", help="SSH log file to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="Attempt threshold for suspicious activity")
    parser.add_argument("-o", "--output", help="Save report to file")
    
    args = parser.parse_args()
    
    try:
        detector = SSHBruteForceDetector(args.logfile)
        detector.parse_log()
        report = detector.analyze(args.threshold)
        
        # Print report
        print("\n" + "="*70)
        print("  SSH BRUTE FORCE DETECTION REPORT")
        print("="*70)
        
        print(f"\n  Summary:")
        print(f"    Total failed attempts: {report['total_attempts']}")
        print(f"    Unique IPs: {report['unique_ips']}")
        print(f"    Unique users tried: {report['unique_users']}")
        print(f"    Threshold: {report['threshold']} attempts")
        
        if report['suspicious_ips']:
            print(f"\n  Suspicious IPs ({len(report['suspicious_ips'])} detected):")
            print("  " + "-"*66)
            print(f"  {'IP Address':<18} {'Attempts':<10} {'Risk':<10} {'Users'}")
            print("  " + "-"*66)
            
            for ip_data in report['suspicious_ips'][:20]:
                users = ', '.join(ip_data['users_tried'][:3])
                if len(ip_data['users_tried']) > 3:
                    users += '...'
                print(f"  {ip_data['ip']:<18} {ip_data['attempts']:<10} {ip_data['risk']:<10} {users}")
        
        if report['suspicious_users']:
            print(f"\n  Most Targeted Users:")
            print("  " + "-"*66)
            for user_data in report['suspicious_users'][:10]:
                print(f"    {user_data['user']}: {user_data['attempts']} attempts from {user_data['unique_ips']} IPs")
        
        # Recommendations
        print("\n" + "="*70)
        print("  RECOMMENDATIONS")
        print("="*70)
        
        recommendations = detector.get_recommendations(report['suspicious_ips'])
        for rec in recommendations:
            print(f"\n  {rec}")
        
        print("\n" + "="*70)
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
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
