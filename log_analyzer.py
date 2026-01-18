## Log analyzer 
# 1. Reads a log file (I'll provide sample format)
#2. Uses comprehensions to parse entries
# 3. Uses Counter to find most common events
# 4. Uses defaultdict to group by timestamp/IP

from collections import Counter, defaultdict, namedtuple
from datetime import datetime
import re

# Define a LogEntry namedtuple for structured data
LogEntry = namedtuple('LogEntry', ['timestamp', 'ip', 'level', 'message'])

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.entries = []
        self.parse_logs()

    def parse_logs(self):
        print(f"DEBUG: Trying to open {self.log_file}")

        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"ERROR: File '{self.log_file}' not found!")
            return

        print(f"DEBUG: Read {len(lines)} lines from file")

        # Parse each line using list comprehension
        self.entries = [
            self._parse_line(line.strip())
            for line in lines
            if line.strip()
        ]

        print(f"Parsed {len(self.entries)} log entries\n")  # ✅ Fixed spelling

    def _parse_line(self, line):
        ## Parse a single log line into a LogEntry
        # Pattern: YYYY-MM-DD HH-MM-SS IP LEVEL MESSAGE 
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\w+) (.+)'
        match = re.match(pattern, line)

        if match:
            timestamp_str, ip, level, message = match.groups()
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            return LogEntry(timestamp, ip, level, message)
        else:
            # Return None for malformed lines
            return None
        
    def get_level_stats(self):
        ## Count occurances of each log level using Counter
        levels = [entry.level for entry in self.entries if entry]
        return Counter(levels)
        
    def group_by_ip(self):
        grouped = defaultdict(list)
        for entry in self.entries:
            if entry:
                grouped[entry.ip].append(entry)
        return dict(grouped)

    def group_by_hour(self):
        grouped = defaultdict(list)
        for entry in self.entries:
            if entry:
                hour = entry.timestamp.hour
                grouped[hour].append(entry)
        return dict(grouped)
    
    def find_security_issues(self):
        # Detect potential security issues
        issues = {
            'failed_logins': [],
            'account_lockouts': [],
            'suspicious_activity': [],
            'rate_limit_exceeded': []
        }
        
        for entry in self.entries:
            if not entry:
                continue
            
            message_lower = entry.message.lower()
            
            if 'failed login' in message_lower:
                issues['failed_logins'].append(entry)
            elif 'account locked' in message_lower:
                issues['account_lockouts'].append(entry)
            elif 'suspicious activity' in message_lower:
                issues['suspicious_activity'].append(entry)
            elif 'rate limit' in message_lower:
                issues['rate_limit_exceeded'].append(entry)
        
        return issues

    def get_top_ips(self, n=5):
        ip_counter = Counter(entry.ip for entry in self.entries if entry)
        return ip_counter.most_common(n)
    
    def get_error_summary(self):
        errors = [
            entry.message
            for entry in self.entries
            if entry and entry.level == 'ERROR'
        ]
        return Counter(errors)
    
    def detect_brute_force(self, threshold=3):
        failed_by_ip = defaultdict(list)
        for entry in self.entries:
            if entry and 'failed login' in entry.message.lower():
                failed_by_ip[entry.ip].append(entry)
        
        brute_force_attempts = {
            ip: entries
            for ip, entries in failed_by_ip.items()
            if len(entries) >= threshold
        }

        return brute_force_attempts

    def generate_report(self):
        print("=" * 70)
        print("LOG ANALYSIS REPORT")
        print("=" * 70)

        # Basic stats
        print("\n BASIC STATISTICS")
        print(f"Total Log entries: {len(self.entries)}")

        if self.entries:
            first_entry = min(entry.timestamp for entry in self.entries if entry)
            last_entry = max(entry.timestamp for entry in self.entries if entry)
            print(f"Time range: {first_entry} to {last_entry}")
        
        # 2. Log Level Distribution
        print("\n LOG LEVEL DISTRIBUTION")
        print("-" * 70)
        level_stats = self.get_level_stats()
        for level, count in level_stats.most_common():
            percentage = (count / len(self.entries) * 100)
            print(f"{level:10s}: {count:3d} ({percentage:5.1f}%)")

        # Top Active IPs
        print("\n TOP 5 MOST ACTIVE IP ADDRESSES")
        print("-" * 70)
        top_ips = self.get_top_ips(5)
        for rank, (ip, count) in enumerate(top_ips, 1):
            print(f"{rank}. {ip:15s} - {count} events")

        # Activity by Hour
        print("\n ACTIVITY BY HOUR")
        print("-" * 70)
        by_hour = self.group_by_hour()
        for hour in sorted(by_hour.keys()):
            count = len(by_hour[hour])
            print(f"{hour:02d}:00 - {count:2d} events")
        
        # Error Summary
        print("\n ERROR SUMMARY")
        print("-" * 70)
        error_summary = self.get_error_summary()
        if error_summary:
            for error, count in error_summary.most_common():
                print(f" [{count}x] {error}")
        else:
            print(" No errors found ")
        
        # Security Issues
        print("\n SECURITY ANALYSIS")
        print("-" * 70)
        security_issues = self.find_security_issues()

        print(f"Failed login attempts: {len(security_issues['failed_logins'])}")
        print(f"Account lockouts: {len(security_issues['account_lockouts'])}")
        print(f"Suspicious activity: {len(security_issues['suspicious_activity'])}")
        print(f"Rate limit violations: {len(security_issues['rate_limit_exceeded'])}")

        # Brute force Detection
        print("\n BRUTE FORCE DETECTION")
        print("-" * 70)
        brute_force = self.detect_brute_force(threshold=3)
        if brute_force:
            print("WARNING: Potential brute force attacks detected!")
            for ip, attempts in brute_force.items():
                print(f"\n IP: {ip}")
                print(f"    Failed attempts: {len(attempts)}")
                print(f"    First attempt: {attempts[0].timestamp}")
                print(f"    Last Attempt: {attempts[-1].timestamp}")

                # Extract usernames
                usernames = set()
                for attempt in attempts:
                    match = re.search(r'user: (\w+)', attempt.message)
                    if match:
                        usernames.add(match.group(1))
                if usernames:
                    print(f"    Targeted users: {', '.join(usernames)}")
        
        else:
            print("No brute force attacks detected")

        # Recommendations
        print("\n RECOMMENDATIONS")
        print("-" * 70)
        recommendations = []

        if brute_force:
            recommendations.append("- Block or rate-limit IPs with multiple failed logins" )
        if security_issues:
            recommendations.append("- Review rate limiting policies")
        
        error_count = len([e for e in self.entries if e and e.level == "ERROR"])
        if error_count > len(self.entries) * 0.1:    # More than 10% errors
            recommendations.append("- High error rate detected - investigate system health")
        if security_issues['suspicious_activity']:
            recommendations.append("- Investigate flagged suspicious activities")
        if recommendations:
            for rec in recommendations:
                print(rec)
        else:
            print(" No immediate concerns")
        
        print("\n" + "=" * 70)

def main():
    # Main execution
    print("\n LOG ANALYZER TOOL")

    # Create analyzer instance
    analyzer = LogAnalyzer('server.log')

    # Generate report
    analyzer.generate_report()

    # Interactive queries
    print("\n\n ADDITIONAL QUERIES")
    print("-" * 70)

    ## Query specific IP
    ip_to_check = '192.128.1.101'
    by_ip = analyzer.group_by_ip()
    if ip_to_check in by_ip:
        print(f"\nActivity for {ip_to_check}:")
        for entry in by_ip[ip_to_check]:
            print(f"    [{entry.timestamp  }] {entry.level}: {entry.message}")

if __name__ == "__main__":
    main()