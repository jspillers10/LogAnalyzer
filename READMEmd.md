# Security Log Analyzer

A Python-based log analysis tool designed for cybersecurity professionals to detect threats, analyze patterns, and generate comprehensive security reports from server logs.

## Project Overview

This tool parses server log files and performs automated security analysis including brute force detection, suspicious activity identification, and statistical reporting. Built with Python's data structures (Counter, defaultdict, namedtuple) and pattern matching capabilities, it demonstrates practical applications of data analysis in cybersecurity contexts.

## Features

### Core Functionality
- Parse structured log files with regex pattern matching
- Extract and structure log entries using namedtuples
- Generate comprehensive analysis reports
- Query logs by IP address or time period

### Security Analysis
- Brute force attack detection with configurable thresholds
- Failed login attempt tracking
- Account lockout monitoring
- Suspicious activity flagging
- Rate limit violation detection
- Username extraction from failed login attempts

### Statistical Analysis
- Log level distribution with percentages
- Top active IP addresses
- Activity patterns by hour
- Error frequency and categorization
- Time range analysis

### Automated Recommendations
- Risk-based recommendation generation
- Threshold-based alerting (10% error rate)
- Security best practice suggestions

## Technical Implementation

### Data Structures Used

**namedtuple**: Structured log entry representation
```python
LogEntry = namedtuple('LogEntry', ['timestamp', 'ip', 'level', 'message'])
```

**Counter**: Frequency analysis for log levels, errors, and IPs
```python
level_stats = Counter(levels)
ip_counter = Counter(entry.ip for entry in entries)
```

**defaultdict**: Grouping entries by IP address or time period
```python
grouped = defaultdict(list)
for entry in entries:
    grouped[entry.ip].append(entry)
```

### Pattern Matching

Regex pattern for log parsing:
```
YYYY-MM-DD HH:MM:SS IP_ADDRESS LEVEL MESSAGE
```

Pattern: `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\w+) (.+)`

## Installation

### Requirements
- Python 3.6+
- Standard library only (no external dependencies)

### Setup
```bash
git clone https://github.com/yourusername/security-log-analyzer.git
cd security-log-analyzer
```

No additional packages needed - uses only Python standard library.

## Usage

### Basic Usage
```bash
python log_analyzer.py
```

### With Custom Log File
Modify the file path in `main()`:
```python
analyzer = LogAnalyzer('your_log_file.log')
```

### Expected Log Format

```
2024-01-15 10:23:45 192.168.1.100 INFO User login successful: user: admin
2024-01-15 10:24:12 192.168.1.101 WARN Failed login attempt: user: admin
2024-01-15 10:24:30 192.168.1.101 WARN Failed login attempt: user: admin
2024-01-15 10:25:00 192.168.1.101 ERROR Account locked: user: admin
2024-01-15 10:30:15 10.0.0.5 ERROR Database connection timeout
```

Each line must follow the format:
- Timestamp: `YYYY-MM-DD HH:MM:SS`
- IP Address: Any valid IP format
- Log Level: INFO, WARN, ERROR, DEBUG, etc.
- Message: Any text content

## Example Output

```
======================================================================
LOG ANALYSIS REPORT
======================================================================

 BASIC STATISTICS
Total Log entries: 150
Time range: 2024-01-15 08:00:00 to 2024-01-15 18:30:00

 LOG LEVEL DISTRIBUTION
----------------------------------------------------------------------
INFO      :  95 ( 63.3%)
WARN      :  32 ( 21.3%)
ERROR     :  23 ( 15.3%)

 TOP 5 MOST ACTIVE IP ADDRESSES
----------------------------------------------------------------------
1. 192.168.1.100   - 45 events
2. 192.168.1.101   - 38 events
3. 10.0.0.5        - 25 events
4. 172.16.0.10     - 22 events
5. 192.168.1.102   - 20 events

 ACTIVITY BY HOUR
----------------------------------------------------------------------
08:00 - 15 events
09:00 - 22 events
10:00 - 35 events
11:00 - 28 events
12:00 - 18 events
13:00 - 12 events
14:00 - 10 events
15:00 -  8 events
16:00 -  2 events

 ERROR SUMMARY
----------------------------------------------------------------------
 [8x] Database connection timeout
 [5x] API rate limit exceeded
 [4x] Invalid authentication token
 [3x] File not found: /var/log/app.log
 [3x] Memory allocation failed

 SECURITY ANALYSIS
----------------------------------------------------------------------
Failed login attempts: 12
Account lockouts: 2
Suspicious activity: 3
Rate limit violations: 5

 BRUTE FORCE DETECTION
----------------------------------------------------------------------
WARNING: Potential brute force attacks detected!

 IP: 192.168.1.101
    Failed attempts: 8
    First attempt: 2024-01-15 10:24:12
    Last Attempt: 2024-01-15 10:28:45
    Targeted users: admin, root, developer

 RECOMMENDATIONS
----------------------------------------------------------------------
- Block or rate-limit IPs with multiple failed logins
- Review rate limiting policies
- Investigate flagged suspicious activities

======================================================================
```

## Use Cases

### SOC Operations
- Automated log review for security operations centers
- First-line threat detection
- Incident response data gathering

### System Administration
- Server health monitoring
- Error pattern identification
- Peak usage time analysis

### Incident Investigation
- Timeline reconstruction
- Attack vector identification
- User behavior analysis

### Compliance Auditing
- Failed access attempt documentation
- Security event logging
- Access pattern verification

## Configuration

### Brute Force Detection Threshold
Modify in the report generation:
```python
brute_force = self.detect_brute_force(threshold=3)  # Default: 3 attempts
```

### Top IP Count
Modify in the report generation:
```python
top_ips = self.get_top_ips(5)  # Default: top 5
```

### Error Rate Threshold
Modify in recommendations section:
```python
if error_count > len(self.entries) * 0.1:  # Default: 10%
```

## Code Architecture

### Class Structure

**LogAnalyzer**
Main class handling all log analysis operations.

**Methods:**
- `__init__(log_file)`: Initialize analyzer with log file path
- `parse_logs()`: Read and parse log file into structured entries
- `_parse_line(line)`: Parse individual log line with regex
- `get_level_stats()`: Calculate log level distribution
- `group_by_ip()`: Group entries by source IP address
- `group_by_hour()`: Group entries by hour for temporal analysis
- `find_security_issues()`: Identify security-related events
- `get_top_ips(n)`: Find most active IP addresses
- `get_error_summary()`: Summarize error messages
- `detect_brute_force(threshold)`: Identify potential brute force attacks
- `generate_report()`: Create comprehensive analysis report

### Algorithm Complexity

**Time Complexity:**
- Log parsing: O(n) where n = number of log lines
- IP grouping: O(n)
- Brute force detection: O(n)
- Report generation: O(n + m) where m = number of unique categories

**Space Complexity:**
- O(n) for storing all parsed log entries
- O(k) for grouping structures where k = unique IPs/hours

## Security Considerations

### Pattern Detection

**Brute Force Attacks:**
- Tracks failed login attempts per IP
- Configurable threshold for alerting
- Extracts targeted usernames

**Account Lockouts:**
- Monitors for locked account events
- Correlates with failed login attempts

**Rate Limiting:**
- Detects rate limit violations
- Identifies potential DoS attempts

**Suspicious Activity:**
- Flags explicitly marked suspicious events
- Enables manual review prioritization

## Sample Log Generator

For testing, create sample logs with:

```python
from datetime import datetime, timedelta
import random

ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.10']
levels = ['INFO', 'WARN', 'ERROR']
messages = [
    'User login successful: user: admin',
    'Failed login attempt: user: admin',
    'Database connection established',
    'API request processed',
    'Rate limit exceeded'
]

start_time = datetime(2024, 1, 15, 8, 0, 0)

with open('server.log', 'w') as f:
    for i in range(100):
        timestamp = start_time + timedelta(minutes=i*5)
        ip = random.choice(ips)
        level = random.choice(levels)
        message = random.choice(messages)
        f.write(f"{timestamp} {ip} {level} {message}\n")
```

## Extension Ideas

### Future Enhancements
- Geographic IP location lookup
- Machine learning anomaly detection
- Real-time log monitoring with tail -f
- Export to JSON/CSV formats
- Web dashboard interface
- Integration with SIEM systems
- Custom alert rule engine
- Multi-file analysis
- Correlation between different log sources

## Cybersecurity Applications

This tool demonstrates key concepts relevant to cybersecurity roles:

**Threat Detection:**
- Pattern recognition in log data
- Behavioral analysis
- Automated threat hunting

**Data Analysis:**
- Large dataset parsing and processing
- Statistical analysis for security metrics
- Time series analysis for incident timelines

**Automation:**
- Automated report generation
- Scripted security analysis
- Repeatable investigation procedures

**Python for Security:**
- Practical use of Python collections
- Regex for log parsing
- Object-oriented security tool design

## Learning Outcomes

This project demonstrates:
- Python data structure proficiency (Counter, defaultdict, namedtuple)
- Regular expression pattern matching
- Object-oriented programming principles
- Security-focused data analysis
- Report generation and formatting
- Error handling and input validation
- Algorithm design for security applications

## Author

Jake Spillers  
Cyber Security Specialist

## License

Educational project - Free to use with attribution

---

Built with Python standard library  
Designed for cybersecurity education and portfolio presentation
