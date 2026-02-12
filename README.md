# 🛡️ Security Scripts Collection
## Professional Security Testing Tools in Python

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Tools-red.svg)](https://github.com/ChetanBiranje)

Collection of professional-grade security testing scripts for penetration testing, vulnerability assessment, and security research.

## 🎯 Tools Included

| Tool | Description | Status |
|------|-------------|--------|
| 🔍 **Port Scanner** | Advanced TCP/UDP port scanner with service detection | ✅ Complete |
| 🌐 **Web Fuzzer** | Directory and parameter fuzzing tool | ✅ Complete |
| 🔐 **Password Analyzer** | Password strength checker and cracker | ✅ Complete |
| 📊 **Log Parser** | Security log analyzer with threat detection | ✅ Complete |
| 🌍 **Subdomain Enumerator** | Subdomain discovery tool | ✅ Complete |
| 🔓 **Hash Cracker** | Multi-algorithm hash cracking tool | ✅ Complete |
| 📡 **Network Sniffer** | Packet capture and analysis | ✅ Complete |
| 🐛 **Vulnerability Scanner** | Basic CVE and vulnerability detection | ✅ Complete |

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/ChetanBiranje/security-scripts.git
cd security-scripts

# Install dependencies
pip install -r requirements.txt

# Run any tool
python port-scanner/scanner.py --target 192.168.1.1
python web-fuzzer/fuzzer.py --url https://example.com
python password-analyzer/analyzer.py --password "MyP@ssw0rd"
```

## 📦 Installation

```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install scapy colorama requests tqdm
```

## 🔧 Tools Documentation

### 1. Port Scanner

Advanced port scanner with service detection and banner grabbing.

**Features:**
- TCP/UDP scanning
- Service version detection
- Banner grabbing
- Concurrent scanning
- Export results to JSON/CSV

**Usage:**
```bash
# Scan common ports
python port-scanner/scanner.py --target 192.168.1.1

# Scan specific port range
python port-scanner/scanner.py --target example.com --ports 1-1000

# Scan with service detection
python port-scanner/scanner.py --target 10.0.0.1 --service-detect

# Full scan (all 65535 ports)
python port-scanner/scanner.py --target scanme.nmap.org --full
```

---

### 2. Web Fuzzer

Directory and parameter fuzzing for web applications.

**Features:**
- Directory bruteforcing
- Parameter fuzzing
- Custom wordlists
- Response filtering
- Threading support

**Usage:**
```bash
# Directory fuzzing
python web-fuzzer/fuzzer.py --url https://example.com --wordlist wordlists/dirs.txt

# Parameter fuzzing
python web-fuzzer/fuzzer.py --url https://example.com/search?q=FUZZ --mode param

# Custom headers
python web-fuzzer/fuzzer.py --url https://example.com --header "Cookie: session=abc"
```

---

### 3. Password Analyzer

Analyze password strength and perform dictionary attacks.

**Features:**
- Strength calculation
- Common password detection
- Dictionary attack
- Pattern analysis
- Password generation

**Usage:**
```bash
# Check password strength
python password-analyzer/analyzer.py --password "MyPassword123"

# Dictionary attack
python password-analyzer/analyzer.py --hash "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist rockyou.txt

# Generate secure password
python password-analyzer/analyzer.py --generate --length 16
```

---

### 4. Log Parser

Parse and analyze security logs for threats.

**Features:**
- Failed login detection
- Port scan detection
- Suspicious patterns
- IP geolocation
- Report generation

**Usage:**
```bash
# Parse access logs
python log-parser/parser.py --file /var/log/apache2/access.log

# Parse auth logs
python log-parser/parser.py --file /var/log/auth.log --type auth

# Generate report
python log-parser/parser.py --file logs.txt --output report.json
```

---

### 5. Subdomain Enumerator

Discover subdomains using multiple techniques.

**Features:**
- DNS bruteforce
- Certificate transparency
- Search engine queries
- Zone transfer attempts
- Wildcard detection

**Usage:**
```bash
# Basic enumeration
python subdomain-enum/enum.py --domain example.com

# With wordlist
python subdomain-enum/enum.py --domain example.com --wordlist subdomains.txt

# Save results
python subdomain-enum/enum.py --domain example.com --output results.txt
```

---

### 6. Hash Cracker

Crack password hashes using various methods.

**Features:**
- MD5, SHA1, SHA256, SHA512 support
- Dictionary attack
- Rainbow tables
- Hash identification
- Salt support

**Usage:**
```bash
# Identify hash type
python hash-cracker/cracker.py --hash "5f4dcc3b5aa765d61d8327deb882cf99" --identify

# Crack hash
python hash-cracker/cracker.py --hash "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist rockyou.txt

# Multiple hashes
python hash-cracker/cracker.py --file hashes.txt --wordlist passwords.txt
```

---

### 7. Network Sniffer

Capture and analyze network packets.

**Features:**
- Protocol analysis
- Packet filtering
- Traffic statistics
- Export to PCAP
- Real-time monitoring

**Usage:**
```bash
# Start sniffing
sudo python network-sniffer/sniffer.py --interface eth0

# Filter HTTP traffic
sudo python network-sniffer/sniffer.py --interface eth0 --filter http

# Save to file
sudo python network-sniffer/sniffer.py --interface wlan0 --output capture.pcap
```

---

### 8. Vulnerability Scanner

Basic vulnerability detection for web applications.

**Features:**
- SQL injection detection
- XSS detection
- Open redirect detection
- Information disclosure
- Security headers check

**Usage:**
```bash
# Scan website
python vulnerability-scanner/scanner.py --url https://example.com

# Deep scan
python vulnerability-scanner/scanner.py --url https://example.com --deep

# Custom payloads
python vulnerability-scanner/scanner.py --url https://example.com --payloads custom.txt
```

---

## 📋 Requirements

```txt
requests>=2.28.0
scapy>=2.5.0
colorama>=0.4.6
tqdm>=4.65.0
beautifulsoup4>=4.11.0
dnspython>=2.3.0
python-whois>=0.8.0
```

## 🎓 Usage Examples

### Example 1: Complete Network Scan

```bash
#!/bin/bash
# Complete network assessment

# 1. Port scan
python port-scanner/scanner.py --target 192.168.1.0/24 --output ports.json

# 2. Subdomain enumeration
python subdomain-enum/enum.py --domain target.com --output subdomains.txt

# 3. Web fuzzing
python web-fuzzer/fuzzer.py --url https://target.com --wordlist dirs.txt

# 4. Vulnerability scan
python vulnerability-scanner/scanner.py --url https://target.com --output vulns.json
```

### Example 2: Log Analysis Workflow

```python
#!/usr/bin/env python3
from log_parser import LogParser

# Parse logs
parser = LogParser()
parser.parse_file('/var/log/auth.log')

# Get failed logins
failed_logins = parser.get_failed_logins()
print(f"Failed login attempts: {len(failed_logins)}")

# Detect port scans
port_scans = parser.detect_port_scans()
print(f"Port scan attempts: {len(port_scans)}")

# Generate report
parser.generate_report('security_report.json')
```

---

## ⚠️ Disclaimer

**IMPORTANT:** These tools are for educational and authorized testing purposes only.

- ✅ Only use on systems you own or have explicit permission to test
- ❌ Unauthorized use may be illegal
- ✅ Always follow responsible disclosure practices
- ❌ Not responsible for misuse

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Submit pull request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## 🌟 Acknowledgments

- OWASP for security testing guidelines
- Security community for tools and techniques
- Open source projects that inspired these tools

---

## 📧 Contact

**Chetan Biranje**
- GitHub: [@ChetanBiranje](https://github.com/ChetanBiranje)
- LinkedIn: [chetanbiranje](https://linkedin.com/in/chetanbiranje)
- Email: chetanbiranje@proton.me

---

## 🎯 Roadmap

- [ ] Web application firewall bypass techniques
- [ ] API security testing module
- [ ] Cloud security scanner (AWS/Azure/GCP)
- [ ] Mobile app security analyzer
- [ ] Automated reporting system
- [ ] GUI interface for tools

---

**Made with ❤️ for the security community**

⭐ **Star this repo if you find it useful!**
