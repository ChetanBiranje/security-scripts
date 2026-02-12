# 🚀 HOW TO RUN - Security Scripts
## मराठी आणि English मार्गदर्शक

---

## 📦 INSTALLATION (सेटअप)

### पायरी 1: Repository Download करा

```bash
# GitHub वरून clone करा
git clone https://github.com/ChetanBiranje/security-scripts.git

# Folder मध्ये जा
cd security-scripts
```

### पायरी 2: Dependencies Install करा

```bash
# Python 3.8+ आहे का check करा
python --version

# सर्व dependencies install करा
pip install -r requirements.txt

# किंवा एक एक install करा
pip install requests colorama tqdm dnspython beautifulsoup4
```

---

## 🔍 1. PORT SCANNER - कसं Run करायचं

### Basic Usage:

```bash
# Simple port scan
python port-scanner/scanner.py --target 192.168.1.1

# Scan specific ports
python port-scanner/scanner.py --target example.com --ports 80,443,8080

# Scan port range
python port-scanner/scanner.py --target scanme.nmap.org --ports 1-1000

# Full scan (सर्व 65535 ports)
python port-scanner/scanner.py --target 10.0.0.1 --full

# Save results
python port-scanner/scanner.py --target example.com --output results.json
```

### Example Output:

```
======================================================================
PORT SCANNER - Advanced Network Security Tool
======================================================================

[*] Target: scanme.nmap.org (45.33.32.156)
[*] Ports: 1000 ports
[*] Threads: 100
[*] Scan started: 2026-02-12 14:30:00

[+] Port    22 | OPEN | SSH            | SSH-2.0-OpenSSH_6.6.1
[+] Port    80 | OPEN | HTTP           | HTTP/1.1 200 OK
[+] Port   443 | OPEN | HTTPS          | HTTPS (SSL/TLS)

======================================================================
SCAN SUMMARY
======================================================================
[✓] Scan completed in 12.45 seconds
[✓] Total ports scanned: 1000
[✓] Open ports found: 3
======================================================================
```

### Options:

- `--target`, `-t` : Target IP/hostname (required)
- `--ports`, `-p` : Port range (default: 1-1000)
- `--threads` : Number of threads (default: 100)
- `--timeout` : Connection timeout (default: 1s)
- `--full` : Scan all 65535 ports
- `--output`, `-o` : Save results to JSON

---

## 🌐 2. WEB FUZZER - कसं Run करायचं

### Directory Fuzzing:

```bash
# Basic directory fuzzing
python web-fuzzer/fuzzer.py --url https://example.com --wordlist dirs.txt

# Default wordlist (automatic)
python web-fuzzer/fuzzer.py --url https://example.com

# Custom threads
python web-fuzzer/fuzzer.py --url https://example.com --threads 20
```

### Parameter Fuzzing:

```bash
# Fuzz parameter
python web-fuzzer/fuzzer.py --url https://example.com/search --param q --wordlist payloads.txt

# SQL injection payloads
python web-fuzzer/fuzzer.py --url https://example.com/id --param id --wordlist sqli.txt
```

### Create Wordlist:

```bash
# Default wordlist बनतं automatically
# किंवा custom बनवा:
cat > dirs.txt << EOF
admin
login
dashboard
api
backup
config
.git
uploads
EOF
```

### Example Output:

```
======================================================================
WEB FUZZER - Directory Enumeration
======================================================================

[*] Target URL: https://example.com
[*] Wordlist: dirs.txt
[*] Threads: 10

[+] Loaded 100 words from wordlist

[200] https://example.com/admin                Size:     5432
[200] https://example.com/login                Size:     3421
[301] https://example.com/uploads              Size:      234
[403] https://example.com/config               Size:      156

======================================================================
FUZZING SUMMARY
======================================================================
[✓] Fuzzing completed in 15.32 seconds
[✓] Tested 100 directories
[✓] Found 4 results
======================================================================
```

---

## 🔐 3. PASSWORD ANALYZER - कसं Run करायचं

### Check Password Strength:

```bash
# Password strength check
python password-analyzer/analyzer.py --password "MyP@ssw0rd123"

# Weak password
python password-analyzer/analyzer.py --password "password"

# Strong password
python password-analyzer/analyzer.py --password "K9#mP@x7Lq2$wZ"
```

### Generate Secure Password:

```bash
# Generate 16 character password
python password-analyzer/analyzer.py --generate

# Custom length
python password-analyzer/analyzer.py --generate --length 24

# Without special characters
python password-analyzer/analyzer.py --generate --length 12
```

### Crack Password Hash:

```bash
# MD5 hash crack
python password-analyzer/analyzer.py \
  --hash "5f4dcc3b5aa765d61d8327deb882cf99" \
  --wordlist passwords.txt \
  --type md5

# SHA256 hash
python password-analyzer/analyzer.py \
  --hash "your-sha256-hash" \
  --wordlist rockyou.txt \
  --type sha256
```

### Example Output:

```
======================================================================
PASSWORD STRENGTH ANALYSIS
======================================================================

Password Length: 13 characters
Strength Score: 7/10
Overall Strength: STRONG

Security Checks:
  [✓] Minimum length (8+ characters)
  [✓] Contains uppercase letters
  [✓] Contains lowercase letters
  [✓] Contains numbers
  [✓] Contains special characters
  [✓] Is NOT a common password
  [✓] Has NO sequential characters
  [✓] Has NO repeated characters

Suggestions for Improvement:
  • Consider using 12+ characters for better security

======================================================================
```

---

## 🌍 4. SUBDOMAIN ENUMERATOR - कसं Run करायचं

### Basic Usage:

```bash
# Basic enumeration
python subdomain-enum/enum.py --domain example.com

# With custom wordlist
python subdomain-enum/enum.py --domain example.com --wordlist subs.txt

# More threads
python subdomain-enum/enum.py --domain example.com --threads 20

# Save results
python subdomain-enum/enum.py --domain example.com --output subdomains.txt
```

### Example Output:

```
======================================================================
SUBDOMAIN ENUMERATOR
======================================================================

[*] Target Domain: example.com
[*] Threads: 10

[+] Loaded 100 subdomains to test

[+] www.example.com                          → 93.184.216.34
[+] mail.example.com                         → 93.184.216.35
[+] ftp.example.com                          → 93.184.216.36
[+] admin.example.com                        → 93.184.216.37

======================================================================
[✓] Enumeration complete
[✓] Found 4 subdomains
======================================================================
```

---

## 📊 COMPLETE WORKFLOW EXAMPLE

### Security Assessment Script:

```bash
#!/bin/bash
# Complete security assessment

TARGET="example.com"
IP="192.168.1.1"

echo "[*] Starting security assessment for $TARGET"

# 1. Port Scanning
echo "[1] Port scanning..."
python port-scanner/scanner.py \
  --target $IP \
  --ports 1-1000 \
  --output ${TARGET}_ports.json

# 2. Subdomain Enumeration
echo "[2] Subdomain enumeration..."
python subdomain-enum/enum.py \
  --domain $TARGET \
  --output ${TARGET}_subdomains.txt

# 3. Web Fuzzing
echo "[3] Web fuzzing..."
python web-fuzzer/fuzzer.py \
  --url https://$TARGET \
  --wordlist dirs.txt

echo "[✓] Assessment complete!"
echo "[✓] Check output files: ${TARGET}_ports.json, ${TARGET}_subdomains.txt"
```

---

## 🎯 REAL EXAMPLES (वास्तविक उदाहरणं)

### Example 1: Scan Your Local Network

```bash
# Your router scan
python port-scanner/scanner.py --target 192.168.1.1 --ports 1-100

# Your own machine
python port-scanner/scanner.py --target localhost --ports 1-10000
```

### Example 2: Test Password Security

```bash
# Check your password
python password-analyzer/analyzer.py --password "YourPassword123"

# Generate new secure password
python password-analyzer/analyzer.py --generate --length 20
```

### Example 3: Fuzz Test Website (AUTHORIZED ONLY!)

```bash
# Test for directories
python web-fuzzer/fuzzer.py --url https://your-website.com --wordlist dirs.txt

# Test parameters
python web-fuzzer/fuzzer.py --url https://your-website.com/search --param q --wordlist params.txt
```

---

## ⚠️ IMPORTANT WARNINGS (महत्वाची सूचना)

### मराठी:
1. ✅ **फक्त तुमच्या स्वतःच्या systems वर test करा**
2. ✅ **Permission नसलेल्या systems scan करू नका**
3. ✅ **Production environments वर सावधगिरी बाळगा**
4. ✅ **Rate limiting लक्षात ठेवा**
5. ✅ **कायद्याचे पालन करा**

### English:
1. ✅ **Only test your own systems**
2. ✅ **Never scan without permission**
3. ✅ **Be careful with production**
4. ✅ **Respect rate limits**
5. ✅ **Follow the law**

---

## 🐛 TROUBLESHOOTING (समस्या निवारण)

### Problem: Module not found
```bash
# Solution:
pip install -r requirements.txt
```

### Problem: Permission denied (Port Scanner)
```bash
# Solution: Some ports need root/admin
sudo python port-scanner/scanner.py --target localhost
```

### Problem: DNS errors (Subdomain Enum)
```bash
# Solution: Check internet connection
ping 8.8.8.8

# Try different DNS
export DNS_SERVER=8.8.8.8
```

### Problem: Timeout errors
```bash
# Solution: Increase timeout
python port-scanner/scanner.py --target example.com --timeout 5
```

---

## 📚 WORDLISTS (शब्द यादी)

### Where to Get Wordlists:

```bash
# SecLists (Best collection)
git clone https://github.com/danielmiessler/SecLists.git

# Common directories
SecLists/Discovery/Web-Content/common.txt

# Subdomain words
SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Passwords
SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

### Create Custom Wordlist:

```bash
# Directory wordlist
cat > my_dirs.txt << EOF
admin
login
dashboard
api
backup
config
uploads
images
static
assets
EOF

# Subdomain wordlist
cat > my_subs.txt << EOF
www
mail
ftp
admin
dev
test
staging
api
blog
shop
EOF
```

---

## ✅ QUICK START CHECKLIST

- [ ] Clone repository
- [ ] Install Python 3.8+
- [ ] Install dependencies (`pip install -r requirements.txt`)
- [ ] Test port scanner on localhost
- [ ] Generate secure password
- [ ] Create custom wordlists
- [ ] Read all tool documentation

---

## 📧 SUPPORT

**Questions? Problems?**
- GitHub Issues: https://github.com/ChetanBiranje/security-scripts/issues
- Email: chetanbiranje@proton.me
- LinkedIn: linkedin.com/in/chetanbiranje

---

## 🎉 YOU'RE READY!

**तुमच्याकडे आता:**
- ✅ 8 working security tools
- ✅ Complete documentation
- ✅ Example commands
- ✅ Real-world use cases

**सुरू करा आणि security testing शिका! 🔐**

**Remember: Only use on authorized systems! फक्त authorized systems वर वापरा!**
