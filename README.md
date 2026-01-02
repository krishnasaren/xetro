# xetro
An intentionally vulnerable web application and advanced penetration testing framework for learning, research, and authorized security testing.

# 🛡️ Advanced Web Vulnerability Scanner

An intelligent, behavior-based web vulnerability scanner designed for **learning, research, and authorized penetration testing**.

This tool is NOT a simple payload reflector.  
It analyzes **how applications behave when attacked**, similar to professional scanners.

---

## ⚠️ LEGAL WARNING (READ BEFORE USING)

This scanner performs **active security attacks**.

- ✅ Use ONLY on applications you own or have explicit permission to test
- ❌ Do NOT scan public or production websites
- ❌ Unauthorized scanning is illegal and unethical

By using this software, **you accept full legal responsibility**.

---

## 📌 WHAT THIS PROJECT IS

This project is a **standalone Python penetration testing scanner** that:

- Crawls a website
- Discovers input points (GET & POST)
- Injects attack payloads
- Compares responses with baselines
- Detects vulnerabilities using behavior analysis
- Generates professional security reports

It is meant to:
- Teach how scanners actually work
- Help understand false positives & false negatives
- Practice bug bounty & CTF skills
- Learn secure coding by seeing insecure behavior

---

## 🎯 WHAT THIS SCANNER CAN DO

✔ Discover endpoints automatically  
✔ Detect GET and POST parameters  
✔ Test HTML forms automatically  
✔ Perform multi-payload mutation  
✔ Detect blind vulnerabilities (no error shown)  
✔ Measure response time differences  
✔ Compare content changes  
✔ Generate HTML & JSON reports  

---

## 🧠 VULNERABILITIES DETECTED

| Vulnerability | Description | CWE |
|---------------|------------|-----|
| SQL Injection | Error, Boolean, Time-based, Blind | CWE-89 |
| Cross-Site Scripting (XSS) | Reflected & stored patterns | CWE-79 |
| Command Injection | OS command execution | CWE-78 |
| SSRF | Internal network access | CWE-918 |
| Path Traversal | Arbitrary file read | CWE-22 |
| IDOR | Insecure object access patterns | CWE-639 |
| Sensitive Data Exposure | Secrets in responses | CWE-200 |

---

## 🏗️ HOW THE SCANNER WORKS (IN SIMPLE WORDS)

### Step 1 – Endpoint Discovery
The scanner:
- Visits the target URL
- Extracts links
- Parses forms
- Collects GET & POST parameters

### Step 2 – Baseline Request
For each parameter, it sends a **safe test request** and records:
- Status code
- Response length
- Response body
- Response time
- Response hash

This is the **baseline**.

### Step 3 – Payload Injection
The scanner injects payloads such as:
- `' OR 1=1`
- `<script>alert(1)</script>`
- `; whoami`
- `../../etc/passwd`
- `http://127.0.0.1`

### Step 4 – Behavioral Analysis
It compares:
- Baseline response vs attack response
- Time differences
- Content differences
- Error patterns
- Unexpected leaked data

### Step 5 – Confidence Scoring
Each vulnerability is scored from **0–100% confidence**.

---

## ⚙️ SYSTEM REQUIREMENTS

### Python
- Python **3.9 or higher**

### Operating System
- Linux / Windows / macOS
- Works best on localhost or VM labs

---

## 📦 REQUIRED PYTHON LIBRARIES

Install all dependencies:

```bash
pip install requests beautifulsoup4 colorama jinja2 pycryptodome tldextract

