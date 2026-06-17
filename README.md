
```
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

# WebRecon 🔍


*Passive & active web recon — IP, DNS, ports, SSL, headers, subdomains, vulns*

> ⚠️ **Only scan systems you own or have written permission to test.**



---

## What It Does

WebRecon runs **8 automated modules** on any target website and gives you a full intelligence report — with no paid APIs, no heavy dependencies, and no extra tools required.

| Module | What you get |
|--------|-------------|
| 🌐 IP Resolution | Primary IP, all IPs, IPv6, reverse DNS |
| 🔍 DNS Enumeration | A, MX, NS, TXT, SOA, DMARC, DKIM, SPF |
| 🚪 Port Scan | 30+ ports, threaded, service names + risk rating |
| 📋 Header Analysis | Tech stack, CDN, cookies, security headers score |
| 🔒 SSL/TLS | Certificate issuer, expiry, TLS version, ciphers |
| 🌳 Subdomains | 60 common subdomains tested via DNS |
| 📝 WHOIS | Registrar, dates, domain age |
| ⚠️ Vuln Hints | CRITICAL / HIGH / MEDIUM / LOW findings |

---

## Install — 3 Steps

```bash
# 1. Install the only dependency
pip3 install dnspython --break-system-packages

# 2. Make the script executable
chmod +x web_recon.py

# 3. Run it
python3 web_recon.py example.com
```

---

## Usage

```bash
# Standard scan
python3 web_recon.py example.com

# Full scan (+ subdomains + WHOIS)
python3 web_recon.py example.com --full

# Custom ports + more threads
python3 web_recon.py example.com --ports 8080,9200 --threads 50

# Save results to JSON
python3 web_recon.py example.com --full --output report.json
```

| Flag | Short | What it does |
|------|-------|-------------|
| `--full` | `-f` | All modules including subdomains + WHOIS |
| `--subdomains` | | Subdomain enumeration only |
| `--whois` | `-w` | WHOIS lookup only |
| `--ports` | `-p` | Extra ports (comma-separated) |
| `--threads` | `-t` | Thread count (default: 30) |
| `--timeout` | | Per-port timeout seconds (default: 1.0) |
| `--output` | `-o` | Export results to JSON file |

---

## Screenshots

<img width="900" height="480" alt="screenshot_01_ip_dns" src="https://github.com/user-attachments/assets/3c08ccf8-880c-4ede-aff4-5b62294ebaa6" />


---

### 02 — Port Scan with Risk Ratings
<img width="900" height="480" alt="screenshot_02_ports" src="https://github.com/user-attachments/assets/e3370f23-2568-427c-8b34-532fa86ec81e" />



### 03 — Vulnerability Assessment Summary
<img width="900" height="480" alt="screenshot_04_vulns" src="https://github.com/user-attachments/assets/c7880774-13ff-4197-aaa8-f5f36fb844e7" />



## After Scanning — Go Deeper

```bash
# Deep Nmap scan
nmap -sV -sC -O -p- example.com

# Web vulnerability scanner
nikto -h https://example.com

# Directory brute-force
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# WordPress scan (if detected)
wpscan --url https://example.com
```

---

## Project Structure

```
phishing_project/
├── web_recon.py           ← This tool
├── phishing_analyzer.py   ← Email phishing tool (Project 3)
├── phishing_report.html   ← Visual awareness report
├── README.md              ← This file
└── assets/
    ├── screenshot_01_ip_dns.png
    ├── screenshot_02_ports.png
    ├── screenshot_03_vulns.png
 
```

---

## Legal

✅ Your own servers · CTF challenges · Authorised pen-tests · Training labs  
❌ Scanning without permission is illegal — IT Act 2000 (India) · CFAA (US) · Computer Misuse Act (UK)

---

<div align="center">

**DecodeLabs · Batch 2026 · Cyber Security Project 3**  
📧 decodelabs.tech@gmail.com · 🌐 www.decodelabs.tech · 📍 Greater Lucknow, India

</div>
