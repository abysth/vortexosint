# VortexOSINT

<div align="center">

```text
//    ____   ____________ ____________________________________  ___
//    \   \ /   /\_____  \\______   \__    ___/\_   _____/\   \/  /
//     \   Y   /  /   |   \|       _/ |    |    |    __)_  \     / 
//      \     /  /    |    \    |   \ |    |    |        \ /     \ 
//       \___/   \_______  /____|_  / |____|   /_______  //___/\  \
//                       \/       \/                   \/       \_/
```

**Multi-tool OSINT/GEOSINT Reconnaissance Framework**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)](https://github.com/abysth/vortexosint/releases)

</div>

---

## 🎯 Overview

VortexOSINT is a comprehensive command-line intelligence gathering toolkit designed for OSINT (Open Source Intelligence), GEOSINT (Geospatial Intelligence), and related reconnaissance activities. Built with a modular architecture, it provides specialized modules for different intelligence domains.

## ✨ Features

VortexOSINT includes **20 specialized modules**, a **2-page interactive menu** (`79` shortcuts), and a **built-in tutorial & environment checker** (`vortexosint tuto` / `vortexosint tuto setup` — see also [TUTORIAL.md](TUTORIAL.md)).

| Module | Description |
|--------|-------------|
| **OSINT** | Domain, email, phone, username, IP reconnaissance & Wayback Machine |
| **GEOSINT** | IP geolocation, coordinate analysis, address geocoding, WiFi/cell tower lookup, HTML maps |
| **SOCIAL** | Username enumeration across 50+ platforms, email/phone lookup |
| **GITHUB** | GitHub profile, organizations, top repos, public SSH keys & commit emails |
| **NETWORK** | Port scanning, service/banner detection, OS fingerprinting, ASN lookup, ping & public IP |
| **WEB** | HTTP security headers grading (A–F), redirect chain, `robots.txt` / `sitemap.xml` / `security.txt` |
| **TECH** | Web technology stack fingerprinter (servers, CDN/WAF, CMS, JS/CSS frameworks, cookies) |
| **SSL** | Live SSL/TLS certificate inspection (SANs, expiry, fingerprints) & `crt.sh` Certificate Transparency |
| **DNS** | Full DNS record dump (`A/AAAA/MX/NS/TXT/CAA/SOA`), reverse PTR & passive subdomain enumeration |
| **EMAILSEC** | Email & DNS security audit (SPF, DMARC, DKIM, CAA) & DNS propagation check |
| **MAC** | MAC address normalization, randomized/LAA detection & OUI vendor lookup |
| **IOC** | IOC extractor (IPs/URLs/emails/hashes), defang/refang & public threat feeds check |
| **URL** | URL unshortener, tracking parameter stripper (`utm_*`, `fbclid`) & heuristic phishing analyzer |
| **DORK** | Google, GitHub & Shodan dork generator |
| **BREACH** | Email exposure check (XposedOrNot / HIBP + Gravatar) & k-Anonymity pwned passwords check |
| **CRYPTO** | Blockchain address analysis, transaction tracking, clustering & entity profiling |
| **METADATA** | File metadata extraction (EXIF, GPS, PDF, Office DOCX/XLSX, binary strings, hashes) |
| **DECODE** | Mini CyberChef CLI: Base64/Hex/URL/ROT13, JWT decoder, Hash-ID, Timestamp & CIDR calc |
| **PASSWORD** | Secure generation (CSPRNG), passphrases, strength audit & salted hashing |
| **REPORT** | Merge JSON scan outputs into clean HTML or Markdown intelligence reports |

## 🚀 Installation

### Quick Install
```bash
pip install vortexosint
```

### From Source
```bash
git clone https://github.com/abysth/vortexosint.git
cd vortexosint
pip install -e .
```

### With Full Features
```bash
pip install vortexosint[full]
```

### 🤖 Install with an AI Assistant
You can also let an AI coding assistant (**Antigravity, Cursor, Claude Code, GitHub Copilot, Codex…**) install and verify everything for you automatically. Just paste this prompt:

```text
Clone https://github.com/abysth/vortexosint.git, install it with all dependencies (pip install -e ".[full]"), run `python -m vortexosint tuto setup` to verify the environment, and launch `python -m vortexosint`.
```

### Running the CLI
You can launch VortexOSINT either with the `vortexosint` command or directly as a Python module (works everywhere even if Python's `Scripts` folder is not in your `PATH`):
```bash
python -m vortexosint              # Launch the 2-page interactive menu
python -m vortexosint tuto setup   # Check Python, packages & .env
python -m vortexosint <module> ... # Run any module directly
```

## 📖 Usage

### Global Options & Tutorial
```bash
vortexosint                        # Interactive 2-page menu (guided mode)
vortexosint --menu                 # Force the interactive menu
vortexosint tuto                   # Built-in tutorial overview (all 20 modules)
vortexosint tuto setup             # Check Python, dependencies & .env API keys
vortexosint tuto <module>          # Detailed guide for a module (e.g. ssl, dns, decode)
vortexosint --help                 # Show help
vortexosint --version              # Show version
vortexosint --no-banner            # Disable ASCII banner
vortexosint --no-color             # Disable colored output
vortexosint -V                     # Verbose output
vortexosint -o results.json        # Save output to file
vortexosint --format json|txt|csv  # Output format
```

> 📘 **Full step-by-step guide (FR)** : see [TUTORIAL.md](TUTORIAL.md) for prerequisites, installation, `.env` configuration, all 20 modules, and troubleshooting.

### OSINT Module
```bash
# Domain reconnaissance
vortexosint osint --domain example.com
vortexosint osint -d example.com --deep

# Email investigation
vortexosint osint --email admin@example.com
vortexosint osint -e admin@example.com --deep

# Phone investigation
vortexosint osint --phone "+33 1 23 45 67 89"

# Username enumeration
vortexosint osint --username johndoe
vortexosint osint -u johndoe --deep

# IP investigation
vortexosint osint --ip 8.8.8.8

# Archived URLs (Wayback Machine: forgotten files, APIs, backups)
vortexosint osint --domain example.com --wayback
vortexosint osint -d example.com --wayback --wayback-limit 500
```

### GEOSINT Module
```bash
# IP geolocation
vortexosint geosint --ip 8.8.8.8
vortexosint geosint -i 8.8.8.8 --provider ipapi

# Reverse geocoding (coordinates to address)
vortexosint geosint --coords "48.8566,2.3522"
vortexosint geosint -c "48.8566,2.3522" --radius 5000

# Forward geocoding (address to coordinates)
vortexosint geosint --address "1600 Pennsylvania Ave NW"
vortexosint geosint -a "1600 Pennsylvania Ave NW" --map

# WiFi BSSID lookup (wardriving)
vortexosint geosint --wifi "AA:BB:CC:DD:EE:FF"
vortexosint geosint -w "AA:BB:CC:DD:EE:FF"

# Cell tower lookup
vortexosint geosint --cell "310,260,12345,67890"
```

### NETWORK Module
```bash
# Port scan
vortexosint network --target 192.168.1.0/24
vortexosint network -t example.com --ports 80,443,8080
vortexosint network -t 10.0.0.1 --scan-type syn

# Service detection
vortexosint network --target example.com --service-detect --banner-grab

# OS detection
vortexosint network --target 192.168.1.1 --os-detect

# ASN lookup
vortexosint network --asn AS15169

# Quick tools (also in the interactive menu, page 2)
vortexosint network --my-ip
vortexosint network --ping 8.8.8.8
```

### CRYPTO Module
```bash
# Address analysis
vortexosint crypto --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
vortexosint crypto -a 0x742d35Cc6634C0532925a3b844Bc9e7595f6E --blockchain eth

# Transaction analysis
vortexosint crypto --tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Entity lookup
vortexosint crypto --entity "Binance"
vortexosint crypto -e "Coinbase" --cluster
```

### SOCIAL Module
```bash
# Username enumeration
vortexosint social --username johndoe
vortexosint social -u johndoe --platforms twitter,github,linkedin

# Email lookup
vortexosint social --email johndoe@example.com

# Phone lookup
vortexosint social --phone "+1 555 123 4567"

# Availability check
vortexosint social --username johndoe --check-availability
```

### METADATA Module
```bash
# Single file
vortexosint metadata --file document.pdf
vortexosint metadata -f image.jpg --gps --exif

# Directory batch analysis
vortexosint metadata --dir /path/to/files
vortexosint metadata -d /path/to/files --recursive --strings
```

### PASSWORD Module
```bash
# Generate 5 secure passwords (20 chars, CSPRNG)
vortexosint password --length 20 --count 5
vortexosint password -l 32 -n 3 --no-symbols

# Memorable passphrase (6 words)
vortexosint password --passphrase --words 6

# Audit a password (hidden prompt, nothing written to disk)
vortexosint password --check

# Salted hash (sha256/sha512/sha3_256)
vortexosint password --hash --algo sha256
```

### WEB, TECH, SSL, DNS & EMAILSEC Modules
```bash
# Web security headers grade (A-F) & well-known files
vortexosint web --url https://example.com

# Web technology stack fingerprinter
vortexosint tech --url https://example.com

# SSL/TLS certificate inspection + crt.sh Certificate Transparency
vortexosint ssl --host example.com --ct

# Full DNS dump, passive subdomains & reverse PTR
vortexosint dns --domain example.com --subdomains
vortexosint dns --reverse 8.8.8.8

# SPF/DMARC/DKIM/CAA audit & DNS propagation
vortexosint emailsec --domain example.com --propagation

# MAC address / OUI vendor & randomization check
vortexosint mac --mac B8:27:EB:11:22:33
```

### IOC, URL, DORK, GITHUB, BREACH, DECODE & REPORT Modules
```bash
# IOC extraction, defang/refang & threat check
vortexosint ioc --extract alert.log
vortexosint ioc --defang https://evil.com/login

# URL unshortener, tracking stripper & phishing heuristic analysis
vortexosint url --url https://bit.ly/example
vortexosint url --url "http://192.168.1.1/login-verify" --phishing

# Dork generator (Google, GitHub, Shodan)
vortexosint dork --domain example.com --keyword secret

# GitHub developer OSINT
vortexosint github --username octocat

# Email breach exposure & k-Anonymity pwned password check
vortexosint breach --email user@example.com
vortexosint breach --password

# Offline Decode toolkit (Base64/Hex/URL/ROT13, JWT, Hash-ID, Timestamp, CIDR)
vortexosint decode --base64 "Vm9ydGV4"
vortexosint decode --jwt "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
vortexosint decode --hash-id d41d8cd98f00b204e9800998ecf8427e
vortexosint decode --cidr 192.168.1.0/24

# Merge JSON results into HTML or Markdown report
vortexosint report --input dns.json,web.json --report-out report.html
```

## 📊 Output Formats

```bash
# JSON (default)
vortexosint osint -d example.com -o results.json

# Text
vortexosint osint -d example.com -o results.txt --format txt

# CSV
vortexosint osint -d example.com -o results.csv --format csv
```

## 🔧 Configuration

Create a `.env` file for API keys:
```env
# Geolocation APIs
IPAPI_KEY=your_key
IPINFO_TOKEN=your_token
GEOJS_KEY=your_key

# Breach checking
HIBP_API_KEY=your_key

# Blockchain APIs
BLOCKCYPHER_TOKEN=your_token
ETHERSCAN_API_KEY=your_key

# Social APIs
TWITTER_BEARER_TOKEN=your_token
GITHUB_TOKEN=your_token
```

## 📁 Project Structure

```
vortexosint/
├── vortexosint/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                  # Main CLI entry point & 2-page interactive menu
│   ├── core/
│   │   ├── banner.py           # ASCII banners
│   │   ├── colors.py           # Terminal colors
│   │   ├── output.py           # JSON / TXT / CSV export
│   │   ├── tutorial.py         # Built-in tutorial & environment checker
│   │   └── ui.py               # Rich UI (tables, panels, prompts)
│   └── modules/
│       ├── osint_module.py
│       ├── geosint_module.py
│       ├── social_module.py
│       ├── github_module.py
│       ├── network_module.py
│       ├── web_module.py
│       ├── tech_module.py
│       ├── ssl_module.py
│       ├── dns_module.py
│       ├── emailsec_module.py
│       ├── mac_module.py
│       ├── ioc_module.py
│       ├── url_module.py
│       ├── dork_module.py
│       ├── breach_module.py
│       ├── crypto_module.py
│       ├── metadata_module.py
│       ├── decode_module.py
│       ├── password_module.py
│       └── report_module.py
├── tests/                      # Pytest unit test suite
├── TUTORIAL.md                 # Complete French user guide (A to Z)
├── pyproject.toml
├── requirements.txt
└── README.md
```

## ⚠️ Legal Disclaimer

**This tool is for educational and authorized testing purposes only.**

- Only use on systems you own or have explicit permission to test
- Respect rate limits and terms of service of external APIs
- Comply with applicable laws and regulations
- The authors are not responsible for misuse

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

### Auto-push local (optionnel)

`tools/autopush.py` surveille le dépôt : dès qu'un fichier change, il lance
les contrôles (`py_compile` + smoke test), commit, push vers `main` puis
vérifie via l'API GitHub que le distant == HEAD local.

```bash
python tools/autopush.py          # surveillance en continu (Ctrl+C pour arrêter)
python tools/autopush.py --once   # un seul passage
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Inspired by tools like `recon-ng`, `theHarvester`, `Sherlock`, `PhoneInfoga`
- Built with Python and love for the OSINT community

---

<div align="center">
Made with ❤️ by the VortexOSINT Team
</div>
