# 🥷 NULLVEIL RECON

> **Owner:** NULLVEIL · **Engine:** DeepHat · **Version:** 2.0.0 · **License:** MIT

A fast, colorful, modular **website & domain reconnaissance** tool built in Python. Run 17 attack modules — from DNS records to full API discovery — with a live progress bar and a premium terminal report.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║       ███╗   ██╗██╗   ██╗██╗     ██╗     ██╗   ██╗███████╗██╗██╗            ║
║       ████╗  ██║██║   ██║██║     ██║     ██║   ██║██╔════╝██║██║            ║
║       ██╔██╗ ██║██║   ██║██║     ██║     ██║   ██║█████╗  ██║██║            ║
║       ██║╚██╗██║██║   ██║██║     ██║     ╚██╗ ██╔╝██╔══╝  ██║██║            ║
║       ██║ ╚████║╚██████╔╝██║     ██║      ╚████╔╝ ███████╗██║██║            ║
║       ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝       ╚═══╝  ╚══════╝╚═╝╚═╝            ║
║                   R E C O N N A I S S A N C E   S U I T E                   ║
║                                                                              ║
║   Owner: NULLVEIL   Engine: DeepHat   Version: 2.0.0   Status: OPERATIONAL   ║
║                 Licensed use only — authorized targets only                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## ⚠️ Disclaimer

This tool is for **education, bug bounty, and authorized security testing ONLY**.

- Only scan targets **you own** or have **written permission** to test.
- Scanning systems without authorization is illegal in most countries.
- The authors are not responsible for misuse. **You are responsible for how you use this tool.**

By using NULLVEIL Recon you agree to these terms.

---

## ✨ Features — 17 Attack Modules

| # | Module | What it does |
|---|--------|--------------|
| 1 | **DNS Record Recon** | A / AAAA / CNAME / MX / NS / TXT / SOA / SRV / CAA records |
| 2 | **Subdomain Enumeration** | 230+ wordlist (330+ in deep) + SSL certificate SAN resolve |
| 3 | **Port Scanning** | Async TCP scan — 61 ports (140+ in deep) |
| 4 | **HTTP Analysis** | Server, headers, security header audit, tech stack |
| 5 | **SSL Certificate** | Issuer, subject, SANs, expiry date, days left |
| 6 | **Content Leakage** | Emails, IPs, phones, HTML comments, **API keys / secrets** |
| 7 | **Robots & Sitemap** | robots.txt + sitemap parsing (disallowed paths auto-queued) |
| 8 | **Path / Admin Discovery** | 80+ paths (180+ in deep): `.env`, `.git`, backups, swagger |
| 9 | **User Enumeration** | WordPress REST API, `?author=`, oEmbed |
| 10 | **API & Full Site Intel** | **Swagger/OpenAPI docs, JS endpoint extraction, forms, cookies, JSON-LD, 35+ tech fingerprint** |
| 11 | **WAF / CDN Detection** | Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, F5, ModSecurity + block-page probe |
| 12 | **Email Security** | SPF, DKIM (15+ selectors), DMARC, MTA-STS, BIMI + policy audit & findings |
| 13 | **API Security Audit** | OWASP API Top 10: CORS reflection, missing auth, verbose errors, rate limiting, sensitive data exposure (names only), HTTP methods, JWT config analysis |
| 14 | **External Intelligence** | **crt.sh certificate transparency subdomains, Wayback Machine history (old URLs / params / sensitive paths), dangling subdomain takeover check (35+ services)** |
| 15 | **CVE & Misconfig Scan** | **Version fingerprint (headers / meta / JS) → CVE correlation, exposed `.git` / `.env` / actuator / heapdump / phpinfo / server-status probes** |
| 16 | **Deep Crawler & Params** | **Multi-page BFS crawl, query + form parameter inventory, JS endpoint discovery, reflection detection (report-only)** |
| 17 | **TLS Deep Analysis** | **TLS 1.0–1.3 + cipher matrix, weak/legacy cipher flags, RSA/EC key size, OCSP stapling, HSTS audit** |

**Plus:**
- 🎨 Premium ASCII banner + live progress bar
- 📊 Exposure Risk Meter (0–100 score)
- 🎯 Selectable modules — run only what you need
- 💾 JSON export + **standalone HTML report** (dark theme, shareable)
- 📝 **Custom subdomain wordlist** (`-w wordlist.txt`)
- 🌐 Async & concurrent (fast on slow networks)
- 🛡 DNS-over-HTTPS fallback — works even when TCP/53 is blocked

---

## 📦 Installation

**Requirements:** Python **3.9+**

```bash
# 1. Clone
git clone https://github.com/nullveil0x/nullveil-recon.git
cd nullveil-recon

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python3 nullveil_recon.py example.com
```

### Optional: install as a `nullveil` command

```bash
chmod +x nullveil_recon.py
ln -s "$(pwd)/nullveil_recon.py" ~/.local/bin/nullveil
# then anywhere:
nullveil example.com
```

Or with a virtualenv:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
python3 nullveil_recon.py TARGET [options]
```

### Examples

```bash
# Full scan (all 17 modules)
python3 nullveil_recon.py example.com

# Interactive attack menu — pick modules by number
python3 nullveil_recon.py example.com -m

# Only DNS + SSL
python3 nullveil_recon.py example.com -a 1,5

# By module name
python3 nullveil_recon.py example.com -a dns,ssl,api

# Deep mode (bigger wordlists, more ports, more paths, more JS)
python3 nullveil_recon.py example.com --deep

# Save JSON report
python3 nullveil_recon.py example.com -o report.json

# Save standalone HTML report (dark theme — open in any browser)
python3 nullveil_recon.py example.com -H report.html

# Custom subdomain wordlist
python3 nullveil_recon.py example.com -w mysubs.txt

# WAF + Email security audit only
python3 nullveil_recon.py example.com -a waf,email

# API security audit (CORS, auth, rate limit, JWT checks)
python3 nullveil_recon.py example.com -a api,audit

# Advanced: CT logs + CVE scan + crawler + TLS audit
python3 nullveil_recon.py example.com -a ext,cve,crawl,tls

# Custom ports + timeout
python3 nullveil_recon.py http://192.168.1.10:8080 -p 80,443,8080 -t 15

# List all attack modules
python3 nullveil_recon.py -l
```

### All Options

| Flag | Description |
|------|-------------|
| `-m`, `--menu` | Interactive attack selection menu |
| `-a`, `--attack LIST` | Comma-separated modules: `1,2,5` or `dns,ssl` or `all` |
| `-l`, `--list-attacks` | Show all attack modules |
| `-d`, `--deep` | Deep mode: bigger wordlists, more ports & paths |
| `-t`, `--timeout N` | HTTP/DNS timeout in seconds (default: 10) |
| `-c`, `--concurrency N` | Max concurrent requests (default: 100) |
| `-p`, `--ports LIST` | Custom ports, e.g. `80,443,8080` |
| `-o`, `--output FILE` | Save JSON report to file |
| `-H`, `--html FILE` | Save standalone HTML report (open in browser) |
| `-w`, `--wordlist FILE` | Custom subdomain wordlist (one per line) |
| `-q`, `--quiet` | Suppress console output |
| `-V`, `--version` | Show version |

---

## 📖 Sample Output

```
      Target: example.com   Mode: NORMAL   Started: 2026-10-19 01:10:21
      Attacks: dns, sub  (2/17 modules)

╔══════════════════════════════ ◈ RECON REPORT ◈ ══════════════════════════════╗
║                                 example.com                                  ║
║        Scanned: 2026-10-19 01:10:33   Duration: 11.6s   Mode: NORMAL         ║
╚══════════════════════════════════════════════════════════════════════════════╝
╭───────────────────────────── ◈ EXPOSURE LEVEL ◈ ─────────────────────────────╮
│ ███████░░░░░░░░░░░░░  36/100 — CAUTION                                       │
│   Risk Level: MEDIUM   Secrets: 0   Flagged Paths: 0   Missing Headers: 9    ╰──────────────────────────────────────────────────────────────────────────────╯
```

### API Discovery example

Against an API-first site (e.g. Swagger Petstore):

```
╔═══════════ ◈ API DOCUMENT FOUND: Swagger Petstore - OpenAPI 3.0 ◈ ═══════════╗
║   Source: /api/v3/openapi.json                                               ║
║   Title:  Swagger Petstore - OpenAPI 3.0  v1.0.27                            ║
║   Endpoints: 13                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
   1   /pet            2   /store/order        3   /user/login
   4   /pet/{petId}    5   /user/{username}    ...
```

---

## 💾 JSON Report

```bash
python3 nullveil_recon.py example.com -o report.json
```

```json
{
  "tool": "NULLVEIL Recon",
  "owner": "NULLVEIL",
  "version": "2.0.0",
  "summary": { "dns_records": 3, "api_endpoints": 16, "...": "..." },
  "dns": [...],
  "subdomains": [...],
  "open_ports": [...],
  "paths": [...],
  "secrets": [...],
  "api": {
    "documents": [...],
    "live_endpoints": [...],
    "paths_in_source": [...],
    "forms": [...],
    "cookies": [...],
    "metadata": {...}
  },
  "external_intel": { "ct_subdomains": [...], "wayback": {...}, "takeover_risks": [...] },
  "cve": { "versions": [...], "findings": [...] },
  "crawler": { "pages": [...], "parameters": [...], "forms": [...] },
  "tls": { "matrix": [...], "certificate": {...}, "findings": [...] }
}
```

---

## 🗺️ Roadmap

- [x] HTML report export (`-H report.html`)
- [x] WAF detection (`-a waf`)
- [x] Email security (SPF / DKIM / DMARC / MTA-STS / BIMI) (`-a email`)
- [x] Custom wordlist support (`-w wordlist.txt`)
- [x] API security audit (OWASP API Top 10) (`-a audit`)
- [x] External intel — crt.sh CT logs + Wayback history + subdomain takeover (`-a ext`)
- [x] CVE correlation + misconfig scan (`-a cve`)
- [x] Deep crawler + parameter inventory (`-a crawl`)
- [x] TLS version / cipher deep analysis (`-a tls`)
- [ ] Resume / scan history
- [ ] Nuclei template integration
- [ ] Screenshot capture

Contributions welcome — open an issue or PR.

---

## 📜 License

MIT © NULLVEIL — see [LICENSE](LICENSE).

---

**Use responsibly. Authorized targets only.** 🥷
