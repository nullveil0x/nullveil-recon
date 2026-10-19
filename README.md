# 🥷 NULLVEIL RECON

> **Owner:** NULLVEIL · **Engine:** DeepHat · **Version:** 3.2.2 · **License:** MIT

A fast, colorful, modular **website & domain reconnaissance** tool built in Python. Run 27 attack modules — from DNS records to full API discovery — with a live progress bar and a premium terminal report.

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
║   Owner: NULLVEIL   Engine: DeepHat   Version: 3.2.2   Status: OPERATIONAL   ║
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

## ✨ Features — 27 Attack Modules

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
| 18 | **Supply Chain / Third-Party Risk** | **External scripts/styles/iframes/vendor mapping (70+ vendors: CDN, analytics, ads, SRI audit), third-party form actions, NS/MX provider identification, CSP gap check** |
| 19 | **Asset Criticality Classification** | **Rule-based 0–100 scoring → CRITICAL / HIGH / MEDIUM / LOW tiers for subdomains, ports, paths (keyword + finding signals)** |
| 20 | **Anomaly Detection (ML)** | **Unsupervised: soft-404 content-hash clustering, latency z-score, response-size IQR outliers, k-means (k=2) outlier cluster** |
| 21 | **Threat Intel Feeds** | **AlienVault OTX pulses, OpenPhish active phishing feed, SSLBL botnet-C2 blacklist, Spamhaus Zen DNSBL (keyless DoH), optional AbuseIPDB** |
| 22 | **Breach Monitoring** | **HaveIBeenPwned breach enumeration + harvested-email exposure check (free HIBP_API_KEY), phishing cross-check** |
| 23 | **Compliance Mapping** | **PCI-DSS v4.0 + ISO 27001:2022 Annex A + SOC 2 TSC — 31 controls mapped to scan evidence (PASS/FAIL/PARTIAL) with disclaimer** |
| 24 | **Attack Path Graph** | **Asset/finding graph, BFS attack-path search (entry → crown jewels), exploit-chain hypotheses, DOT export — report-only narratives** |
| 25 | **Target Correlation** | **Cross-org/multi-tenant correlation: shared NS / MX / IP / CDN across your domains, auto-derived from cert SANs or `--correlate`** |
| 26 | **Screenshot Capture** | **Headless-Chromium snapshots of homepage + discovered/flagged paths → `nullveil_shots/<domain>/`, embedded in HTML report (optional: `playwright`)** |
| 27 | **Nuclei Template Scan** | **ProjectDiscovery nuclei integration — runs the industry-standard template engine (critical/high/medium) and parses JSONL findings (optional: `nuclei` binary)** |

**Plus:**
- 🎨 Premium ASCII banner + live progress bar
- 📊 Exposure Risk Meter (0–100 score)
- 🎯 Selectable modules — run only what you need
- 💾 JSON export + **standalone HTML report** (dark theme, shareable)
- 📄 **Client-ready PDF report** (`--pdf`, headless Chromium, paginated A4)
- 🖥 **Local web dashboard** (`--dashboard`) — live charts, findings search, screenshot gallery — offline, stdlib-only, localhost-only
- 💾 **Scan history + resume** — every scan auto-saves; `Ctrl+C` keeps partial results; `--resume` runs only what's missing
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

### Optional power-ups

Screenshot capture (`-a shot`) and Nuclei scanning (`-a nuclei`) use **optional** tools —
NULLVEIL degrades gracefully with a friendly hint if they are missing:

```bash
# Screenshots (headless Chromium)
pip install playwright
playwright install chromium

# Nuclei — industry-standard vulnerability templates
# (github.com/projectdiscovery/nuclei/releases or):
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## 🚀 Usage

```bash
python3 nullveil_recon.py TARGET [options]
```

### Examples

```bash
# Full scan (all 27 modules)
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

# v3.0.0: supply chain + attack graph + compliance mapping
python3 nullveil_recon.py example.com -a supply,graph,comp

# v3.0.0: full advanced pipeline (intel + breach + anomaly + graph)
python3 nullveil_recon.py example.com -a intel,breach,anom,graph

# Evidence / repro pack (benign curl/dig commands — no exploit payloads)
python3 nullveil_recon.py example.com -R repro.md

# Export attack path graph as DOT (render with Graphviz: dot -Tpng graph.dot -o g.png)
python3 nullveil_recon.py example.com --dot graph.dot

# Cross-org correlation (your own domains)
python3 nullveil_recon.py example.com --correlate brand2.com,brand3.com

# Breach monitoring (free key: haveibeenpwned.com/APIKey)
HIBP_API_KEY=yourkey python3 nullveil_recon.py example.com -a breach

# v3.1.0: screenshots + nuclei template scan
python3 nullveil_recon.py example.com -a shot,nuclei

# Custom nuclei templates
python3 nullveil_recon.py example.com -a nuclei --nuclei-templates ~/my-templates/

# v3.2.0: client-ready PDF report
python3 nullveil_recon.py example.com -a all -H report.html --pdf report.pdf

# Convert an old JSON report to PDF (works with -o exports AND history files)
python3 nullveil_recon.py --pdf-from old_report.json --pdf client.pdf
python3 nullveil_recon.py --pdf-from ~/.nullveil/history/20261019-071049-e904a1.json --pdf client.pdf

# v3.2.0: interactive web dashboard (localhost, offline, zero extra deps)
python3 nullveil_recon.py --dashboard          # http://127.0.0.1:8899
python3 nullveil_recon.py --dashboard 9000     # custom port

# Scan history: list past scans / resume an interrupted one
python3 nullveil_recon.py --history
python3 nullveil_recon.py example.com --resume          # latest scan for target
python3 nullveil_recon.py example.com --resume 20261019 # specific ID prefix

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
| `-R`, `--repro FILE` | Export evidence/reproduction pack (markdown, benign — no payloads) |
| `--dot FILE` | Export Attack Path Graph as Graphviz DOT file |
| `--correlate LIST` | Extra domains for cross-org correlation, e.g. `a.com,b.com` |
| `--hibp-key KEY` | HaveIBeenPwned API key (or set `HIBP_API_KEY` env) |
| `--history` | List saved scan history (`~/.nullveil/history`) |
| `--resume [ID]` | Resume previous scan — re-runs only the missing modules |
| `--no-history` | Don't auto-save this scan to history |
| `--nuclei-templates DIR` | Custom nuclei template path for `-a nuclei` |
| `--pdf FILE` | Save a **client-ready PDF report** (headless Chromium — needs playwright) |
| `--pdf-from JSON` | Convert an existing JSON report to PDF (use with `--pdf`) |
| `--dashboard [PORT]` | Serve a **local web dashboard** of scan history (default port 8899) |
| `-q`, `--quiet` | Suppress console output |
| `-V`, `--version` | Show version |

---

## 📖 Sample Output

```
      Target: example.com   Mode: NORMAL   Started: 2026-10-19 01:10:21
      Attacks: dns, sub  (2/25 modules)

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
  "version": "3.1.0",
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
  "tls": { "matrix": [...], "certificate": {...}, "findings": [...] },
  "supply_chain": { "vendors": [...], "findings": [...], "providers": {...} },
  "criticality": { "tiers": {...}, "assets": [...] },
  "anomaly": { "samples": [...], "findings": [...], "soft404": true },
  "threat_intel": { "ips": [...], "sources": [...], "findings": [...] },
  "breach": { "breaches": [...], "checks": [...], "findings": [...] },
  "compliance": { "frameworks": {...}, "coverage_pct": 52, "total_controls": 31 },
  "attack_graph": { "nodes": [...], "edges": [...], "attack_paths": [...], "chains": [...] },
  "correlation": { "targets": [...], "links": [...], "findings": [...] },
  "screenshots": { "captured": 5, "shots": [...], "dir": "nullveil_shots/example.com" },
  "nuclei": { "version": "v3.11.1", "templates_run": 1284, "findings": [...] }
}
```

---

## 🧭 v3.0.0 Design Notes (safe-by-design choices)

A few v3 features are **deliberately shaped** so the tool stays defensive & report-only:

| Requested | How NULLVEIL delivers it |
|-----------|--------------------------|
| Exploit chain simulator | **Chain *hypothesis* narratives** built from confirmed facts (graph module) — no exploit payloads, no execution |
| Dark-web / leaked-credential monitoring | **Breach-intel APIs** (HaveIBeenPwned + phishing feeds) — the same approach commercial monitoring products use; no Tor/marketplace scraping |
| Automated PoC generation | **Evidence / repro pack** (`-R`): benign `curl`/`dig` commands that reproduce each finding so developers can verify & re-test fixes |
| Multi-tenant correlation | Correlates **domains you provide/own** (`--correlate`) or auto-derived from your cert SANs |

Compliance output is **evidence-based partial mapping**, never a certification claim.

### v3.2.2 notes (polish + fixes)

- **Cleaner output**: probing deliberately-old TLS 1.0/1.1 no longer prints Python `DeprecationWarning` noise — reports stay readable (findings themselves are unchanged and accurate).
- **`--pdf-from` now accepts history files**: you can convert either a `-o report.json` export *or* a `~/.nullveil/history/<id>.json` entry straight to PDF (the history wrapper is auto-unwrapped).

### v3.2.0 notes (dashboard, PDF, robustness)

- **Dashboard** is a **zero-dependency**, **localhost-only**, **offline** standard-library web server — it reads your local scan history and renders charts/findings/screenshots in the browser. Screenshot serving is index-based (no user-controlled paths) and constrained to your own home/workspace directories.
- **PDF export** renders the branded HTML report through the same headless Chromium used for screenshots (`--pdf`), and can convert any saved JSON report (`--pdf-from`).
- **Interrupt-safe scanning**: `Ctrl+C` saves partial results to history, and `--resume` finishes exactly the modules that didn't complete — nothing is re-scanned twice.

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
- [x] Supply chain / third-party risk mapping (`-a supply`)
- [x] Asset criticality classification (`-a crit`)
- [x] ML anomaly detection — soft-404, z-score, k-means (`-a anom`)
- [x] Threat intel feeds — OTX, OpenPhish, SSLBL, Spamhaus (`-a intel`)
- [x] Breach monitoring — HIBP integration (`-a breach`)
- [x] Compliance mapping — PCI-DSS / ISO 27001 / SOC 2 (`-a comp`)
- [x] Attack path graph + chain hypotheses + DOT export (`-a graph`)
- [x] Multi-target / cross-org correlation (`--correlate`)
- [x] Evidence / repro pack export (`-R`)
- [x] Screenshot capture — headless Chromium (`-a shot`)
- [x] Nuclei template integration (`-a nuclei`)
- [x] Scan history + resume (`--history`, `--resume`)
- [x] Ctrl+C-safe scans — partial results auto-saved, `--resume` finishes the job
- [x] Web dashboard (`--dashboard`) — local, offline, zero-dependency
- [x] Client-ready PDF reports (`--pdf`, `--pdf-from`)

Contributions welcome — open an issue or PR.

---

## 📜 License

MIT © NULLVEIL — see [LICENSE](LICENSE).

---

**Use responsibly. Authorized targets only.** 🥷
