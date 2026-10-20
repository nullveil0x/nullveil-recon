# 🥷 NULLVEIL RECON

> **Owner:** NULLVEIL · **Engine:** DeepHat · **Version:** 3.9.0 · **License:** MIT (dual-licensed — see [Commercial](LICENSE-COMMERCIAL.md))

[![CI](https://github.com/nullveil0x/nullveil-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/nullveil0x/nullveil-recon/actions/workflows/ci.yml)
![tests](https://img.shields.io/badge/tests-34%20passing-brightgreen)
![modules](https://img.shields.io/badge/modules-48-blue)
![python](https://img.shields.io/badge/python-3.9%2B-blue)

A fast, colorful, modular **website & domain reconnaissance** tool built in Python. Run 48 attack modules — from DNS records to full API discovery, advanced JS/historical/cloud discovery, vulnerability verification (CVSS/CWE, MITRE ATT&CK, live CVE intel), remediation and executive reporting — with a live progress bar and a premium terminal report.

**Defensive by design:** read-only, no exploit payloads, no active exploitation. See [`SECURITY.md`](SECURITY.md) and [`docs/AUTHORIZATION.md`](docs/AUTHORIZATION.md) before scanning.

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
║   Owner: NULLVEIL   Engine: DeepHat   Version: 3.9.0   Status: OPERATIONAL   ║
║                 Licensed use only — authorized targets only                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## ⚡ Quick Start (TL;DR)

```bash
git clone https://github.com/nullveil0x/nullveil-recon.git
cd nullveil-recon
pip install -r requirements.txt
python3 nullveil_recon.py example.com                  # full scan (49 modules)
python3 nullveil_recon.py example.com --dashboard      # scan → PDF-ready UI opens
```

Scan a target you are **authorized** to test, then explore the results in JSON, HTML, PDF, or the web dashboard.

---

## ⚠️ Disclaimer

This tool is for **education, bug bounty, and authorized security testing ONLY**.

- Only scan targets **you own** or have **written permission** to test.
- Scanning systems without authorization is illegal in most countries.
- The authors are not responsible for misuse. **You are responsible for how you use this tool.**

By using NULLVEIL Recon you agree to the [EULA](EULA.md). Full policy:
[SECURITY.md](SECURITY.md) · authorization checklist: [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md).

---

## ✨ Features — 48 Attack Modules

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
| 28 | **Katana Crawler (API)** | **ProjectDiscovery katana deep crawl — URL/endpoint/JS-file harvesting that feeds the unified API pool (optional: `katana` binary)** |
| 29 | **LinkFinder JS Endpoints** | **Hidden API endpoint extraction from every JS bundle via LinkFinder's regex engine (uses `linkfinder` CLI if installed, otherwise built-in engine — zero-dependency)** |
| 30 | **FFUF API Fuzzing** | **Content/API brute-force with a curated 400+ path API wordlist + every endpoint discovered by other modules, auto-calibrated, soft-404 filtered (optional: `ffuf` binary)** |
| 31 | **Authenticated API Scan** | **Session/auth injection (`--auth-token` / `--auth-header` / `--auth-cookie`) + automated login engine (`--login-url` + user/pass → captures cookies & Bearer tokens) + multi-role profiling (`--role`) — probes every discovered endpoint *with & without* auth to expose auth-gated and role-hidden APIs** |
| 32 | **SSRF & Internal Pivot** | **IP-bypass header fuzzing (XFF/X-Real-IP/X-Internal-API/X-Original-URL… vs baseline diff), cloud metadata probing (AWS/GCP/Azure paths + provider headers), optional out-of-band callbacks via `interactsh-client` (`--oob`)** |
| 33 | **Smart Context Fuzz** | **Context-aware wordlist generation from business type / domain / tech fingerprint (e-commerce → `api/order/internal`, `cart/v2` …) + JS data-flow analysis that resolves `const API_BASE = … + '/v3/users'` concatenations into concrete endpoints, then fuzzes (ffuf or native prober)** |
| 34 | **Burp / Caido Traffic Bridge** | **Two-way intercepting-proxy integration: `--proxy` routes the *entire* scan (shared httpx client + katana/ffuf/nuclei subprocesses) through Burp Suite / Caido so automated traffic lands in their HTTP history for manual follow-up — module verifies the listener is live; `--har` imports HAR captures exported from Burp (Save items → HAR) or Caido (Export HAR), parsing every entry for endpoints, query/body params, cookies, auth-header names and secrets in responses — all fed into the unified API pool so ffuf/auth/smartfuzz analyze captured traffic too** |
| 35 | **AI Patch & Remediation Generator** | **Offline, template + heuristic engine (no AI key needed) that turns each finding into copy-paste remediation — nginx security-header blocks, Cloudflare WAF/rate-limit rules, CSP/CORS/TLS configs, secret rotation steps, admin/IP allow-listing and more, ranked by severity** |
| 36 | **Read-Only PoC Verification Generator** | **Non-destructive verification commands (`curl` HEAD/GET, `dig`, `openssl s_client`, `nc -z`) that *demonstrate a finding exists* for CRITICAL/HIGH/MEDIUM issues — no exploit payloads, no writes, no brute-force; policy printed with every report** |
| 37 | **Multi-Channel Webhook Notifications** | **Instant scan alert to Slack / Telegram / Discord / Teams via `--webhook-slack` / `--webhook-telegram TOKEN:CHATID` / `--webhook-discord` / `--webhook-teams` — a CRITICAL/HIGH finding changes the headline (🚨 CRITICAL ALERT), severity counts included, redaction-aware (no secret values), Telegram is MarkdownV2-safe with a plain-text fallback, graceful when unconfigured** |
| 39 | **Executive Report Exporter** | **C-level HTML report (`--exec-report`) + best-effort PDF (`--exec-pdf`; weasyprint → reportlab → playwright): exposure score, severity mix, KPIs, top risks, PCI-DSS/ISO 27001/SOC 2 compliance snapshot and a prioritised remediation plan — print-ready** |
| 40 | **JS Secret & Source-Map Miner** | **Deep JavaScript analysis (`jsecret`): follows `//# sourceMappingURL` source maps to recover original (unminified) sources, scans every bundle for API keys/tokens/private keys (AWS, Stripe, GitHub, Slack, Google…), webpack chunk discovery, dangerous DOM sinks and hidden endpoints. Secrets are masked in the report; GET-only** |
| 41 | **Historical URL Miner** | **Queries Wayback / CommonCrawl / OTX for URLs that *used* to exist (`wayback`) — forgotten admin panels, backups, `.env`/`.git`, config and old query parameters that may still be live; feeds the API pool** |
| 42 | **Hidden Parameter Miner** | **Arjun-style GET/POST parameter discovery (`param`): control-parameter baseline + response-diff/reflection analysis to find real hidden params with near-zero false positives. Sends only a benign unique marker — no SQLi/XSS/command payloads** |
| 43 | **GraphQL Deep Audit** | **`gql`: locates GraphQL endpoints and checks introspection exposure, `did you mean` field-suggestion leakage, depth-limit enforcement and batching — query (read) operations only, never mutations** |
| 44 | **Cloud Storage Enumeration** | **`cloud`: derives bucket names from the target and probes AWS S3 / Azure Blob / GCP Storage with HEAD/GET only — flags public listings and (carefully) suspected world-writable buckets. No uploads, no writes** |
| 45 | **CVSS 4.0 / CWE Risk Scoring** | **`cvss`: re-scores every finding with a documented CVSS 4.0 macro-vector + legacy CVSS 3.1 base score and a CWE weakness ID — produces an industry-standard, prioritised risk register and flags severity re-banding** |
| 46 | **MITRE ATT&CK Mapping** | **`attack`: maps every finding to MITRE ATT&CK Enterprise tactics/techniques and exports an importable **ATT&CK Navigator layer** (`--attack-layer FILE`) — SOC / blue-team coverage view; no techniques are executed** |
| 47 | **CVE Intelligence Enricher** | **`cveintel`: enriches each fingerprinted CVE. Curated **offline intel** by default (CVSS, CWE, EPSS-style, CISA KEV, exploit-availability → P1–P4 patch priority); add `--cve-live` to merge **LIVE NVD 2.0 + FIRST EPSS + CISA KEV** data (disk-cached, no API key, graceful offline fallback)** |
| 48 | **Subdomain Takeover v3** | **`takeover`: dedicated takeover engine with 70+ provider fingerprints (S3/CloudFront/Heroku/GitHub Pages/Netlify/Vercel/Azure/Fastly/Firebase…) — resolves full CNAME chains and matches unclaimed-resource HTTP signatures. Read-only: nothing is registered or claimed** |
| 49 | **Continuous Change Monitor** | **`watch`: baseline snapshot + drift alerting for repeat scans (`--watch [N] --interval SEC`) — reports new/removed assets and a risk delta/verdict (REGRESSION/IMPROVEMENT/STABLE); also usable as a CI drift gate** |
| 50 | **Read-Only Vulnerability Verification** | **`vulnverify`: benign-marker proof for reflected-XSS sinks, SQL error/boolean signatures and param-driven path traversal — proves *reachability* only, never sends an executable payload or extracts data** |

**Plus:**
- 🎨 Premium ASCII banner + live progress bar
- 📊 Exposure Risk Meter (0–100 score)
- 🎯 Selectable modules — run only what you need
- 🧹 **Smart deduplication** — redundant INFO findings collapsed (`×N`), path/number normalisation (`--no-dedupe` to disable)
- ⏱ **Strict per-module timeouts** — 180s normal / 300s crawl-fuzz (`--module-timeout`, `--module-timeout-heavy`)
- 🔁 **Scan-diff change tracking** — new subdomains / ports / paths / APIs surfaced vs the previous scan
- 💾 JSON export + **standalone HTML report** (dark theme, shareable)
- 📄 **Client-ready PDF report** (`--pdf`, headless Chromium, paginated A4)
- 🖥 **Local web dashboard** (`--dashboard`) — live charts, findings search, screenshot gallery, **1-click Executive PDF/HTML download** — offline, stdlib-only, localhost-only
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

Screenshot capture (`-a shot`), Nuclei (`-a nuclei`), external crawlers/fuzzers and the
executive PDF use **optional** tools — NULLVEIL degrades gracefully with a friendly hint
if they are missing:

```bash
# Screenshots (headless Chromium) & HTML→PDF executive reports
pip install playwright
playwright install chromium

# Nuclei — industry-standard vulnerability templates
# (github.com/projectdiscovery/nuclei/releases or):
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**v3.7.0 feature dependencies:** **none** — both tiers are pure-Python over the existing `httpx` dependency. The five Tier-1 discovery modules (JS secret miner, historical URL miner, hidden parameter miner, GraphQL audit, cloud storage enumeration) and the five Tier-2 intelligence modules (CVSS/CWE scoring, MITRE ATT&CK mapping, CVE intel enricher, subdomain takeover v3, change monitor) need no extra packages, AI keys or remote APIs. **Live CVE enrichment** (`--cve-live`, module 47) uses public NVD 2.0 + FIRST EPSS + CISA KEV endpoints (no API key required), is **disk-cached** (`~/.nullveil/cve_cache/`, weekly TTL) and **gracefully falls back** to curated offline intel if the network is unreachable. All network touchpoints degrade gracefully when endpoints are unavailable.

**v3.6.0 feature dependencies (all optional — modules degrade gracefully):**

```bash
pip install aiogram slack-sdk weasyprint reportlab playwright
python -m playwright install
```

| Feature | Package | Notes |
|---------|---------|-------|
| Executive PDF | `weasyprint` → `reportlab` → `playwright` | first available is used; HTML report always works |
| Webhook notifications | `httpx` (already required) | Slack/Discord/Teams use plain HTTP; Telegram uses the Bot API |
| Screenshots / PDF | `playwright` (+ `playwright install chromium`) | same optional dep as before |
| AI Patch generator | *none* | **fully offline** — template/heuristic engine, no API key |
| Read-only PoC generator | *none* | pure Python, emits `curl`/`dig`/`openssl` commands |

---

## 🚀 Usage

```bash
python3 nullveil_recon.py TARGET [options]
```

### Examples

```bash
# Full scan (all 49 modules)
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

# v3.3.0: API extraction pipeline — katana crawl → linkfinder JS endpoints → ffuf API fuzz
python3 nullveil_recon.py example.com -a katana,linkfinder,ffuf

# Same pipeline with custom fuzz wordlist
python3 nullveil_recon.py example.com -a ffuf --ffuf-wordlist ~/api-paths.txt

# v3.4.0: authenticated scan — automated login, then diff every endpoint with & without the session
python3 nullveil_recon.py example.com -a api,katana,linkfinder,ffuf,auth \
  --login-url https://example.com/api/login --login-user you@example.com --login-pass secret

# Session / API-key injection (applies to EVERY module, incl. katana/ffuf/nuclei subprocesses)
python3 nullveil_recon.py example.com -a auth --auth-token eyJhbGciOi... \
  --auth-cookie 'session=abc123' --auth-header 'X-Api-Key: xyz'

# Multi-role profiling: find APIs the admin role sees but the user role doesn't
python3 nullveil_recon.py example.com -a auth --auth-token "$USER_TOKEN" \
  --role 'user=Cookie: sid=user123' --role 'admin=Authorization: Bearer admin456'

# v3.4.0: SSRF & internal pivot — bypass-header fuzz + cloud metadata + OOB callbacks
python3 nullveil_recon.py example.com -a ssrf --oob --oob-wait 60
# (needs: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)

# v3.4.0: smart context fuzz — business-aware wordlist + JS data-flow endpoint resolution
python3 nullveil_recon.py example.com -a smartfuzz --deep

# v3.5.0: Burp/Caido bridge — route the whole scan through your intercepting proxy
# (Burp: Proxy → Options → Proxy Listeners, default 127.0.0.1:8080 — every NULLVEIL
# request — httpx, katana, ffuf, nuclei — shows up in Proxy → HTTP history)
python3 nullveil_recon.py example.com --proxy http://127.0.0.1:8080

# v3.5.0: import a HAR capture exported from Burp (Save items → HAR) or Caido (Export HAR)
# → endpoints, params, cookies & secrets feed the API pool for ffuf/auth/smartfuzz
python3 nullveil_recon.py example.com -a burp,ffuf --har burp_export.har

# Multiple captures (e.g. one per logged-in role) — repeatable
python3 nullveil_recon.py example.com -a burp --har user.har --har admin.har

# v3.6.0: AI-style remediation + read-only PoC verification (offline, no AI key)
python3 nullveil_recon.py example.com -a all,patch,poc

# v3.6.0: executive C-level report (HTML always; PDF best-effort: weasyprint → reportlab → playwright)
python3 nullveil_recon.py example.com -a all,exec --exec-report exec.html --exec-pdf exec.pdf

# v3.6.0: push the summary to chat (Slack / Telegram / Discord / Teams — any combination)
python3 nullveil_recon.py example.com --webhook-slack https://hooks.slack.com/services/T/B/X
python3 nullveil_recon.py example.com --webhook-telegram "123456:ABC-DEF:-1001234567890"
python3 nullveil_recon.py example.com --webhook-discord https://discord.com/api/webhooks/...

# v3.6.0: scan-diff is automatic — rerun any target to get a "changes since last scan" panel

# v3.6.0: tune module timeouts / disable dedup if you want raw findings
python3 nullveil_recon.py example.com --module-timeout 120 --module-timeout-heavy 300
python3 nullveil_recon.py example.com --no-dedupe

# v3.7.0: risk-standardisation + blue-team intelligence + continuous monitoring
python3 nullveil_recon.py example.com -a cvss,attack,cveintel,takeover,watch
python3 nullveil_recon.py example.com -a cveintel --cve-live          # live NVD + EPSS + CISA KEV
python3 nullveil_recon.py example.com --cve-cache-clear              # reset the live-CVE cache
python3 nullveil_recon.py example.com -a all --attack-layer layer.json   # ATT&CK Navigator layer
python3 nullveil_recon.py example.com --watch            # loop until Ctrl+C, alert on drift
python3 nullveil_recon.py example.com --watch 24 --interval 3600         # hourly, 24 runs (CI gate)

# v3.8.0: plugin rule engine — extend the built-in CVE + misconfig knowledge
python3 nullveil_recon.py example.com -a cve --rules rules/            # load a directory of YAML/JSON rules
python3 nullveil_recon.py example.com -a cve --rules my-cves.json      # or a single file
# see rules/example.yaml + rules/example.json for the rule schema

# v3.8.0: resilient scanning — transparent retry/backoff on 429/503 + connection errors
python3 nullveil_recon.py example.com --retries 5                      # more retries (default 2)
python3 nullveil_recon.py example.com --no-retry                       # disable the retry layer

# v3.9.0: mass scanning — many targets in one run
python3 nullveil_recon.py --targets-file targets.txt -a all -o out.json   # one report per line (+ combined .index.json)
python3 nullveil_recon.py --targets-list 'a.com,b.com,10.0.0.0/29' -a http # inline list; CIDR expands to hosts
# v3.9.0: WAF evasion — coherent real-browser profile rotation per request
python3 nullveil_recon.py example.com --evade light                     # rotate UA + jitter (default: none)
python3 nullveil_recon.py example.com --evade stealth --evade-rotate-every 3
# v3.9.0: deep accuracy — re-verify findings, drop false positives
python3 nullveil_recon.py example.com -a paths --verify                  # second independent probe; non-reproducers removed
# v3.9.0: read-only vulnerability verification (reachability proof, no payloads)
python3 nullveil_recon.py example.com -a vulnverify                      # benign-marker XSS / SQL-error / traversal proof
# v3.9.0: automation — external plugins + headless JSON API
python3 nullveil_recon.py example.com -a all --plugin my_policy.py       # run external Python plugin(s) over the results
python3 nullveil_recon.py --serve-api                                    # JSON scan API on :8900 (POST /scan, GET /health)

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
| `--ffuf-wordlist FILE` | Custom path wordlist for `-a ffuf` (default: built-in API wordlist) |
| `--auth-header 'Name: Value'` | Header injected into **every** scan request (repeatable) |
| `--auth-cookie name=value` | Session cookie injected into every request (repeatable) |
| `--auth-token TOKEN` | Bearer token shorthand → `Authorization: Bearer TOKEN` |
| `--auth-api-key KEY` / `--auth-api-key-header NAME` | API key sent in a custom header (default `X-API-Key`) |
| `--login-url URL` + `--login-user` + `--login-pass` | **Automated login engine** — POSTs credentials, captures cookies/Bearer token from the response, every module then runs authenticated |
| `--login-user-field` / `--login-pass-field` | JSON/form field names (default `username` / `password`) |
| `--login-body JSON` | Raw login JSON template with `{user}` / `{pass}` placeholders |
| `--login-form` | Send login fields as form data instead of JSON |
| `--login-token-path PATH` | Dot-path of the Bearer token in the login JSON (auto-detects `access_token`/`token`/`jwt`) |
| `--login-extra K=V` | Extra login body field (repeatable) |
| `--role 'NAME=SPEC'` | Multi-role profile for role-diff scan (repeatable): header, cookie, or bare-token spec |
| `--oob` | Enable interactsh out-of-band SSRF callbacks for `-a ssrf` (needs `interactsh-client`) |
| `--oob-server HOST` | Custom interactsh server (default: public server) |
| `--oob-wait SEC` | Seconds to wait for OOB callbacks (default 45 normal / 90 deep) |
| `--proxy URL` | Route the **entire scan** (httpx + katana/ffuf/nuclei) through an intercepting proxy — Burp / Caido `http://127.0.0.1:8080`. The `burp` module verifies the listener and reports capture status |
| `--har FILE` | Import a **HAR capture** from Burp (*Save items → HAR*) or Caido (*Export HAR*) — endpoints, params, cookies, auth-header names & secrets feed the unified API pool (repeatable) |
| `--pdf FILE` | Save a **client-ready PDF report** (headless Chromium — needs playwright) |
| `--pdf-from JSON` | Convert an existing JSON report to PDF (use with `--pdf`) |
| `--exec-report FILE` | Write the **executive C-level HTML report** (module 39) |
| `--exec-pdf FILE` | Also export the executive report as PDF (weasyprint → reportlab → playwright) |
| `--webhook-slack URL` | Post the scan summary to a **Slack** incoming-webhook URL (module 37) |
| `--webhook-telegram TOKEN:CHATID` | Post to **Telegram** via a bot, e.g. `123456:ABC:-1001234567890` |
| `--webhook-discord URL` | Post the scan summary to a **Discord** webhook URL |
| `--webhook-teams URL` | Post the scan summary to a **Microsoft Teams** incoming-webhook URL |
| `--module-timeout SEC` | Strict per-module hard timeout for normal modules (default: 180s) |
| `--module-timeout-heavy SEC` | Strict hard timeout for crawl/fuzz modules (default: 300s) |
| `--no-dedupe` | Disable smart deduplication of redundant low-severity findings |
| `--dashboard [PORT]` | Serve a **local web dashboard** of scan history (default port 8899) |
| `-q`, `--quiet` | Suppress console output |
| `-V`, `--version` | Show version |

---

## 🖥 Web Dashboard (v3.2.0+)

A **zero-dependency**, **localhost-only**, **offline** web UI (Python stdlib `http.server` + an embedded SPA — no CDN, no extra pip package) that reads your local scan history.

```bash
# After / alongside a scan — dashboard opens automatically when the scan finishes
python3 nullveil_recon.py example.com --dashboard
python3 nullveil_recon.py example.com --dashboard 9000     # custom port

# Dashboard only — browse every past scan (no target needed)
python3 nullveil_recon.py --dashboard
```

**What you get:** exposure score + severity charts · findings with search/filter · screenshot gallery · per-module breakdown · clickable scan list · **1-click Executive PDF / HTML download** (module 39) for any past scan.

| Thing to know | Detail |
|---|---|
| Does it open by itself after a scan? | **Only if you pass `--dashboard`** in the same command, or chain `nullveil site.com && nullveil --dashboard` |
| Where does the data come from? | `~/.nullveil/history/` — **every** past scan shows up, no re-scan needed |
| URL | `http://127.0.0.1:8899` (default) |
| How to stop it | **`Ctrl + C`** in the terminal running it |
| `Address already in use` | Another dashboard is running — use `--dashboard 9000`, or stop the first one |

> Binds to `127.0.0.1` only. Screenshot serving is index-based and constrained to your own home/workspace dirs.

---

## 📖 Sample Output

```
      Target: example.com   Mode: NORMAL   Started: 2026-10-19 01:10:21
      Attacks: dns, sub  (2/49 modules)

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
  "version": "3.9.0",
  "summary": { "dns_records": 3, "api_endpoints": 16, "remediation_patches": 9, "poc_verifications": 4, "dedupe_removed": 6, "...": "..." },
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
  "nuclei": { "version": "v3.11.1", "templates_run": 1284, "findings": [...] },
  "burp_caido": { "proxy": "http://127.0.0.1:8080", "proxy_ok": true, "har_entries": 312, "endpoints": [...], "params": [...], "cookies": [...], "secrets": [...] },
  "scan_diff": { "available": true, "score": 47, "verdict": "HIGH DRIFT", "added": {...}, "findings": [...] },
  "remediation": { "generated": 9, "patches": [ { "severity": "HIGH", "title": "Enforce HTTP security headers at the edge", "remediation": "```nginx ...```" } ] },
  "poc_verification": { "generated": 4, "policy": "Read-only verification only — HEAD/GET/dig/openssl", "pocs": [ { "severity": "HIGH", "check": "admin-api", "commands": [ { "desc": "HEAD the endpoint", "cmd": "curl -sSI https://..." } ] } ] },
  "notifications": { "channels": ["slack"], "sent": [ { "channel": "slack", "status": 200 } ], "failed": [] },
  "executive_report": { "html": "exec.html", "pdf": "exec.pdf", "score": 40, "verdict": "HIGH EXPOSURE" },
  "js_secret": { "bundles": 6, "secrets": [...], "sinks": [...], "source_maps": [...], "count": 3, "findings": [...] },
  "wayback": { "historical_urls": 415, "interesting": [...], "params": [...], "count": 415, "findings": [...] },
  "params": { "endpoints": [...], "hidden": [...], "count": 4, "findings": [...] },
  "graphql": { "endpoints": [...], "introspection": true, "suggestions": true, "depth_limited": false, "count": 1, "findings": [...] },
  "cloud_storage": { "candidates_tested": 19, "buckets": [...], "count": 1, "findings": [...] },
  "cvss": { "count": 123, "mean_score": 7.23, "distribution": { "CRITICAL": 41, "HIGH": 33, "MEDIUM": 49, "LOW": 0 }, "top": [ { "score": 9.3, "severity": "CRITICAL", "cwe": "CWE-798", "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N", "rebanded": "HIGH→CRITICAL" } ], "findings": [...] },
  "mitre_attack": { "technique_count": 9, "tactic_count": 6, "techniques": [ { "id": "T1552.001", "tactic": "Credential Access", "max_severity": "HIGH", "count": 5 } ], "layer": { "techniques": [...] }, "findings": [...] },
  "cve_intel": { "count": 1, "kev_count": 1, "kev": ["CVE-2021-41773"], "cvss_mean": 9.8, "live": true, "live_enriched": 1, "cves": [ { "cve": "CVE-2021-41773", "cvss": 9.8, "cwe": "CWE-22", "kev": true, "epss": 0.99992, "exploit_available": true, "source": "live:nvd+epss", "priority": "P1 — patch now" } ], "findings": [...] },
  "takeover_v3": { "hosts_checked": 12, "risk_count": 1, "providers": 73, "risks": [ { "host": "blog.example.com", "service": "GitHub Pages", "status": "LIKELY TAKEOVER", "cname_chain": [...] } ], "findings": [...] },
  "watch": { "baseline": true, "added_total": 3, "removed_total": 0, "risk_delta": 9, "verdict": "REGRESSION", "baseline_when": "2026-10-19T01:10:21", "findings": [...] },
  "dedupe": { "before": 84, "after": 71, "removed": 13 }
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

### v3.9.0 notes (mass scanning · WAF evasion · deep accuracy)

Three advanced-operator features — all still **read-only / defensive**:

- **Mass Scanning** (`--targets-file FILE` / `--targets-list LIST`) runs the whole pipeline over many targets in one invocation. Targets are de-duplicated, blank lines and `#` comments ignored, and **CIDR blocks are expanded to host IPs** (safety-capped by `--max-hosts`, default 1024). Each target gets its own report (`-o out.json` → `out.<target>.json`, `-H`/`--pdf` likewise) plus a combined **`out.index.json`** with the per-target exposure score + verdict, so a fleet scan is one command and one summary.
- **WAF Evasion** (`--evade none|light|stealth`) rewrites every request to a **coherent, real-browser profile** — UA, `Accept`, `Accept-Language`, `Sec-Ch-Ua`, `Sec-Fetch-*` — rotating between four profiles (Chrome/Windows, Chrome/macOS, Firefox, Safari) with added **request jitter** (`--evade-rotate-every N`). Profiles are self-consistent (a Chrome UA never ships a Firefox header set), which is what gets naive scripts fingerprinted. It **never** forges auth, tampers with payloads or mutates the target — it only makes the scan's *own* traffic look like an ordinary visitor's. Injected auth headers (`Authorization`/`Cookie`/`X-Api-Key`/`X-Auth-Token`) are preserved. Requests rewritten are exported under `evasion`.
- **Deep Accuracy** (`--verify`) adds a second, independent verification pass: it re-probes the **false-positive-prone** classes (flagged paths, `.git`/`.env`/config/backup exposures) from a fresh connection and **drops anything that does not reproduce**, recording it (never silently deleting) under `verify_dropped`. A network hiccup is treated as *inconclusive* — findings are kept, so a flaky link can never hide a real issue. Results are exported under `verification` (`tested`/`kept`/`dropped`/`unknown`/`paths_removed`).
- **Read-Only Vulnerability Verification** (`vulnverify`, module 50) proves *reachability* of a vulnerability class with **benign markers only — it never sends an executable payload and never extracts data**:
  - **Reflected-XSS sink** — an alphanumeric marker plus a quote/bracket pair is placed in a parameter; if the bracket survives **raw** in the response (rather than becoming an HTML entity) the value reaches an unencoded output sink. No `<script>`, no event handler.
  - **SQL-injection surface** — a marker plus a single quote is sent; a hit requires **both** the marker **and** a recognised database-error signature in the body (the marker prevents a pre-existing error page matching). No data is read.
  - **Path traversal** — traversal sequences are tried only against file-ish parameters, and a hit is confirmed against a **control request** that does not contain the sequence, matched to a known system-file signature. No file contents are extracted or stored.
  - Every hit becomes a standard finding (JSON/HTML/PDF/dashboard/CVSS/ATT&CK/remediation/webhooks). Results under `vuln_verify` (`tested`, `xss`, `sqli`, `traversal`). See [`docs/VERIFICATION.md`](docs/VERIFICATION.md).
- **External Plugins** (`--plugin FILE.py`, repeatable) load plain Python modules that run **after** the scan and turn organisation-specific logic into first-class findings. A plugin defines `run(ctx)` and returns `(severity, check, detail)` tuples (or strings → `INFO`); the `ctx` object exposes the results, summary, target, a `findings()` helper and a `log()`. Plugin findings flow into CVSS/ATT&CK/remediation/report/webhooks like any other, and are inventoried under `plugins` + `plugin_runs`. A **crashing plugin never aborts the scan** (recorded, skipped). Only load plugins you trust. See [`docs/AUTOMATION.md`](docs/AUTOMATION.md) and [`examples/plugin_example.py`](examples/plugin_example.py).
- **Headless JSON API** (`--serve-api [PORT]`, `--api-host`) turns NULLVEIL into a service for CI/CD: `POST /scan` (JSON body → full report JSON), `GET /health`, `GET /report?id=…`. One scan runs at a time (concurrent `POST /scan` → `429`), `id` is validated against path traversal, errors are always JSON, and it binds to **localhost by default**. Authentication is off by default in the API. See [`docs/AUTOMATION.md`](docs/AUTOMATION.md).

### v3.8.0 notes (plugin rule engine + resilient scanning)

Two power-user features that make NULLVEIL **extensible** and **robust under real-world throttling**:

- **Plugin Rule Engine** (`--rules PATH` — file or directory, repeatable) loads external **YAML or JSON** rule files that extend the built-in knowledge without editing the source. Two rule kinds:
  - **CVE / version rules** — `product`, `mode` (`lt|le|eq|ge|gt`), `version` (boundary, list or string), optional `major`, `id`, `severity`, `title`. Merged with the built-in `CVE_RULES` and matched by the version-fingerprint engine in module 15.
  - **Misconfiguration probes** — `path`, optional `match` regex, `severity`, `id`, `title`. Merged with the built-in probes; **user rules always run in full**, even on a quick (non-`--deep`) scan.
  - Every external rule becomes a real finding (JSON/HTML/PDF/dashboard/notifications), and the loaded rule inventory is recorded in the report under `ruleset` (`files`, `cve_rules`, `misconfig_rules`, `errors`). See [`rules/example.yaml`](rules/example.yaml) and [`rules/example.json`](rules/example.json) for the schema. YAML needs `PyYAML`; **JSON works with the standard library alone**.
- **Transparent Retry / Backoff Layer** — the HTTP transport now retries transient failures (**429 / 502 / 503 / 504** and connection errors) with **exponential backoff + jitter**, honouring a server's `Retry-After` header. It wraps the transport, so **every** request — discovery, audit, fuzzing, subprocess-driven — benefits without a single call-site change, keeping scans **polite** under rate-limiting instead of silently dropping data. Tune with `--retries N` (default 2) or disable with `--no-retry`; the scan-wide retry count is exported as `retries`.

### v3.7.0 notes (Tier-1 advanced discovery)

Five new discovery modules push NULLVEIL into top-tier territory — the kind of deep surface discovery that commercial scanners charge for:

- **JS Secret & Source-Map Miner** (`jsecret`, module 40) walks every JS bundle (page, crawlers, HAR) and then *de-obfuscates* them by fetching `//# sourceMappingURL` **source maps**, recovering the original unminified `sourcesContent`. It scans all recovered text for ~22 secret patterns (AWS, Stripe, GitHub, GitLab, Slack, SendGrid, Google, OpenAI, JWTs, private-key blocks…) plus dangerous DOM sinks (`innerHTML`, `eval`, `document.write`, wildcard `postMessage`). **All secret values are masked** (`AKIAIO…MPLE`) — nothing is ever used to authenticate — and it feeds recovered endpoints/chunks into the shared API pool.
- **Historical URL Miner** (`wayback`, module 41) queries **Wayback CDX**, **CommonCrawl** and **AlienVault OTX** for URLs that *used to* exist on the domain (including subdomains), then flags the interesting ones (`.env`, `.git`, backups, `.sql`, config, `admin`, `debug`, `token`…) and harvests old query-parameter names. Forgotten endpoints frequently remain live — one of the highest-yield real-world findings.
- **Hidden Parameter Miner** (`param`, module 42) is Arjun-style but with a key safety upgrade: a **control-parameter baseline**. It first probes an obviously-unknown parameter; if the endpoint echoes/varies for *that* too, reflection alone is discarded. Only parameters that change the response beyond the control baseline, or reflect when the control does not, are reported — **near-zero false positives**. GET and (deep) POST. Sends only a benign unique marker; no SQLi/XSS/command payloads.
- **GraphQL Deep Audit** (`gql`, module 43) locates common GraphQL endpoints and reports introspection exposure (schema dump), `did you mean` field-suggestion leakage (enumeration without introspection), missing depth limits (DoS surface) and batching. **Query-only — never mutations.**
- **Cloud Storage Enumeration** (`cloud`, module 44) derives ~19 likely bucket names from the target domain and probes **AWS S3 / Azure Blob / GCP Storage** with HEAD/GET only, flagging public listings and (conservatively) buckets that answer to an unknown key. **Never uploads, writes or deletes.**

All five integrate with the existing pipeline: they export to JSON, appear as CLI panels, render in the web dashboard, feed the executive report/compliance/remediation engines, and are included in `--webhook-*` alert severity counts.

### v3.7.0 notes (Tier-2 verification & intelligence)

Tier 2 turns raw findings into **standardised, prioritised, blue-team-ready intelligence**. All five modules are additive — they re-use every finding the discovery pass already collected and add no active exploitation:

- **CVSS 4.0 / CWE Risk Scoring** (`cvss`, module 45) re-scores **every** finding with a documented **CVSS 4.0 macro-vector**, a legacy **CVSS 3.1 base score** and a **CWE** weakness ID. The combined score drives a prioritised risk register (mean score, severity distribution, top 25), and findings whose score bands differ from the original severity are flagged as **re-banded** (e.g. `HIGH→CRITICAL`). The vector and method are printed/exported so scores are auditable — it is a *reviewed heuristic*, not an authoritative NVD assessment.
- **MITRE ATT&CK Mapping** (`attack`, module 46) maps each finding category to **ATT&CK Enterprise** tactics and techniques (T1190, T1552.001, T1530, T1078, T1499…) and emits a tactic coverage view plus an importable **ATT&CK Navigator layer** JSON (`--attack-layer FILE`). Pure defensive mapping — no technique is ever executed.
- **CVE Intelligence Enricher** (`cveintel`, module 47) enriches every CVE surfaced by module 15 with **CVSS base score, CWE, EPSS likelihood, CISA KEV** membership and exploit-availability, ranked into **P1–P4** patch priorities (KEV › high-EPSS › CVSS). By default it uses **curated offline intel** (no network); pass **`--cve-live`** to merge **LIVE NVD 2.0 + FIRST EPSS + the CISA KEV catalog** (all public, **no API key**). Live results are **disk-cached** at `~/.nullveil/cve_cache/` with a weekly TTL (only cache-misses hit the network, capped per scan to stay polite), so repeat scans are instant and offline. If the network is unreachable the module **silently falls back** to the offline values and records the error. Clear the cache with `--cve-cache-clear`. No active checks against the target.
- **Subdomain Takeover v3** (`takeover`, module 48) is a dedicated takeover engine with **70+ provider fingerprints** (AWS S3/CloudFront/Elastic Beanstalk, Heroku, GitHub/GitLab Pages, Netlify, Vercel, Azure App Service/Blob/Front Door, Shopify, Fastly, Firebase, Fly/Render/Railway, Zendesk, Statuspage and many more). It resolves the **full CNAME chain** and matches unclaimed-resource HTTP signatures, reporting LIKELY TAKEOVER (HIGH) and dangling-but-unreachable (MEDIUM) candidates. **Read-only** — nothing is registered, claimed or modified.
- **Continuous Change Monitor** (`watch`, module 49) snapshots the target's asset sets and compares each run against the newest prior baseline, reporting **new/removed assets** and a **risk delta + verdict** (`REGRESSION` / `IMPROVEMENT` / `CHANGED` / `STABLE`). Drive it with `--watch [N] --interval SEC` (N=0 loops until `Ctrl+C`) or use it as a **CI drift gate**. Each watch run rebuilds its network transport, so long-running loops stay stable run after run.

All five export to JSON, render as CLI panels and dashboard sections, and feed `_collect_findings` (so they appear in notifications, compliance and the executive report).

### v3.6.0 notes (remediation, PoC verification, notifications & executive reporting)

- **AI Patch & Remediation Generator** (`patch`, module 35) is **fully offline** — a template + heuristic engine maps each finding to concrete, copy-paste fixes: nginx security-header blocks, Cloudflare WAF / rate-limit / transform rules, CSP & CORS config, TLS modernisation, secret-rotation steps, admin IP allow-listing, SSRF egress hardening and more. **No AI API key, no network traffic.**
- **Read-Only PoC Verification Generator** (`poc`, module 36) emits strictly non-destructive commands (`curl` HEAD/GET, `dig`, `openssl s_client`, `nc -z`) that *demonstrate a finding exists*. It sends **no payloads, performs no writes and never brute-forces** — the policy is printed with every report and embedded in the JSON.
- **Multi-Channel Webhook Notifications** (`notify`, module 37) pushes a concise summary (counts, change verdict, admin-API hits) to Slack / Telegram / Discord / Teams. Only **counts and the target name** are sent — never secrets — and the module degrades gracefully when nothing is configured *or* when a channel rejects the message. Slack/Discord/Teams use plain HTTP; Telegram uses the Bot API.
- **Executive Report Exporter** (`exec`, module 39) produces a print-ready C-level HTML report (`--exec-report`) plus a best-effort PDF (`--exec-pdf`; the first available of `weasyprint` → `reportlab` → `playwright` is used). It summarises exposure score, severity mix, KPIs, top risks, a PCI-DSS / ISO 27001 / SOC 2 compliance snapshot and a prioritised remediation plan.
- **Scan-diff change tracking** is automatic — every scan is compared against the newest previous scan for the same target, surfacing **new subdomains / ports / paths / APIs** with a 0–100 drift score and verdict.
- **Smart deduplication** collapses redundant and near-identical findings (repeated INFO items become one entry marked `(×N)`, paths/numbers are normalised) — disable with `--no-dedupe`.
- **Strict per-module timeouts** guarantee the scan never hangs: `180s` for normal modules and `300s` for crawl/fuzz modules, tunable via `--module-timeout` / `--module-timeout-heavy`.
- **1-click Executive PDF from the dashboard** — every past scan in the local web dashboard has `⬇ Executive PDF` (and `⬇ HTML`) buttons that stream the module-39 report straight from `/api/exec-pdf?id=…`. No CLI re-run needed; if no PDF engine is installed the endpoint transparently serves the print-ready HTML instead. The history-entry id is regex-validated, so path traversal is rejected (404).
- **Instant alert headline** — module 37 now leads with a severity verdict (`🚨 CRITICAL ALERT` / `⚠️ HIGH-RISK ALERT` / `🔔 Recon complete`), adds a 🔴/🟠/🟡/🔵 severity line and the single top risk; Telegram uses crash-safe **MarkdownV2** with an automatic **plain-text fallback** when escaping still fails.

### v3.5.0 notes (Burp Suite / Caido traffic bridge)

- **`--proxy URL`** routes the **entire scan** through an intercepting proxy (Burp Suite / Caido / mitmproxy / ZAP): the shared httpx client **and** the external subprocesses (`katana -proxy`, `ffuf -x`, `nuclei -proxy`) all go through the listener, so NULLVEIL's automated traffic shows up in the proxy's HTTP history for manual follow-up (Repeater / Caido replay).
- **`--har FILE`** imports a HAR capture exported from Burp (*Proxy → HTTP history → Save items → HAR*), Caido (*Export HAR*) or a browser's DevTools. Every entry is parsed for **endpoints, query/body parameters, cookies, auth-header names and secrets in responses** — all injected into the unified API pool so `ffuf`, `auth` and `smartfuzz` analyze captured traffic too. Requests outside the target domain are ignored.
- Module verifies the proxy listener is actually reachable and reports capture status; `--proxy`/`--har` **auto-select** the `burp` module. (module 34)

### v3.2.2 notes (polish + fixes)

- **Cleaner output**: probing deliberately-old TLS 1.0/1.1 no longer prints Python `DeprecationWarning` noise — reports stay readable (findings themselves are unchanged and accurate).
- **`--pdf-from` now accepts history files**: you can convert either a `-o report.json` export *or* a `~/.nullveil/history/<id>.json` entry straight to PDF (the history wrapper is auto-unwrapped).

### v3.2.0 notes (dashboard, PDF, robustness)

- **Dashboard** is a **zero-dependency**, **localhost-only**, **offline** standard-library web server — it reads your local scan history and renders charts/findings/screenshots in the browser. Screenshot serving is index-based (no user-controlled paths) and constrained to your own home/workspace directories.
- **PDF export** renders the branded HTML report through the same headless Chromium used for screenshots (`--pdf`), and can convert any saved JSON report (`--pdf-from`).
- **Interrupt-safe scanning**: `Ctrl+C` saves partial results to history, and `--resume` finishes exactly the modules that didn't complete — nothing is re-scanned twice.

---

## 🩺 Troubleshooting / FAQ

| Problem | Fix |
|---|---|
| `nullveil: command not found` | Use the full path (`python3 nullveil_recon.py …`) or create the symlink (see *install as a `nullveil` command*) |
| `ModuleNotFoundError: No module named 'httpx'` (or `dns` / `rich`) | `pip install -r requirements.txt` |
| PDF skipped / no PDF produced | PDF uses headless Chromium → `pip install playwright && playwright install chromium` |
| Screenshots skipped (`-a shot`) | Same as PDF — install `playwright` + Chromium |
| `nuclei` skipped (`-a nuclei`) | Optional binary: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `katana` skipped / `ffuf` skipped (`-a katana` / `-a ffuf`) | Optional binaries: `go install github.com/projectdiscovery/katana/cmd/katana@latest` and `go install github.com/ffuf/ffuf/v2@latest` |
| Proxy unreachable (`--proxy`) | Start the Burp/Caido listener first (Burp: *Proxy → Options → Proxy Listeners*, default `127.0.0.1:8080`) — scan continues but traffic is not captured |
| `--har` shows 0 entries | Burp needs *Save items → HAR*, Caido *Export HAR*; only requests to the target domain are imported |
| Executive PDF skipped | Install one of `weasyprint`, `reportlab`, `playwright` (`pip install weasyprint reportlab playwright && python -m playwright install`) — the HTML report is always written |
| Webhook shows `ConnectError` / `404` | Check the URL/token; Telegram needs `TOKEN:CHATID`, Slack/Discord/Teams need their full incoming-webhook URL. `404` from Telegram usually means a wrong bot token |
| Module shows `⏱ timeout` | The module exceeded its hard cap (180s normal / 300s crawl-fuzz) — raise `--module-timeout` / `--module-timeout-heavy` for slow targets |
| Fewer findings than before | Smart deduplication collapsed duplicates (look for `(×N)`) — pass `--no-dedupe` to see every raw finding |
| PoC commands look generic | The generator matches on the finding text; ensure the relevant modules ran so there is evidence to build commands from |
| Dashboard: `Address already in use` | Another dashboard is running — use `nullveil --dashboard 9000`, or stop the first one |
| `crt.sh` 502 / Wayback timeout in the report's `errors` | External services being slow — **not** a tool bug; all other modules still ran |
| Scan looks thin / target is large | Re-run with `-d` (deep mode: bigger wordlists, more ports & paths) |
| I stopped a scan with `Ctrl + C` | Partial results were saved — `nullveil <target> --resume` runs only the missing modules |
| Where are screenshots saved? | `nullveil_shots/<domain>/` (also embedded in the HTML report) |
| Where is scan history stored? | `~/.nullveil/history/` — the dashboard reads from here |
| `--pdf-from` a history file | Supported (v3.2.2+) — history entries are auto-unwrapped |

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
- [x] Burp Suite / Caido bridge (`--proxy`, `--har`) — full-scan proxy capture + HAR import into the API pool
- [x] **Scan History & Diff Tracking** — automatic "new since last scan" alerting (subdomains / ports / paths / APIs) with a drift score
- [x] **Authenticated / role-based admin API audit** — session injection, role-diff and backend/admin surface auditing (`-a auth`)
- [x] **AI Patch & Remediation Generator** (`-a patch`) — offline template/heuristic fixes (nginx, Cloudflare WAF, code-level)
- [x] **Read-Only PoC Verification Generator** (`-a poc`) — non-destructive `curl`/`dig`/`openssl` verification commands
- [x] **Multi-Channel Webhook Notifications** (`--webhook-slack` / `--webhook-telegram` / `--webhook-discord` / `--webhook-teams`)
- [x] **Executive C-Level Report Exporter** (`-a exec`, `--exec-report`, `--exec-pdf`) — HTML + optional PDF with compliance highlights
- [x] **Smart deduplication** (`--no-dedupe` to disable) + **strict per-module timeouts** (`--module-timeout`)
- [x] **JS Secret & Source-Map Miner** (`-a jsecret`) — source-map de-obfuscation + masked secret/sink detection
- [x] **Historical URL Miner** (`-a wayback`) — Wayback / CommonCrawl / OTX forgotten endpoints & old params
- [x] **Hidden Parameter Miner** (`-a param`) — control-baseline Arjun-style GET/POST discovery, near-zero false positives
- [x] **GraphQL Deep Audit** (`-a gql`) — introspection / suggestions / depth-limit checks (query-only)
- [x] **Cloud Storage Enumeration** (`-a cloud`) — S3 / Azure / GCP public-listing checks (HEAD/GET only)
- [x] **CVSS 4.0 / CWE Risk Scoring** (`-a cvss`) — industry-standard vectors + CWE + severity re-banding
- [x] **MITRE ATT&CK Mapping** (`-a attack`, `--attack-layer`) — enterprise technique coverage + Navigator layer export
- [x] **CVE Intelligence Enricher** (`-a cveintel`) — offline CVSS/CWE/EPSS/KEV/exploit prioritisation (P1–P4), plus **live NVD 2.0 + FIRST EPSS + CISA KEV** (`--cve-live`, disk-cached)
- [x] **Subdomain Takeover v3** (`-a takeover`) — 70+ provider fingerprints + full CNAME-chain proof
- [x] **Continuous Change Monitor** (`-a watch`, `--watch`, `--interval`) — baseline drift alerting & CI gate
- [x] **Advanced operator pack** (`--targets-file`/`--targets-list`, `--evade`, `--verify`) — mass scanning, WAF evasion, deep-accuracy false-positive reduction
- [x] **Read-Only Vulnerability Verification** (`-a vulnverify`) — benign-marker XSS/SQLi/traversal reachability proof (no payloads, no extraction)
- [x] **Automation layer** (`--plugin`, `--serve-api`) — external Python plugins + headless JSON scan API for CI/CD

Contributions welcome — open an issue or PR.

---

## 📜 License

NULLVEIL Recon is **dual-licensed**:

- **MIT** — free for personal, educational, and non-commercial use; see [LICENSE](LICENSE).
- **Commercial License** — required for commercial use (client work, resale, SaaS,
  white-label); see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) and
  [docs/PRICING.md](docs/PRICING.md).

You may use the software under **either** license, but not both at once. The
[EULA](EULA.md) governs use of the Software generally.

**Disclaimer:** provided "AS IS", without warranty. You are solely responsible for
ensuring every target you scan is authorized. See [SECURITY.md](SECURITY.md) and
[docs/AUTHORIZATION.md](docs/AUTHORIZATION.md).

---

## 🧪 Development, Testing & Deployment

**Test suite** (offline, no network required — uses an in-process mock target):

```bash
pip install pytest
python -m pytest tests/ -q          # 96 tests: registry, scoring, helpers, rules, advanced scanning, vuln-verify, plugins/API, Tier-2 intel, report, integration
```

**Lint** (bug classes only — undefined names, unused imports/vars, redefinitions):

```bash
pip install ruff
ruff check nullveil_recon.py tests/ --select F,E9
```

**Coverage** (line coverage is concentrated on pure logic — normalisers, scoring,
dedupe, registry, report schema — while the network modules are validated
behaviourally via crash/error sweeps and integration tests):

```bash
pip install coverage
coverage run --include="nullveil_recon.py" -m pytest tests/ -q && coverage report
```

**Install as a package** (console entry point `nullveil-recon`):

```bash
pip install .                       # from the repo root (pyproject.toml)
nullveil-recon example.com -a all
```

**Docker** (non-root, read-only tool):

```bash
docker build -t nullveil-recon .
docker run --rm nullveil-recon https://example.com -a all
```

**CI** runs compile + smoke + the full test suite (Python 3.9–3.13), a ruff
bug-class lint, a coverage report, and builds the Docker image — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

**Feature guides:**

- [docs/ADVANCED.md](docs/ADVANCED.md) — mass scanning (`--targets-file`/`--targets-list` + CIDR), WAF evasion (`--evade`), deep accuracy (`--verify`).
- [docs/VERIFICATION.md](docs/VERIFICATION.md) — module 50 read-only vulnerability verification: benign-marker XSS/SQLi/traversal reachability proof.
- [docs/AUTOMATION.md](docs/AUTOMATION.md) — external plugins (`--plugin`) and the headless JSON scan API (`--serve-api`).
- [docs/RULES.md](docs/RULES.md) — the plugin rule engine (`--rules`): extend the built-in CVE + misconfig knowledge with your own YAML/JSON.
- [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) — authenticated scanning: static session material, automated login, multi-role profiling.
- [docs/RESILIENCE.md](docs/RESILIENCE.md) — the transparent retry/backoff layer, external-service degradation, and per-module timeouts.

**Commercial use / consulting:** [docs/CONSULTING.md](docs/CONSULTING.md) ·
**pricing:** [docs/PRICING.md](docs/PRICING.md) ·
**support:** [`.github/FUNDING.yml`](.github/FUNDING.yml).

---

**Use responsibly. Authorized targets only.** 🥷
