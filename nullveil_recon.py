#!/usr/bin/env python3
"""
NULLVEIL Recon - Website & Domain Reconnaissance Tool
Owner/Author: NULLVEIL
Engine: DeepHat
Version: 1.0.0

Features:
  - DNS Records (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV)
  - Subdomain Enumeration (wordlist + SSL SAN)
  - Port Scanning (Top 100 TCP ports, async)
  - HTTP Analysis (headers, security headers, tech stack)
  - SSL/TLS Certificate Analysis
  - Content & Data Leakage Analysis (emails, IPs, phones, comments, secrets)
  - Robots.txt & Sitemap.xml parsing
  - Hidden Path / Admin Panel Discovery
  - User/Author Enumeration (REST API + pages)
  - JSON Report Export

Usage:
  python3 kundo_recon.py example.com
  python3 kundo_recon.py example.com --deep --timeout 15 --output report.json
"""

import asyncio
import ssl
import socket
import re
import json
import sys
import argparse
import base64
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, unquote
from collections import defaultdict, deque
import ipaddress
import os
import time
import math
import hashlib
import statistics

# --- Friendly error if dependencies are missing ---
try:
    import httpx
    import dns.asyncresolver
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box as rbox
    from rich.align import Align
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import print as rprint
except ImportError as e:
    missing = getattr(e, "name", None) or str(e).split("'")[-2] if "'" in str(e) else None
    missing = missing or "unknown module"
    sys.stderr.write(
        f"\n[!] Missing dependency: {missing}\n"
        f"    Fix:  pip install -r requirements.txt\n"
        f"    Or:   pip install 'httpx[http2]' dnspython rich\n\n"
    )
    sys.exit(1)

__version__ = "3.1.0"

# --- Global Configuration ---
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "staging", "test", "beta", "admin", "api",
    "app", "web", "shop", "store", "blog", "news", "cms", "wp", "wordpress",
    "phpmyadmin", "pma", "db", "database", "mysql", "postgres", "redis",
    "s3", "cdn", "static", "assets", "img", "images", "media", "files",
    "docs", "documentation", "wiki", "support", "help", "faq", "contact",
    "about", "team", "careers", "jobs", "hiring", "recruitment", "hr",
    "devops", "ci", "cd", "jenkins", "git", "github", "gitlab", "bitbucket",
    "jira", "confluence", "slack", "zoom", "meet", "teams", "discord",
    "status", "health", "ping", "monitor", "grafana", "kibana", "elasticsearch",
    "prometheus", "loki", "tempo", "jaeger", "zipkin", "sentry", "datadog",
    "newrelic", "splunk", "sumo", "loggly", "papertrail", "cloudwatch",
    "aws", "azure", "gcp", "cloud", "server", "node", "worker", "queue",
    "kafka", "rabbitmq", "active", "message", "bus", "event", "stream",
    "spark", "hadoop", "hive", "jupyter", "notebook", "lab",
    "sandbox", "playground", "demo", "trial", "free", "premium", "pro",
    "enterprise", "business", "corporate", "internal", "intranet", "vpn",
    "sso", "saml", "oauth", "auth", "login", "signin", "signup", "register",
    "account", "profile", "user", "users", "member", "members", "community",
    "forum", "discuss", "chat", "live", "broadcast", "stream", "video",
    "audio", "music", "podcast", "rss", "feed", "atom", "xml", "json",
    "m", "mobile", "img", "cpanel", "webmail", "cpanelwebmail", "autodiscover",
    "ns1", "ns2", "mx", "smtp", "pop", "imap", "remote", "owa", "exchange",
    "owa", "lyncdiscover", "msoid", "portal", "billing", "invoice", "pay",
    "checkout", "cart", "order", "orders", "erp", "crm", "hrms", "intranet2"
]

DEEP_SUBDOMAINS = [
    "api2", "app2", "backend", "frontend", "staging2", "preprod", "uat",
    "qa", "testing", "load", "perf", "canary", "edge", "origin", "proxy",
    "gw", "gateway", "bff", "auth2", "id", "idp", "sso2", "vault2",
    "grafana2", "kibana2", "elastic", "log", "logs", "metrics", "tracing",
    "ci2", "build", "runner", "registry", "docker", "harbor", "nexus",
    "artifactory", "sonar", "wiki2", "git2", "svn", "bastion", "jump",
    "vpn2", "mail2", "smtp2", "mx2", "relay", "filter", "spam",
    "shop2", "pay2", "payments", "gateway2", "cdn2", "media2", "files2",
    "upload", "downloads", "dl", "static2", "img2", "video", "stream2",
    "cdn3", "origincache", "waf", "bot", "analytics", "bi", "report",
    "reports", "data", "bigdata", "ml", "ai", "notebook2", "colab",
    "old", "new2", "legacy", "archive", "backup2", "db2", "dbadmin",
    "pgadmin", "phpmyadmin2", "mongo", "mongo-express", "redis2", "cache",
    "memcached", "rabbit", "mq", "zookeeper", "etcd", "consul2", "nomad2"
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/login", "/signin", "/wp-admin",
    "/wp-login.php", "/phpmyadmin", "/pma", "/mysql", "/db", "/database",
    "/console", "/dashboard", "/panel", "/manager", "/manage", "/control",
    "/backend", "/backoffice", "/staff", "/superuser", "/root", "/user",
    "/users", "/accounts", "/settings", "/config", "/configuration",
    "/env", ".env", "config.php", "wp-config.php", "settings.py", "settings.js",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/rest", "/v1", "/v2",
    "/swagger", "/swagger-ui.html", "/docs", "/documentation", "/openapi.json",
    "/sitemap.xml", "/robots.txt", "/.git", "/.git/config", "/.git/HEAD",
    "/.svn", "/.hg", "/.DS_Store", "/backup", "/old", "/new", "/tmp", "/temp",
    "/upload", "/uploads", "/files", "/images", "/media", "/assets", "/static",
    "/js", "/css", "/fonts", "/favicon.ico", "/humans.txt", "/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association", "/.well-known/jwks.json",
    "/.well-known/ct.log", "/.well-known/pki-validation", "/.well-known/step-ca.json",
    "/.well-known/sandbox", "/.well-known/ocsp", "/.well-known/acme-challenge",
    "/.well-known/change-password", "/.well-known/dnt-policy.txt",
    "/.well-known/observed-domain-names"
]

DEEP_ADMIN_PATHS = [
    "/server-status", "/server-info", "/phpinfo.php", "/info.php", "/test.php",
    "/debug", "/debugger", "/trace", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings", "/actuator/info", "/metrics",
    "/health", "/status", "/info", "/version", "/elmah.axd", "/trace.axd",
    "/admin/login", "/admin/dashboard", "/admin/config", "/administrator/index.php",
    "/wp-json", "/wp-json/wp/v2/users", "/xmlrpc.php", "/feed", "/comments/feed",
    "/cgi-bin/", "/cgi-bin/test.cgi", "/solr/", "/jmx-console/", "/manager/html",
    "/host-manager/html", "/invoker/JMXInvokerServlet", "/web-console/", "/adminer.php",
    "/backup.sql", "/dump.sql", "/db.sql", "/site.sql", "/database.sql",
    "/backup.tar.gz", "/backup.zip", "/site.zip", "/www.zip", "/source.zip",
    "/.env.backup", "/.env.old", "/.env.production", "/.env.development",
    "/.git/HEAD", "/.gitignore", "/.svn/entries", "/.hg/hgrc", "/CVS/Root",
    "/id_rsa", "/.ssh/id_rsa", "/.aws/credentials", "/wp-config.php.bak",
    "/config.yml", "/config.json", "/config.yaml", "/docker-compose.yml",
    "/Dockerfile", "/.dockerenv", "/package.json", "/composer.json",
    "/package-lock.json", "/yarn.lock", "/.bash_history", "/error.log",
    "/access.log", "/debug.log", "/app.log", "/logs/error.log",
    "/adminer", "/pgadmin", "/adminer-4.8.1.php", "/myadmin/",
    "/rest/v1", "/graphql/console", "/altair", "/graphiql",
    "/api/docs", "/api/swagger", "/api/openapi.json", "/api/graphql",
    "/redoc", "/swagger/index.html", "/v2/api-docs", "/v3/api-docs",
    "/_profiler", "/_wdt", "/telescope", "/horizon", "/nova",
    "/filament", "/adminer.php", "/storage/logs/laravel.log",
    "/.well-known/change-password", "/sitemap_index.xml", "/wp-sitemap.xml",
    "/llms.txt", "/ads.txt", "/app-ads.txt", "/browserlink",
    "/_next/static/", "/__webpack_hmr", "/sockjs-node", "/__debug__"
]

INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 500}

TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 593, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 3306, 3389,
    4899, 5060, 5061, 5432, 5631, 5666, 5900, 5984, 6000, 6379, 6667, 7001,
    7100, 7443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    9999, 10000, 11211, 15672, 19000, 27017, 3128, 50000
]

DEEP_EXTRA_PORTS = [
    81, 88, 300, 389, 444, 554, 873, 902, 1090, 1099, 1434, 1720, 2049,
    2375, 2376, 2480, 3000, 3001, 3128, 3333, 4000, 4040, 4190, 4443,
    4444, 5000, 5001, 5433, 5555, 5601, 5985, 5986, 6443, 6666, 7002,
    7474, 7687, 8001, 8082, 8085, 8090, 8161, 8500, 8501, 8834, 8880,
    9001, 9042, 9091, 9100, 9201, 9418, 9443, 9990, 10001, 10250, 10443,
    11211, 15672, 16379, 18080, 27017, 27018, 28017, 50000, 50070
]

TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Shopify": [r"cdn.shopify.com", r"Shopify.theme"],
    "Wix": [r"wixstatic.com", r"wix.com"],
    "Squarespace": [r"squarespace.com", r"squarespace-cdn"],
    "Drupal": [r"drupal-settings-json", r"core/misc/drupal.js"],
    "Joomla": [r"/media/jui/", r"option=com_"],
    "React": [r"react-dom", r"data-reactroot"],
    "Angular": [r"ng-version", r"angular\\.min\\.js"],
    "Vue": [r"vue\\.min\\.js", r"data-v-"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Nuxt.js": [r"_nuxt/", r"nuxt-link"],
    "Laravel": [r"XSRF-TOKEN", r"laravel_session"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Flask": [r"werkzeug", r"Flask-"],
    "Node.js": [r"node_modules", r"express"],
    "PHP": [r"\\.php\\?", r"PHPSESSID"],
    "Ruby": [r"rails", r"_rails_session"],
    "Java": [r"JSESSIONID", r"servlet"],
    ".NET": [r"ASP.NET_SessionId", r"__VIEWSTATE", r"aspx"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "IIS": [r"Microsoft-IIS"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "AWS": [r"amazonaws\\.com", r"aws"],
    "Azure": [r"azure", r"microsoft"],
    "GCP": [r"googleapis\\.com", r"gstatic\\.com"]
}

SECRET_PATTERNS = [
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Firebase Key", r"AAAA[A-Za-z0-9_\-]{7,}"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("Slack Webhook", r"https://hooks\\.slack\\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
    ("Stripe Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("PayPal Key", r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"),
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}"),
    ("Twilio Key", r"SK[0-9a-fA-F]{32}"),
    ("SendGrid Key", r"SG\\.[0-9A-Za-z_\\-]{22}\\.[0-9A-Za-z_\\-]{43}"),
    ("Heroku Key", r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{16,}['\"]"),
    ("Generic Secret", r"(?i)(secret|password|passwd|pwd|token)['\"]?\\s*[:=]\\s*['\"][^'\"\\s]{8,}['\"]"),
    ("JWT", r"eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+"),
    ("Private Key Block", r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("Basic Auth URL", r"https?://[^/\\s:@]+:[^/\\s:@]+@[^/\\s]+"),
]

EMAIL_RE = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
IPV4_RE = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
PHONE_RE = r'(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{3,4}\b'

console = Console()

# ---------------------------------------------------------- NULLVEIL Banner & helpers
BANNER_LETTERS = {
    'N': ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    'U': ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    'L': ["██╗     ", "██║     ", "██║     ", "██║     ", "██║     ", "╚═╝     "],
    'V': ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
    'E': ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    'I': ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
}
BANNER_COLORS = ["bold cyan", "bold bright_blue", "bold magenta", "bold bright_magenta", "bold red", "bold yellow", "bold green", "bold bright_cyan"]

ATTACK_MODULES = [
    ("dns", 1, "DNS Record Recon", "A/AAAA/CNAME/MX/NS/TXT/SOA/SRV/CAA records"),
    ("sub", 2, "Subdomain Enumeration", "Wordlist + SSL SAN brute resolve"),
    ("ports", 3, "Port Scanning", "Async TCP scan (top 60-140 ports)"),
    ("http", 4, "HTTP Analysis", "Headers, security headers, tech stack"),
    ("ssl", 5, "SSL Certificate", "Issuer, SAN, expiry, days left"),
    ("content", 6, "Content Leakage", "Emails, IPs, phones, comments, secrets"),
    ("robots", 7, "Robots & Sitemap", "robots.txt / sitemap.xml parsing"),
    ("paths", 8, "Path / Admin Discovery", "Hidden dirs, .env, .git, backups, API"),
    ("users", 9, "User Enumeration", "WP REST API, ?author=, oEmbed"),
    ("api", 10, "API & Full Site Intel", "API discovery, JS endpoints, swagger, forms, tech fingerprint"),
    ("waf", 11, "WAF / CDN Detection", "Cloudflare, Akamai, Sucuri, Imperva, AWS WAF fingerprint"),
    ("email", 12, "Email Security", "SPF, DKIM, DMARC, MTA-STS, BIMI records + policy audit"),
    ("audit", 13, "API Security Audit", "OWASP API Top 10: CORS, auth, verbose errors, rate limit, JWT, data exposure"),
    ("ext", 14, "External Intelligence", "crt.sh CT logs, Wayback history, dangling subdomain takeover check"),
    ("cve", 15, "CVE & Misconfig Scan", "Version fingerprint -> CVE match, exposed .git/.env/actuator/phpinfo"),
    ("crawl", 16, "Deep Crawler & Params", "Multi-page BFS crawl, parameter inventory, reflection detection"),
    ("tls", 17, "TLS Deep Analysis", "TLS version/cipher matrix, weak crypto, key size, OCSP, HSTS"),
    ("supply", 18, "Supply Chain / Third-Party Risk", "External scripts, SRI audit, vendor mapping (CDN/analytics/ads/SSO)"),
    ("crit", 19, "Asset Criticality", "Auto-score subdomains/ports/paths into CRITICAL/HIGH/MEDIUM/LOW tiers"),
    ("anom", 20, "Anomaly Detection (ML)", "Unsupervised: soft-404 clustering, latency/size z-score, k-means outliers"),
    ("intel", 21, "Threat Intel Feeds", "AlienVault OTX, OpenPhish, SSLBL, Spamhaus Zen DNSBL (+ optional AbuseIPDB key)"),
    ("breach", 22, "Breach Monitoring", "HaveIBeenPwned breach enumeration (HIBP_API_KEY), domain exposure, phishing check"),
    ("comp", 23, "Compliance Mapping", "PCI-DSS 4.0, ISO 27001:2022 Annex A, SOC 2 TSC — evidence-based mapping"),
    ("graph", 24, "Attack Path Graph", "Asset graph, attack-path search, exploit-chain hypotheses (report-only)"),
    ("correlate", 25, "Target Correlation", "Multi-target/tenant correlation: shared NS/MX/IP/CDN, --correlate list"),
    ("shot", 26, "Screenshot Capture", "Headless browser page snapshots (needs optional playwright)"),
    ("nuclei", 27, "Nuclei Template Scan", "ProjectDiscovery nuclei integration — 9000+ vuln templates (needs nuclei binary)"),
]

MAX_MODULE = len(ATTACK_MODULES)


def parse_attack_list(s: str):
    s = s.lower().strip()
    if s in ("all", "full", "*"):
        return list(range(1, MAX_MODULE + 1))
    items = [x.strip().lower() for x in s.split(',') if x.strip()]
    res = set()
    for it in items:
        if it.isdigit():
            m = int(it)
            if 1 <= m <= MAX_MODULE:
                res.add(m)
            continue
        for name, idx, *_ in ATTACK_MODULES:
            if it == name or (name == "sub" and it in ("subdomains", "subdomain")) or (name == "paths" and it in ("admin", "dirs")):
                res.add(idx)
    return sorted(res)


def attack_menu(target):
    """Interactive attack selection menu. Returns list of module indices."""
    console.print()
    t = Table(title="[bold magenta]◈ SELECT ATTACK MODULES ◈[/]", box=rbox.DOUBLE_EDGE,
              header_style="bold white on dark_magenta", show_header=True)
    t.add_column(" # ", justify="center", style="bold yellow", width=4)
    t.add_column("Module", style="bold cyan")
    t.add_column("Description", style="white")
    t.add_column("Covers", style="dim")
    for name, idx, title, desc in ATTACK_MODULES:
        t.add_row(str(idx), title, desc, f"[dim]{name}[/]")
    console.print(t)
    console.print("[dim]Format:[/] [white]numbers comma-separated[/] (e.g. [bold cyan]1,2,5[/])  "
                  "[dim]or[/] [bold cyan]names[/] (e.g. [bold cyan]dns,ssl[/])  "
                  "[dim]or[/] [bold green]all[/] [dim]for everything[/]")

    while True:
        try:
            choice = console.input("\n[bold yellow]❯ Attack list [/][dim](default: all):[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Cancelled — running ALL modules.[/]")
            return list(range(1, MAX_MODULE + 1))
        if not choice:
            return list(range(1, MAX_MODULE + 1))
        parsed = parse_attack_list(choice)
        if parsed:
            sel = ", ".join(str(i) for i in parsed)
            names = ", ".join(ATTACK_MODULES[i-1][2] for i in parsed)
            console.print(f"[bold green]✓ Selected:[/] [cyan]{sel}[/] — {names}")
            return parsed
        console.print(f"[bold red]✗ Invalid:[/] [white]{choice}[/] — try 1,2,5 / dns,ssl / all")


def print_banner():
    """Big NULLVEIL ASCII banner with per-letter rainbow colors."""
    art_lines = [""] * 6
    for idx, ch in enumerate("NULLVEIL"):
        glyph = BANNER_LETTERS[ch]
        color = BANNER_COLORS[idx % len(BANNER_COLORS)]
        for i in range(6):
            art_lines[i] += f"[{color}]{glyph[i]}[/]"

    subtitle = Text.from_markup("[bold white]R E C O N N A I S S A N C E   S U I T E[/]")
    subtitle.justify = "center"
    meta = Text.from_markup(
        "[dim]Owner:[/] [bold cyan]NULLVEIL[/]   "
        "[dim]Engine:[/] [bold yellow]DeepHat[/]   "
        f"[dim]Version:[/] [bold white]{__version__}[/]   "
        "[dim]Status:[/] [bold green]OPERATIONAL[/]"
    )
    meta.justify = "center"
    legal = Text.from_markup("[dim]Licensed use only — authorized targets only[/dim]")
    legal.justify = "center"

    body = Group(
        Align.center(Text.from_markup("\n".join(art_lines))),
        Align.center(subtitle),
        "",
        Align.center(meta),
        Align.center(legal),
    )
    console.print()
    console.print(Panel(body, border_style="bright_blue", box=rbox.DOUBLE, padding=(0, 2)))
    console.print()


def _section_header(title, icon, style="bright_cyan"):
    """Fancy centered section header."""
    return Panel(
        Align.center(Text.from_markup(f"[bold white]{icon} {title}[/]")),
        border_style=style, box=rbox.ROUNDED, padding=(0, 1),
    )


def _risk_meter(secrets, missing_headers, flagged_paths):
    """Simple 0-100 exposure score based on findings."""
    score = min(100, len(secrets) * 15 + missing_headers * 4 + len(flagged_paths) * 6)
    if score < 30:
        level, color, verdict = "LOW", "green", "SECURE"
    elif score < 60:
        level, color, verdict = "MEDIUM", "yellow", "CAUTION"
    else:
        level, color, verdict = "HIGH", "red", "AT RISK"
    filled = score // 5
    bar = f"[{color}]{'█' * filled}[/][dim]{'░' * (20 - filled)}[/]"
    return score, level, color, verdict, bar


class WebsiteRecon:
    def __init__(self, url, deep=False, timeout=10, concurrency=100, ports=None, wordlist=None):
        url = url.strip()
        self.url = url if url.startswith(('http://', 'https://')) else f'https://{url}'
        self.parsed = urlparse(self.url)
        # Keep non-standard port (e.g. site.com:8080) in netloc
        self.netloc = self.parsed.netloc
        self.domain = self.parsed.netloc.split(':')[0]
        self.base_url = f"{self.parsed.scheme}://{self.netloc}"
        self.deep = deep
        self.timeout = timeout
        self.concurrency = concurrency
        self.ports = ports or (TOP_PORTS + DEEP_EXTRA_PORTS if deep else TOP_PORTS)
        # Load custom subdomain wordlist if provided (-w wordlist.txt)
        self.custom_wordlist = []
        self.wordlist_error = None
        if wordlist:
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    self.custom_wordlist = sorted({
                        line.strip().lower() for line in f
                        if line.strip() and not line.startswith('#') and ' ' not in line.strip()
                    })
            except FileNotFoundError:
                self.wordlist_error = f"Wordlist not found: {wordlist} — using built-in list"
            except Exception as e:
                self.wordlist_error = f"Could not read wordlist: {e} — using built-in list"
        # If URL has an explicit non-default port, always include it
        try:
            if self.parsed.port and self.parsed.port not in self.ports:
                self.ports = list(self.ports) + [self.parsed.port]
        except ValueError:
            pass
        self.results = defaultdict(list)
        self.scalar_results = {}
        self.scan_duration = 0.0
        self.attack_set = list(range(1, MAX_MODULE + 1))  # all modules
        self.client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            verify=False,  # recon: expired/self-signed certs still interesting
            http2=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 NULLVEIL-Recon/1.0"}
        )
        self.sem = asyncio.Semaphore(concurrency)

    # ---------------------------------------------------------- run
    async def run(self):
        # ---------- resume support: hydrate from previous scan, run only missing modules ----------
        resume_note = ""
        entry = getattr(self, "resume_entry", None)
        if entry:
            raw = entry.get("_raw", {})
            for k, v in (raw.get("results") or {}).items():
                self.results[k] = v
            for k, v in (raw.get("scalar") or {}).items():
                self.scalar_results[k] = v
            done = set(entry.get("modules_run", []))
            missing = [i for i in self.attack_set
                       if ATTACK_MODULES[i - 1][0] not in done]
            skipped = len(self.attack_set) - len(missing)
            # keep the already-done selection so the final report shows the full picture
            self._resume_done = [i for i in self.attack_set
                                 if ATTACK_MODULES[i - 1][0] in done]
            self.attack_set = missing
            resume_note = (f"Resumed from scan [bold cyan]{entry.get('id')}[/] "
                           f"({entry.get('when', '')[:16]}) — {skipped} module(s) already done, "
                           f"{len(missing)} remaining.")
        print_banner()
        if resume_note:
            console.print(f"      {resume_note}")
        module_names = ", ".join(ATTACK_MODULES[i - 1][0] for i in self.attack_set) if self.attack_set else "none"
        console.print(f"      [dim]Target:[/] [bold magenta]{self.domain}[/]   "
                      f"[dim]Mode:[/] [bold {'red' if self.deep else 'green'}]"
                      f"{'DEEP' if self.deep else 'NORMAL'}[/]   "
                      f"[dim]Started:[/] [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")
        console.print(f"      [dim]Attacks:[/] [bold cyan]{module_names}[/]  "
                      f"[dim]({len(self.attack_set)}/{MAX_MODULE} modules)[/]\n")
        if self.wordlist_error:
            console.print(f"      [bold yellow]⚠ {self.wordlist_error}[/]\n")

        all_modules = [
            (":globe_with_meridians: DNS Records", self.dns_recon, 1),
            (":spider_web: Subdomain Enumeration", self.subdomain_recon, 2),
            (":unlock: Port Scanning", self.port_scan, 3),
            (":satellite_antenna: HTTP Analysis", self.http_recon, 4),
            (":closed_lock_with_key: SSL Certificate", self.ssl_recon, 5),
            (":mag: Content Analysis", self.content_analysis, 6),
            (":robot: Robots & Sitemap", self.robots_sitemap, 7),
            (":file_folder: Path Discovery", self.admin_discovery, 8),
            (":bust_in_silhouette: User Enumeration", self.user_extraction, 9),
            (":link: API & Full Site Intel", self.api_recon, 10),
            (":shield: WAF / CDN Detection", self.waf_detect, 11),
            (":envelope: Email Security Audit", self.email_security, 12),
            (":test_tube: API Security Audit", self.api_audit, 13),
            (":satellite: External Intelligence", self.external_intel, 14),
            (":warning: CVE & Misconfig Scan", self.cve_scan, 15),
            (":spider: Deep Crawler & Params", self.deep_crawler, 16),
            (":lock: TLS Deep Analysis", self.tls_audit, 17),
            (":package: Supply Chain Risk", self.supply_chain, 18),
            (":dart: Asset Criticality", self.criticality_classify, 19),
            (":chart_with_downwards_trend: Anomaly Detection (ML)", self.anomaly_detection, 20),
            (":safety_vest: Threat Intel Feeds", self.threat_intel, 21),
            (":card_index_dividers: Breach Monitoring", self.breach_monitor, 22),
            (":clipboard: Compliance Mapping", self.compliance_map, 23),
            (":spider_web: Attack Path Graph", self.attack_graph, 24),
            (":arrows_counterclockwise: Target Correlation", self.correlate_targets, 25),
            (":camera: Screenshot Capture", self.screenshot_capture, 26),
            (":test_tube: Nuclei Template Scan", self.nuclei_scan, 27),
        ]
        # Filter by attack set and create coroutines only for selected
        # Modules that READ other modules' results must run sequentially AFTER the
        # concurrent scan finishes (indices: 19 crit, 23 comp, 24 graph, 25 correlate).
        DEFERRED = {19, 23, 24, 25}
        modules = []
        deferred = []
        for name, fn, idx in all_modules:
            if idx in self.attack_set:
                (deferred if idx in DEFERRED else modules).append((name, fn(), idx))

        scan_start = datetime.now()
        progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=28, complete_style="green", finished_style="bold green"),
            TextColumn("{task.fields[status]}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )

        async def runner(name, coro, tid):
            try:
                result = await coro
                progress.update(tid, completed=1, status="[bold green]✓ done[/]")
                return result
            except Exception:
                progress.update(tid, completed=1, status="[bold red]✗ fail[/]")
                raise

        with progress:
            tids = [progress.add_task(name, total=1, status="[dim]scanning…[/]") for name, _, _ in modules]
            results = await asyncio.gather(
                *[runner(modules[i][0], modules[i][1], tids[i]) for i in range(len(modules))],
                return_exceptions=True,
            )

        for i, r in enumerate(results):
            if isinstance(r, Exception):
                self.results['errors'].append(f"{modules[i][0]} crashed: {r!r}")

        # Sequential second pass: analysis modules that depend on scan results
        if deferred:
            with Progress(
                TextColumn("{task.description}"), BarColumn(bar_width=28),
                TextColumn("{task.fields[status]}"), TimeElapsedColumn(),
                console=console, transient=True,
            ) as prog2:
                for name, coro, idx in deferred:
                    tid = prog2.add_task(name, total=1, status="[dim]analyzing…[/]")
                    try:
                        await coro
                        prog2.update(tid, completed=1, status="[bold green]✓ done[/]")
                    except Exception as e:
                        prog2.update(tid, completed=1, status="[bold red]✗ fail[/]")
                        self.results['errors'].append(f"{name} crashed: {e!r}")

        self.scan_duration = (datetime.now() - scan_start).total_seconds()

        await self.client.aclose()
        report = self.export_dict()
        hid = self._history_save(report)
        if hid and not getattr(self, "quiet", False):
            console.print(f"[dim]Scan saved to history:[/] [cyan]{hid}[/]  "
                          f"[dim](list: nullveil <target> --history)[/]")
        self.print_report()
        return report

    # ---------------------------------------------------------- DNS
    async def dns_recon(self):
        types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA']
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout

        async def lookup(rtype):
            try:
                answers = await resolver.resolve(self.domain, rtype)
                for rdata in answers:
                    self.results['dns'].append(f"{rtype}: {rdata.to_text()}")
            except Exception:
                pass

        await asyncio.gather(*[lookup(t) for t in types])

        # Classify A record IPs (public/private)
        for entry in list(self.results['dns']):
            if entry.startswith('A: '):
                ip = entry[3:].strip()
                try:
                    addr = ipaddress.ip_address(ip)
                    kind = 'Private' if addr.is_private else 'Public'
                    self.results['ip_info'].append(f"{ip} ({kind})")
                except ValueError:
                    pass

    # ---------------------------------------------------------- Subdomains
    async def subdomain_recon(self):
        wordlist = set(COMMON_SUBDOMAINS)
        if self.deep:
            wordlist.update(DEEP_SUBDOMAINS)
        if self.custom_wordlist:
            wordlist.update(self.custom_wordlist)

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout

        async def check_sub(sub):
            target = f"{sub}.{self.domain}"
            async with self.sem:
                try:
                    answers = await resolver.resolve(target, 'A')
                    for rdata in answers:
                        self.results['subdomains'].append(f"{target} -> {rdata.to_text()}")
                except Exception:
                    pass

        await asyncio.gather(*[check_sub(sub) for sub in sorted(wordlist)])

    async def resolve_san_subdomains(self):
        """After SSL recon fills SANs, resolve them too."""
        for san in list(self.scalar_results.get('ssl_san', [])):
            if san == self.domain or f"*.{self.domain}" == san:
                continue
            if not san.endswith(self.domain):
                continue
            try:
                answers = await dns.asyncresolver.resolve(san, 'A')
                for rdata in answers:
                    entry = f"{san} -> {rdata.to_text()} (SSL SAN)"
                    if entry not in self.results['subdomains']:
                        self.results['subdomains'].append(entry)
            except Exception:
                pass

    # ---------------------------------------------------------- Ports
    async def port_scan(self):
        async def check_port(port):
            async with self.sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.domain, port), timeout=2
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    self.results['ports'].append(port)
                except Exception:
                    pass

        await asyncio.gather(*[check_port(p) for p in self.ports])
        self.results['ports'].sort()

    # ---------------------------------------------------------- HTTP
    async def http_recon(self):
        # Try https, fall back to http
        for base in (self.base_url, f"http://{self.netloc}", f"https://{self.netloc}"):
            try:
                async with self.sem:
                    response = await self.client.get(base)
                self.scalar_results['final_url'] = str(response.url)
                self.scalar_results['http_status'] = response.status_code
                self.scalar_results['http_headers'] = dict(response.headers)

                # Tech stack from headers + body
                header_blob = " ".join(f"{k}: {v}" for k, v in response.headers.items())
                blob = header_blob + "\n" + response.text[:200_000]
                for tech, patterns in TECH_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, blob, re.IGNORECASE):
                            if tech not in self.results['tech_stack']:
                                self.results['tech_stack'].append(tech)
                            break

                sec_headers = [
                    'strict-transport-security', 'content-security-policy',
                    'x-frame-options', 'x-content-type-options', 'x-xss-protection',
                    'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy',
                    'cross-origin-resource-policy', 'content-encoding',
                ]
                for h in sec_headers:
                    if h in response.headers:
                        if h not in self.results['security_headers']:
                            self.results['security_headers'].append(h)
                    else:
                        if h not in self.results['missing_security_headers']:
                            self.results['missing_security_headers'].append(h)

                server = response.headers.get('server')
                if server:
                    self.scalar_results['server'] = server
                powered = response.headers.get('x-powered-by')
                if powered:
                    self.scalar_results['x_powered_by'] = powered

                if response.history:
                    chain = [f"{r.status_code} -> {r.headers.get('location', '?')}" for r in response.history]
                    chain.append(f"{response.status_code} -> {response.url}")
                    self.results['redirect_chain'] = chain

                return
            except Exception as e:
                self.scalar_results['http_error'] = str(e)
        self.results['errors'].append(f"HTTP Error: {self.scalar_results.get('http_error', 'unknown')}")

    # ---------------------------------------------------------- SSL
    async def ssl_recon(self):
        try:
            context = ssl.create_default_context()
            loop = asyncio.get_running_loop()
            cert = await loop.run_in_executor(None, self._grab_cert, context)
            if not cert:
                return
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            subject = dict(x[0] for x in cert.get('subject', ()))
            self.scalar_results['ssl_issuer'] = issuer.get('organizationName') or issuer.get('commonName') or str(issuer)
            self.scalar_results['ssl_subject'] = subject.get('commonName') or str(subject)
            self.scalar_results['ssl_not_after'] = cert.get('notAfter')
            self.scalar_results['ssl_not_before'] = cert.get('notBefore')
            sans = [v for t, v in cert.get('subjectAltName', ()) if t == 'DNS']
            self.scalar_results['ssl_san'] = sans
            self.scalar_results['ssl_serial'] = cert.get('serialNumber')

            # Expiry check
            not_after = cert.get('notAfter')
            if not_after:
                expire = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire - datetime.now()).days
                self.scalar_results['ssl_days_left'] = days_left

            for san in sans:
                entry = f"SSL SAN: {san}"
                if entry not in self.results['subdomains']:
                    self.results['subdomains'].append(entry)
            await self.resolve_san_subdomains()
        except Exception as e:
            self.results['errors'].append(f"SSL Error: {e}")

    def _grab_cert(self, context):
        with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.domain) as s:
                return s.getpeercert()

    # ---------------------------------------------------------- Content
    async def content_analysis(self):
        try:
            async with self.sem:
                response = await self.client.get(self.scalar_results.get('final_url', self.url))
            html = response.text[:500_000]

            # Emails
            emails = set(e for e in re.findall(EMAIL_RE, html) if not e.lower().endswith(('.png', '.jpg', '.gif', '.svg', '.webp')))
            self.results['emails'] = sorted(emails)

            # IPs (exclude obvious versions / placeholders)
            ips = set()
            for ip in re.findall(IPV4_RE, html):
                try:
                    addr = ipaddress.ip_address(ip)
                    if not addr.is_loopback and not addr.is_multicast and ip != '0.0.0.0':
                        ips.add(ip)
                except ValueError:
                    pass
            self.results['ips'] = sorted(ips)

            # Phone-like numbers (heuristic)
            phones = set()
            for p in re.findall(PHONE_RE, html):
                digits = re.sub(r'\D', '', p)
                if 7 <= len(digits) <= 15:
                    phones.add(p.strip())
            self.results['phones'] = sorted(phones)[:50]

            # HTML comments (leaked info / TODO / FIXME)
            comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
            interesting = [c.strip()[:200] for c in comments
                           if re.search(r'(?i)(todo|fixme|hack|bug|password|secret|key|token|admin|debug|internal|temp)', c)]
            self.results['comments'] = interesting[:50]

            # Meta tags
            metas = re.findall(r'<meta[^>]+>', html, re.IGNORECASE)
            self.results['meta_tags'] = metas[:30]

            # Social / profile links
            socials = set(re.findall(r'https?://(?:www\.)?(?:facebook|twitter|x|instagram|linkedin|youtube|github|gitlab|tiktok|telegram|discord)\.com/[^"\'\s<>]+', html, re.IGNORECASE))
            self.results['social_links'] = sorted(socials)[:50]

            # Secrets / API keys
            for name, pattern in SECRET_PATTERNS:
                try:
                    matches = set(re.findall(pattern, html))
                except re.error:
                    continue
                for m in list(matches)[:3]:
                    snippet = m if isinstance(m, str) else str(m)
                    self.results['secrets'].append(f"{name}: {snippet[:120]}")

            # Exposed JS source maps / bundles (deep)
            if self.deep:
                js_files = set(re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE))
                for js in list(js_files)[:20]:
                    full = urljoin(str(response.url), js)
                    self.results['js_files'].append(full)
                maps = set(re.findall(r'sourceMappingURL=([^*\s]+)', html))
                for m in maps:
                    self.results['js_files'].append(f"sourceMappingURL: {m}")
        except Exception as e:
            self.results['errors'].append(f"Content Analysis Error: {e}")

    # ---------------------------------------------------------- Robots/Sitemap
    async def robots_sitemap(self):
        for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/security.txt", "/.well-known/security.txt"):
            try:
                async with self.sem:
                    r = await self.client.get(urljoin(self.base_url + "/", path.lstrip('/')))
                if r.status_code != 200:
                    continue
                body = r.text[:100_000]
                if path.endswith('.xml'):
                    urls = re.findall(r'<loc>(.*?)</loc>', body)
                    self.results['sitemap_urls'].extend(urls[:100])
                else:
                    lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith('#')]
                    if lines:
                        self.results['robots'].append(f"--- {path} ---")
                        self.results['robots'].extend(lines[:80])
                        # Disallowed paths are juicy for discovery
                        for l in lines:
                            if l.lower().startswith('disallow:'):
                                p = l.split(':', 1)[1].strip()
                                if p and p != '/' and p not in ADMIN_PATHS:
                                    ADMIN_PATHS.append(p)
            except Exception:
                pass

    # ---------------------------------------------------------- Admin Discovery
    async def admin_discovery(self):
        paths = list(ADMIN_PATHS)
        if self.deep:
            paths += DEEP_ADMIN_PATHS

        async def probe(path):
            target = urljoin(self.base_url + "/", path.lstrip('/'))
            async with self.sem:
                try:
                    r = await self.client.get(target)
                except Exception:
                    return
                if r.status_code in INTERESTING_STATUS:
                    ctype = r.headers.get('content-type', '')
                    length = r.headers.get('content-length', str(len(r.content)))
                    flagged = r.status_code in (401, 403, 500) or path.lower().endswith(('.env', '.git/config', '.git/HEAD', '.sql', '.bak', '.zip', '.log', 'id_rsa', '.aws/credentials', 'wp-config.php.bak'))
                    self.results['paths'].append({
                        'path': path,
                        'status': r.status_code,
                        'type': ctype.split(';')[0],
                        'size': length,
                        'flagged': flagged,
                    })

        await asyncio.gather(*[probe(p) for p in paths])

    # ---------------------------------------------------------- User Extraction
    async def user_extraction(self):
        endpoints = [
            "/wp-json/wp/v2/users?per_page=100",
            "/?author=1", "/?author=2", "/?author=3",
            "/wp-json/oembed/1.0/users",
            "/api/users", "/api/v1/users", "/users.json",
            "/feed/author/admin", "/author/admin",
        ]
        if self.deep:
            endpoints += [f"/?author={i}" for i in range(4, 16)]

        seen_users = set()

        async def probe(ep):
            url = urljoin(self.base_url + "/", ep.lstrip('/'))
            async with self.sem:
                try:
                    r = await self.client.get(url)
                except Exception:
                    return
                if r.status_code != 200:
                    return
                ctype = r.headers.get('content-type', '')
                # REST JSON
                if 'json' in ctype:
                    try:
                        data = r.json()
                        items = data if isinstance(data, list) else data.get('users', [])
                        for u in items:
                            if isinstance(u, dict):
                                name = u.get('name') or u.get('username') or ''
                                slug = u.get('slug') or u.get('username') or ''
                                if name or slug:
                                    seen_users.add(f"{name} (@{slug})" if slug else name)
                    except Exception:
                        pass
                # Author redirect: Location header or canonical
                if r.headers.get('location'):
                    m = re.search(r'/author/([^/?#]+)', r.headers['location'])
                    if m:
                        seen_users.add(f"@{m.group(1)} (via redirect)")
                m = re.search(r'/author/([^/?\'"]+)', r.text[:200000])
                if m and 'author' in ep:
                    seen_users.add(f"@{m.group(1)} (via page)")
                # oEmbed
                if 'users' in ep and 'oembed' in ep and 'json' in ctype:
                    try:
                        data = r.json()
                        author = data.get('author_name')
                        if author:
                            seen_users.add(author)
                    except Exception:
                        pass

        await asyncio.gather(*[probe(ep) for ep in endpoints])
        self.results['users'] = sorted(seen_users)

    # ---------------------------------------------------------- API & Full Site Intel
    async def api_recon(self):
        """Full site intelligence + API endpoint discovery.

        - Homepage crawl (forms, meta, JS, links)
        - JS bundle analysis -> hidden API endpoints
        - Probe well-known API doc paths (swagger/openapi/graphql/grpc-web)
        - Cookie & header fingerprinting (tech + frameworks)
        """
        discovered_apis = set()
        forms = []
        meta_info = {}
        js_urls = set()
        homepage_links = set()

        # ---------- 1) Fetch homepage ----------
        try:
            async with self.sem:
                resp = await self.client.get(self.scalar_results.get('final_url', self.base_url + "/"))
            html = resp.text[:800_000]
        except Exception as e:
            self.results['errors'].append(f"API Recon: homepage fetch failed: {e}")
            html = ""

        # ---------- 2) Forms ----------
        for m in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S):
            action, inner = m.group(1), m.group(2)
            method_m = re.search(r'<form[^>]*method=["\']([^"\']*)["\']', m.group(0), re.I)
            method = (method_m.group(1) if method_m else "GET").upper()
            inputs = re.findall(r'<(?:input|select|textarea)[^>]*name=["\']([^"\']+)["\']', inner, re.I)
            sensitive = [n for n in inputs if re.search(r'(?i)pass|pwd|secret|token|otp|credit|card', n)]
            forms.append({
                "action": action or "(same page)",
                "method": method,
                "fields": inputs[:20],
                "sensitive_fields": sensitive,
            })

        # ---------- 3) Meta / generator / JSON-LD ----------
        gen = re.search(r'<meta[^>]*\bname=["\']?generator["\']?[^>]*\bcontent=["\']?([^"\'>]+)', html, re.I)
        if gen:
            meta_info['generator'] = gen.group(1).strip()
        ttl = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
        if ttl:
            meta_info['title'] = ttl.group(1).strip()[:200]
        meta_re = re.compile(
            r'<meta[^>]*\b(?:property|name)=["\']?(og:[\w:]+|description|keywords|author|application-name)["\']?'
            r'[^>]*\bcontent=["\']?([^"\'>]{1,300})', re.I)
        for m in meta_re.finditer(html):
            meta_info.setdefault(m.group(1), m.group(2).strip())
        for m in re.finditer(r'<link[^>]*\brel=["\']?(?:canonical|alternate|EditURI)["\']?[^>]*\bhref=["\']?([^"\'>]+)', html, re.I):
            meta_info.setdefault('links', []).append(m.group(1).strip())
        for m in re.finditer(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', html, re.I | re.S):
            try:
                j = json.loads(m.group(1).strip())
                items = j if isinstance(j, list) else [j]
                for it in items:
                    if isinstance(it, dict):
                        t = it.get("@type", "?")
                        nm = it.get("name") or it.get("headline") or ""
                        if nm:
                            self.results['jsonld'].append(f"{t}: {nm}")
            except Exception:
                pass

        # ---------- 4) Collect JS + internal links ----------
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            js_urls.add(urljoin(str(resp.url) if html else self.base_url + "/", m.group(1)))
        for m in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.I):
            u = urljoin(self.base_url + "/", m.group(1))
            if u.startswith(self.base_url) and not re.search(r'\.(png|jpg|jpeg|gif|svg|css|woff2?|ico)$', u, re.I):
                homepage_links.add(u)
        # API endpoints directly visible in HTML (fetch/axios/XHR strings)
        for m in re.finditer(r'["\'](/(?:api|rest|graphql|v\d|wp-json)[\w\-/{}.?=&%]*)["\']', html, re.I):
            discovered_apis.add(m.group(1))
        for m in re.finditer(r'https?://api[\w.\-]*[^\s"\'<>`]+', html, re.I):
            discovered_apis.add(m.group(0))

        # ---------- 5) JS bundle analysis ----------
        spec_urls = set()   # swagger/openapi spec URLs (may be absolute or relative)
        js_limit = 12 if self.deep else 6

        async def analyze_js(url):
            try:
                async with self.sem:
                    r = await self.client.get(url)
                if r.status_code != 200:
                    return
                body = r.text[:1_000_000]
                # REST-ish paths
                for m in re.finditer(r'["\'`](/(?:api|rest|graphql|auth|oauth|v\d+)[\w\-/{}.?=&%$]*)["\'`]', body):
                    discovered_apis.add(m.group(1))
                # absolute API urls
                for m in re.finditer(r'["\'`](https?://(?:api|backend|service|gateway)[\w.\-]*[^\s"\'<>`]{4,120})["\'`]', body, re.I):
                    discovered_apis.add(m.group(1))
                # swagger / openapi spec references (any host, any path)
                for m in re.finditer(r'["\'`]([^"\'`\s]*(?:swagger|openapi|api-docs)[^"\'`\s]*\.json[^"\'`\s]*)["\'`]', body, re.I):
                    spec_urls.add(m.group(1))
                # fetch/axios/post wrappers
                for m in re.finditer(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post))\(\s*["\'`]([^"\'`]{3,200})["\'`]', body):
                    v = m.group(1)
                    if v.startswith('/') or '://' in v:
                        discovered_apis.add(v)
                # source map reference
                sm = re.search(r'sourceMappingURL=(\S+)', body)
                if sm:
                    self.results['js_files'].append(f"sourceMap: {url} -> {sm.group(1)}")
            except Exception:
                pass

        await asyncio.gather(*[analyze_js(u) for u in sorted(js_urls)[:js_limit]])

        # ---------- 6) Probe API doc / well-known endpoints ----------
        doc_paths = [
            "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/swagger/v1/swagger.json", "/swagger/index.html", "/api/swagger", "/api/docs",
            "/api/explorer", "/graphql", "/graphiql", "/playground", "/altair",
            "/graphql/console", "/gql", "/api/explorer",
            "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
            "/api", "/api/", "/api/v1", "/api/v2", "/api/health", "/api/status",
            "/api/version", "/api/config", "/api/user", "/api/users", "/api/auth",
            "/rest", "/soap", "/wsdl", "/api/wsdl", "/rpc",
            "/feed", "/json", "/api.json", "/endpoints",
            "/api/v3/openapi.json", "/api/openapi.json", "/api/swagger.json",
            "/swagger-initializer.js", "/swagger-config", "/v3/api-docs/swagger-config",
        ]
        if self.deep:
            doc_paths += [
                "/api/v3", "/api/internal", "/api/public", "/api/graphql",
                "/wp-json/", "/wp-json/wp/v2/", "/jsonapi",
                "/_next/data", "/api/openapi", "/redoc", "/docs/api",
                "/api/v31/openapi.json", "/api/v2/swagger.json",
            ]

        api_docs = []
        _parsed_specs = set()

        def _parse_spec(text, source_url):
            """Parse an OpenAPI/Swagger document into api_docs entry."""
            try:
                doc = json.loads(text)
            except Exception:
                return
            if not isinstance(doc, dict):
                return
            paths = doc.get('paths')
            if not isinstance(paths, dict) or not paths:
                # swagger 2.0 sometimes nests differently; bail out
                return
            info = doc.get('info', {}) if isinstance(doc.get('info'), dict) else {}
            servers = doc.get('servers')
            srv = ''
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                srv = servers[0].get('url', '')
            elif isinstance(doc.get('host'), str):
                scheme = 'https' if doc.get('schemes') and 'https' in doc.get('schemes') else 'http'
                srv = f"{scheme}://{doc.get('host')}{doc.get('basePath', '')}"
            api_docs.append({
                "source": source_url,
                "title": info.get('title') or 'API',
                "version": str(info.get('version') or '?'),
                "server": srv,
                "endpoints": sorted(paths.keys()),
                "methods": sorted({m.upper() for p in paths.values() if isinstance(p, dict) for m in p.keys()
                                   if m.upper() in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')}),
            })
            for ep in paths.keys():
                if isinstance(ep, str):
                    discovered_apis.add(ep if ep.startswith('/') else '/' + ep)

        async def probe_api(path):
            url = urljoin(self.base_url + "/", path.lstrip('/'))
            try:
                async with self.sem:
                    r = await self.client.get(url, headers={"Accept": "application/json, */*"})
            except Exception:
                return
            if r.status_code not in (200, 201, 401, 403, 405, 500):
                return
            ctype = r.headers.get('content-type', '')
            is_json = 'json' in ctype
            snippet = ""
            if is_json:
                snippet = re.sub(r'\s+', ' ', r.text[:400])

            # Parse swagger/openapi documents
            if is_json and re.search(r'(?i)swagger|openapi|paths', r.text[:3000]):
                _parse_spec(r.text, path)

            interesting = r.status_code in (200, 201) or (r.status_code in (401, 403) and 'json' in ctype)
            if interesting:
                self.results['api_endpoints'].append({
                    'path': path,
                    'status': r.status_code,
                    'type': ctype.split(';')[0],
                    'size': len(r.content),
                    'auth_required': r.status_code in (401, 403),
                    'snippet': snippet[:160] if is_json else "",
                })

        await asyncio.gather(*[probe_api(p) for p in doc_paths])

        # ---------- 6b) Fetch spec URLs discovered inside JS/config ----------
        async def fetch_spec(raw_url):
            full = urljoin(self.base_url + "/", raw_url)
            if full in _parsed_specs:
                return
            _parsed_specs.add(full)
            try:
                async with self.sem:
                    r = await self.client.get(full, headers={"Accept": "application/json, */*"})
                if r.status_code != 200 or 'json' not in r.headers.get('content-type', ''):
                    return
                before = len(api_docs)
                _parse_spec(r.text, full)
                if len(api_docs) > before:
                    discovered_apis.add(full)
            except Exception:
                pass

        await asyncio.gather(*[fetch_spec(u) for u in sorted(spec_urls)[:10]])

        # ---------- 7) Tech/framework fingerprint (deep) ----------
        headers_blob = " ".join(f"{k}:{v}" for k, v in self.scalar_results.get('http_headers', {}).items())
        cookies_raw = self.scalar_results.get('http_headers', {}).get('set-cookie', '')
        fp = []
        checks = [
            ("Next.js", r'__NEXT_DATA__|_next/static'),
            ("Nuxt.js", r'_nuxt/'),
            ("Vue", r'__vue__|data-v-[a-f0-9]{8}'),
            ("React", r'data-reactroot|react-dom'),
            ("Angular", r'ng-version|_ngcontent'),
            ("jQuery", r'jquery[.-]\d+\.\d+'),
            ("Bootstrap", r'bootstrap[.-]\d+'),
            ("Tailwind", r'tailwind|tw-'),
            ("WordPress", r'wp-content|wp-includes|wordpress'),
            ("WooCommerce", r'woocommerce|wc-'),
            ("Drupal", r'drupal-settings-json'),
            ("Joomla", r'/media/jui/|option=com_'),
            ("Laravel", r'laravel_session|XSRF-TOKEN'),
            ("Django", r'csrftoken|csrfmiddlewaretoken'),
            ("Flask", r'session=.*\.'),
            ("Express/Node", r'express|X-Powered-By.*Express'),
            ("Spring/Java", r'JSESSIONID|tomcat|spring'),
            ("PHP", r'PHPSESSID'),
            ("ASP.NET", r'ASP.NET_SessionId|__VIEWSTATE|aspx'),
            ("Cloudflare", r'cf-ray|__cfduid|cloudflare'),
            ("Akamai", r'akamai|akamai_'),
            ("Fastly", r'fastly|x-served-by'),
            ("Vercel", r'vercel|__next'),
            ("Netlify", r'netlify|nf_'),
            ("Firebase", r'firebaseio|firebasestorage'),
            ("Supabase", r'supabase'),
            ("Stripe", r'stripe|__stripe'),
            ("reCAPTCHA", r'recaptcha|grecaptcha'),
            ("hCaptcha", r'hcaptcha'),
            ("CloudFront", r'cloudfront|x-amz-cf-'),
            ("Google Analytics", r'google-analytics|gtag|ga\('),
            ("Google Tag Manager", r'googletagmanager'),
            ("Hotjar", r'hotjar'),
            ("Sentry", r'sentry|browser.js.*sentry'),
            ("Intercom", r'intercom'),
            ("Zendesk", r'zendesk'),
            ("Segment", r'segment\.com|analytics\.load'),
        ]
        blob = html[:300_000] + " " + headers_blob + " " + cookies_raw
        for name, pat in checks:
            if re.search(pat, blob, re.I):
                fp.append(name)
        for x in sorted(set(fp)):
            if x not in self.results['tech_stack']:
                self.results['tech_stack'].append(x)

        # Cookie analysis
        for c in re.findall(r'(?:^|[,\s])([\w_]+)=[^;,\s]+', cookies_raw):
            flag = ""
            if re.search(r'(?i)session|sess|auth|token|jwt', c):
                flag = " [yellow](auth)[/]"
            if c.lower() in ('__cf_bm', 'cf_clearance', '__cfduid'):
                continue
            self.results['cookies'].append(f"{c}{flag}")

        # ---------- 8) Store results ----------
        clean_apis = []
        for a in sorted(discovered_apis):
            if len(a) > 200 or a in ('/api', '/api/'):
                continue
            clean_apis.append(a)
        self.results['api_endpoints_found'] = clean_apis[:200] if not self.deep else clean_apis[:600]
        self.results['api_docs'] = api_docs
        self.results['forms'] = forms
        self.results['meta'] = meta_info
        self.results['site_links'] = sorted(homepage_links)[:150]
        self.results['js_files'] = sorted(set(self.results['js_files']))

    # ---------------------------------------------------------- WAF / CDN Detection
    # Signature database: (name, header regex, cookie regex, body regex, evidence label)
    WAF_SIGNATURES = [
        ("Cloudflare",  r'cf-ray|cf-cache-status|__cf_bm|cloudflare', r'__cf_bm|cf_clearance|__cflb', r'Attention Required! \|\| Cloudflare|Cloudflare Ray ID|cdn-cgi/challenge', "cf-ray header / challenge page"),
        ("Akamai",      r'akamai|x-akamai|akamaighost', r'akamai_|\^abp', r'Access Denied.*Reference #[\da-f]+|akamai reference', "X-Akamai headers / Reference # page"),
        ("AWS WAF",     r'x-amzn-requestid|x-amzn-waf', r'', r'AWS WAF|This request could not be denied by AWS WAF', "X-Amzn-Waf header"),
        ("Sucuri",      r'x-sucuri|x-cdn-server', r'sucuri_cloudproxy', r'Access Denied - Sucuri Website Firewall|sucuri.net', "X-Sucuri header / block page"),
        ("Imperva (Incapsula)", r'x-iinfo|x-incap|incap_ses|visid_incap', r'incap_ses_|visid_incap_', r'<h1>Incapsula incident|Request unsuccessful. Incapsula', "X-Iinfo header / Incapsula page"),
        ("Wordfence",   r'', r'', r'Wordfence|This response was generated by Wordfence', "Wordfence block page"),
        ("F5 BIG-IP / ASM", r'bigipserver|ts[a-z]{3}_id|x-wa-info', r'BIGipServer|TS[a-f0-9]+', r'The requested URL was rejected|Support ID ?[:#]', "BIG-IP cookie / ASM reject page"),
        ("FortiWeb",    r'', r'', r'FortiWeb|Server Unavailable!', "FortiWeb block page"),
        ("Barracuda",   r'', r'', r'Barracuda|barracuda\.com', "Barracuda block page"),
        ("ModSecurity", r'', r'', r'This request was blocked by ModSecurity|ModSecurity', "ModSecurity block page"),
        ("F5 Distributed Cloud", r'x-dos|x-volos', r'', r'', "X-DoS header"),
        ("StackPath",   r'x-sp-url|stackpath', r'', r'', "StackPath edge header"),
        ("Fastly",      r'x-served-by|x-fastly|fastly-debug', r'fastly', r'', "Fastly CDN header"),
        ("Cloudfront",  r'x-amz-cf-id|x-amz-cf-pop|cloudfront', r'cloudfront-|aws-alb', r'', "CloudFront header"),
        ("Google Cloud / GFE", r'x-frame-options.*SAMEORIGIN.*gws|gws|gfe', r'', r'', "Google front-end"),
        ("Vercel",      r'x-vercel|vercel', r'', r'', "Vercel edge"),
        ("Netlify",     r'x-nf-request-id|netlify', r'__', r'', "Netlify edge"),
    ]

    async def waf_detect(self):
        """Fingerprint WAF/CDN/edge protection from headers, cookies and block pages."""
        evidence = []          # (name, evidence_string)
        detected = set()

        # --- 1) Passive: analyze homepage response ---
        try:
            async with self.sem:
                resp = await self.client.get(self.scalar_results.get('final_url', self.base_url + "/"))
            headers_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
            cookies_blob = resp.headers.get('set-cookie', '')
            body = resp.text[:200_000]
        except Exception as e:
            self.results['errors'].append(f"WAF Detect: fetch failed: {e}")
            headers_blob = cookies_blob = body = ""

        for name, hre, cre, bre, label in self.WAF_SIGNATURES:
            hits = []
            if hre and re.search(hre, headers_blob, re.I):
                hits.append(f"header:{label}")
            if cre and re.search(cre, cookies_blob, re.I):
                hits.append(f"cookie:{label}")
            if bre and re.search(bre, body, re.I):
                hits.append(f"body:{label}")
            if hits:
                detected.add(name)
                evidence.append((name, ", ".join(hits)))

        # --- 2) Active (gentle): request a benign blocked path and inspect the block page ---
        probe_paths = ["/nullveil-waf-probe-test-404", "/.env", "/%2e%2e/etc/passwd"]
        async def probe_block(path):
            try:
                async with self.sem:
                    r = await self.client.get(urljoin(self.base_url + "/", path.lstrip('/')))
            except Exception:
                return
            if r.status_code not in (403, 406, 429, 503, 999):
                return
            blob = r.text[:60_000] + " " + " ".join(f"{k}:{v}" for k, v in r.headers.items())
            for name, hre, cre, bre, label in self.WAF_SIGNATURES:
                if (bre and re.search(bre, blob, re.I)) or (hre and re.search(hre, blob, re.I)):
                    if name not in detected:
                        detected.add(name)
                        evidence.append((name, f"block-page:{label} (HTTP {r.status_code} on {path})"))

        if self.deep:
            await asyncio.gather(*[probe_block(p) for p in probe_paths])
        else:
            await probe_block(probe_paths[0])

        # --- 3) CDN-only detection (edge, not a security block) ---
        cdn_only = []
        for c in ("Cloudflare", "Fastly", "Cloudfront", "Akamai", "Vercel", "Netlify", "StackPath"):
            if c in detected:
                cdn_only.append(c)

        self.results['waf'] = sorted(detected)
        self.results['waf_evidence'] = [f"{n}: {ev}" for n, ev in evidence]
        self.results['cdn'] = cdn_only
        # Security-relevant WAFs (block pages / WAF, not mere CDN edge)
        security_wafs = [n for n in detected if n not in ("Fastly", "Cloudfront", "Vercel", "Netlify",
                                                           "StackPath", "Google Cloud / GFE")]
        self.results['waf_security'] = sorted(security_wafs)

    # ---------------------------------------------------------- Email Security
    @staticmethod
    async def _doh_txt(name):
        """DNS-over-HTTPS fallback (Cloudflare) — used when plain DNS/TCP fails."""
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
                r = await c.get("https://cloudflare-dns.com/dns-query",
                                params={"name": name, "type": "TXT"},
                                headers={"Accept": "application/dns-json"})
                if r.status_code == 200:
                    data = r.json()
                    out = []
                    for ans in data.get("Answer", []):
                        if ans.get("type") == 16:  # TXT
                            out.append(str(ans.get("data", "")).strip('"'))
                    return out
        except Exception:
            pass
        return []

    async def email_security(self):
        """SPF / DKIM / DMARC / MTA-STS / BIMI audit via DNS TXT records."""
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout
        findings = []          # (severity, message)

        async def txt_records(name):
            try:
                ans = await resolver.resolve(name, 'TXT')
                recs = []
                for rdata in ans:
                    # Multi-string TXT (>255 chars, e.g. long SPF) — join parts
                    if hasattr(rdata, 'strings') and rdata.strings:
                        recs.append(b"".join(rdata.strings).decode(errors='replace'))
                    else:
                        recs.append(rdata.to_text().strip('"'))
                if recs:
                    return recs
            except Exception:
                pass
            # Fallback: DoH (handles TCP/53-blocked networks)
            return await self._doh_txt(name)

        async def mx_records():
            try:
                ans = await resolver.resolve(self.domain, 'MX')
                return sorted(f"{rdata.exchange} (prio {rdata.preference})" for rdata in ans)
            except Exception:
                return []

        root_txt, dmarc_txt, mtasts_txt, bimi_txt, mx = await asyncio.gather(
            txt_records(self.domain),
            txt_records(f"_dmarc.{self.domain}"),
            txt_records(f"_mta-sts.{self.domain}"),
            txt_records(f"default._bimi.{self.domain}"),
            mx_records(),
        )

        # ---------- SPF ----------
        spf = [t for t in root_txt if t.lower().startswith('v=spf1')]
        spf_record = spf[0] if spf else None
        if spf_record:
            includes = re.findall(r'(?:include|redirect):([\w.\-]+)', spf_record)
            if re.search(r'(?:^|\s)\+all(?:\s|$)', spf_record):
                findings.append(("CRITICAL", "SPF uses '+all' — ANY server can send mail as this domain (open relay risk)"))
            elif re.search(r'(?:^|\s)~all(?:\s|$)', spf_record):
                findings.append(("MEDIUM", "SPF uses '~all' (softfail) — prefer '-all' (hardfail) for stricter policy"))
            elif not re.search(r'(?:^|\s)-(?:all)(?:\s|$)', spf_record):
                findings.append(("LOW", "SPF has no '-all' terminator — policy is ambiguous"))
            if len(includes) > 10:
                findings.append(("LOW", f"SPF has {len(includes)} includes — DNS lookup limit is 10, may break"))
        else:
            findings.append(("HIGH", "No SPF record — anyone can spoof this domain in the From header"))
        self.results['spf'] = spf_record or ""
        self.results['spf_includes'] = sorted(set(re.findall(r'(?:include|redirect):([\w.\-]+)', spf_record))) if spf_record else []

        # ---------- DKIM ----------
        # Try common selectors (only a sample — full enumeration needs wordlist)
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "s1", "s2",
                          "mail", "smtp", "dkim", "smtpapi", "everest", "hs", "cm", "scph"]
        if self.deep:
            dkim_selectors += ["selector3", "bk", "sig1", "mandrill", "sendgrid", "20230601", "s1024", "global"]
        dkim_found = {}

        async def try_dkim(sel):
            recs = await txt_records(f"{sel}._domainkey.{self.domain}")
            for r in recs:
                if 'p=' in r:
                    dkim_found[sel] = r
        await asyncio.gather(*[try_dkim(s) for s in dkim_selectors])
        self.results['dkim'] = {k: v for k, v in dkim_found.items()}
        if not dkim_found:
            findings.append(("MEDIUM", f"No DKIM found on {len(dkim_selectors)} common selectors "
                                       f"(not proof of absence — custom selector possible)"))

        # ---------- DMARC ----------
        dmarc_record = next((t for t in dmarc_txt if t.lower().startswith('v=dmarc1')), None)
        self.results['dmarc'] = dmarc_record or ""
        if dmarc_record:
            policy_m = re.search(r'(?:^|;)\s*p\s*=\s*(\w+)', dmarc_record)
            policy = policy_m.group(1).lower() if policy_m else "none"
            self.results['dmarc_policy'] = policy
            if policy == "none":
                findings.append(("MEDIUM", "DMARC policy is 'p=none' — monitoring only, spoofing not blocked"))
            elif policy == "quarantine":
                findings.append(("LOW", "DMARC policy 'p=quarantine' — consider 'p=reject' for full protection"))
            else:
                findings.append(("INFO", "DMARC policy 'p=reject' — strongest anti-spoofing policy"))
            if not re.search(r'rua\s*=', dmarc_record):
                findings.append(("LOW", "DMARC has no 'rua=' aggregate report address — you won't see abuse reports"))
            sp_m = re.search(r'(?:^|;)\s*sp\s*=\s*(\w+)', dmarc_record)
            if sp_m and sp_m.group(1).lower() == "none":
                findings.append(("MEDIUM", "DMARC subdomain policy 'sp=none' — subdomains are unprotected"))
        else:
            findings.append(("HIGH", "No DMARC record — domain can be spoofed for phishing"))

        # ---------- MTA-STS ----------
        mtasts_record = next((t for t in mtasts_txt if 'v=STSv1' in t), None)
        self.results['mta_sts'] = mtasts_record or ""
        if not mtasts_record:
            findings.append(("LOW", "No MTA-STS — SMTP TLS downgrade attacks possible"))

        # ---------- BIMI ----------
        bimi_record = next((t for t in bimi_txt if 'v=BIMI1' in t), None)
        self.results['bimi'] = bimi_record or ""

        # ---------- MX ----------
        self.results['mx'] = mx
        provider = ""
        mx_blob = " ".join(mx).lower()
        for name, pat in (("Google Workspace", r'google|gmail|_aspmx'),
                          ("Microsoft 365", r'microsoft|protection\.outlook|mail\.protection'),
                          ("Zoho", r'zoho'), ("Proton", r'protonmail|protonmail\.ch'),
                          ("Yandex", r'yandex'), ("Mimecast", r'mimecast'),
                          ("Proofpoint", r'proofpoint|pphosted'),
                          ("Fastmail", r'fastmail'), ("Titan", r'titan\.email'),
                          ("Mailgun", r'mailgun'), ("SendGrid", r'sendgrid')):
            if re.search(pat, mx_blob):
                provider = name
                break
        self.results['mail_provider'] = provider
        if not mx:
            findings.append(("INFO", "No MX records — domain may not receive email"))

        # ---------- Extra suspicious TXT (BIMI/other) ----------
        self.results['email_findings'] = sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x[0], 5))

    # ---------------------------------------------------------- API Security Audit
    # Sensitive JSON keys we flag (names only — values never printed)
    SENSITIVE_KEY_RE = re.compile(
        r'(?i)^(pass(word|wd|phrase)?|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|'
        r'auth|authorization|ssn|social[_-]?security|credit[_-]?card|card[_-]?num|cvv|'
        r'private[_-]?key|client[_-]?secret|session[_-]?id|otp|pin|balance|salary|'
        r'email|phone|dob|date[_-]?of[_-]?birth|address|answer|security[_-]?question)$')
    VERBOSE_ERROR_RE = re.compile(
        r'(?i)(traceback \(most recent call last\)|stack trace|exception in thread|'
        r'sql syntax.*error|mysql_fetch|ora-\d{5}|pdoexception|postgresql.*error|'
        r'microsoft\.oledb|system\.nullreferenceexception|undefined method|'
        r'\bexception thrown\b|at [\w.$]+\([\w.]+:\d+\)|line \d+ of [\w/.]+\.|'
        r'kingbase|syntax error at or near)')

    async def api_audit(self):
        """Defensive API security audit (OWASP API Security Top 10).

        Reports misconfigurations & risks — never exploits them:
        CORS reflection, verbose errors, missing auth, rate limiting,
        sensitive data exposure (key names only), HTTP methods, JWT config.
        """
        findings = []          # (severity, check, detail)
        endpoint_rows = []

        # ---------- gather endpoints to audit ----------
        candidates = []
        for ep in self.results.get('api_endpoints', []):
            if isinstance(ep, dict) and ep.get('path'):
                candidates.append(ep['path'])
        for p in self.results.get('api_endpoints_found', []):
            if isinstance(p, str) and p.startswith('/') and '{' not in p:
                candidates.append(p)
        for doc in self.results.get('api_docs', []):
            for ep in doc.get('endpoints', []):
                if isinstance(ep, str) and ep.startswith('/') and '{' not in ep:
                    candidates.append(ep)
        # de-dup, keep discovered first
        seen, ordered = set(), []
        for c in candidates:
            c = c.split('?')[0]
            if c not in seen and len(c) < 100:
                seen.add(c)
                ordered.append(c)
        # Fallback / supplement with common API paths
        default_audit = ["/api", "/api/v1", "/api/users", "/api/user", "/api/login",
                         "/api/auth", "/api/health", "/api/config", "/graphql", "/api/docs"]
        if not ordered:
            ordered = default_audit
        elif self.deep:
            ordered = ordered + [p for p in default_audit if p not in ordered]
        audit_targets = ordered[:20] if self.deep else ordered[:12]

        ORIGIN = "https://nullveil-audit.probe"

        # ---------- per-endpoint checks ----------
        async def audit_endpoint(path):
            url = urljoin(self.base_url + "/", path.lstrip('/'))
            row = {"path": path, "status": None, "auth": "-", "cors": "-", "methods": "",
                   "verbose_error": False, "sensitive_keys": []}
            # GET with foreign Origin (CORS reflection test)
            try:
                async with self.sem:
                    r = await self.client.get(url, headers={
                        "Accept": "application/json, */*",
                        "Origin": ORIGIN,
                        "X-Nullveil-Audit": "1",
                    })
            except Exception:
                endpoint_rows.append(row)
                return
            row['status'] = r.status_code

            # --- auth requirement ---
            if r.status_code in (401, 403):
                row['auth'] = "REQUIRED"
            elif r.status_code in (200, 201, 204):
                row['auth'] = "none"

            # --- CORS misconfig ---
            acao = r.headers.get('access-control-allow-origin', '')
            acac = r.headers.get('access-control-allow-credentials', '').lower()
            if acao:
                if acao == ORIGIN and acac == 'true':
                    row['cors'] = "REFLECTED+CRED"
                    findings.append(("CRITICAL", "CORS",
                                     f"{path}: origin reflected WITH credentials — any website can read this API with user cookies"))
                elif acao == ORIGIN:
                    row['cors'] = "REFLECTED"
                    findings.append(("HIGH", "CORS",
                                     f"{path}: foreign origin reflected in ACAO — cross-origin reads allowed"))
                elif acao == "*":
                    row['cors'] = "*"
                    if acac == 'true':
                        findings.append(("HIGH", "CORS", f"{path}: ACAO '*' with Allow-Credentials (browsers block it, but intent is unsafe)"))
                    else:
                        findings.append(("INFO", "CORS", f"{path}: ACAO '*' — public API (OK if intended)"))
                elif acac == 'true':
                    row['cors'] = "CRED"
                    findings.append(("MEDIUM", "CORS", f"{path}: Allow-Credentials true with origin {acao[:60]}"))

            # --- verbose error leak (only on error responses or leak patterns) ---
            body = r.text[:300_000] if 'json' in r.headers.get('content-type', '') or r.status_code >= 500 else ""
            m = self.VERBOSE_ERROR_RE.search(r.text[:300_000])
            if m:
                row['verbose_error'] = True
                findings.append(("MEDIUM", "Verbose Errors",
                                 f"{path}: stack/DB error leaked — '{m.group(0)[:50]}' (info disclosure)"))

            # --- sensitive data exposure (KEY NAMES ONLY, values never stored) ---
            if body:
                try:
                    data = r.json()
                except Exception:
                    data = None
                if isinstance(data, (dict, list)):
                    keys = []
                    def walk(o):
                        if isinstance(o, dict):
                            for k, v in o.items():
                                if isinstance(k, str) and self.SENSITIVE_KEY_RE.match(k.strip()):
                                    keys.append(k)
                                walk(v)
                        elif isinstance(o, list):
                            for v in o[:50]:
                                walk(v)
                    walk(data)
                    if keys:
                        uniq = sorted(set(keys))
                        row['sensitive_keys'] = uniq[:12]
                        if any(re.search(r'(?i)pass|secret|token|key|cvv|card|ssn', k) for k in uniq):
                            findings.append(("HIGH", "Data Exposure",
                                             f"{path}: sensitive field(s) in unauthenticated response: {', '.join(uniq[:6])} (values not collected)"))
                        else:
                            findings.append(("MEDIUM", "Data Exposure",
                                             f"{path}: PII field(s) exposed: {', '.join(uniq[:6])}"))

            # --- allowed methods (OPTIONS preflight) ---
            try:
                async with self.sem:
                    o = await self.client.request("OPTIONS", url, headers={
                        "Origin": ORIGIN,
                        "Access-Control-Request-Method": "GET, POST, PUT, DELETE",
                    })
                allow = o.headers.get('allow', '')
                if allow:
                    row['methods'] = allow
                    risky = [mth.strip().upper() for mth in allow.split(',')
                             if mth.strip().upper() in ('PUT', 'DELETE', 'PATCH', 'TRACE')]
                    if risky:
                        findings.append(("LOW", "HTTP Methods",
                                         f"{path}: state-changing methods allowed: {', '.join(risky)} — verify they need auth"))
                    if 'TRACE' in allow.upper():
                        findings.append(("MEDIUM", "HTTP Methods", f"{path}: TRACE enabled — XST risk"))
            except Exception:
                pass

            endpoint_rows.append(row)

        await asyncio.gather(*[audit_endpoint(p) for p in audit_targets])

        # ---------- missing-auth check on JSON endpoints ----------
        for row in endpoint_rows:
            if (row['status'] in (200, 201) and row['auth'] == "none"
                    and re.search(r'(?i)/(users?|accounts?|orders?|admin|config|internal|search|list)', row['path'])):
                findings.append(("HIGH", "Broken Auth",
                                 f"{row['path']}: returned HTTP {row['status']} WITHOUT authentication on a data-like endpoint"))

        # ---------- rate limiting test (gentle: 10 rapid requests) ----------
        rate_result = {"tested": False, "limited": False, "detail": ""}
        rl_target = next((r for r in endpoint_rows if r['auth'] == "none" and r['status'] in (200, 401, 403, 404)), None)
        probe_path = (rl_target['path'] if rl_target else "/") + "?nullveil_ratetest=1"
        probe_url = urljoin(self.base_url + "/", probe_path.lstrip('/'))
        try:
            async def one():
                try:
                    async with self.sem:
                        resp = await self.client.get(probe_url, headers={"Accept": "application/json"})
                    return resp.status_code, dict(resp.headers)
                except Exception:
                    return None, {}
            codes, hdrs_list = [], []
            for _ in range(10):
                c, h = await one()
                codes.append(c)
                hdrs_list.append(h)
            rate_result['tested'] = True
            limited = (429 in codes) or any('retry-after' in h for h in hdrs_list) or \
                      any('x-ratelimit-remaining' in h and h.get('x-ratelimit-remaining') == '0' for h in hdrs_list)
            rate_result['limited'] = bool(limited)
            if limited:
                rate_result['detail'] = "Rate limit active (HTTP 429 / Retry-After observed) ✅"
                findings.append(("INFO", "Rate Limiting", "Rate limiting is active — brute-force is throttled"))
            else:
                rate_result['detail'] = f"No 429 in 10 rapid requests ({', '.join(str(c) for c in codes)})"
                findings.append(("MEDIUM", "Rate Limiting",
                                 "No rate limiting observed in 10 rapid requests — credential/endpoint brute-force possible"))
        except Exception as e:
            rate_result['detail'] = f"test failed: {e}"

        # ---------- JWT analysis (passive decode — never forged) ----------
        jwt_findings = []
        jwt_re = re.compile(r'eyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}')
        # search sources already collected
        search_blobs = []
        for h in (self.scalar_results.get('http_headers') or {}).items():
            search_blobs.append(f"{h[0]}:{h[1]}")
        search_blobs.append(" ".join(self.results.get('cookies', [])))
        search_blobs.append(" ".join(self.results.get('api_endpoints_found', [])))
        for c in self.results.get('cookies', []):
            search_blobs.append(c)
        # also scan homepage + API snippets collected by api module
        for ep in self.results.get('api_endpoints', [])[:20]:
            if isinstance(ep, dict):
                search_blobs.append(ep.get('snippet', ''))

        jwts = set()
        for blob in search_blobs:
            if blob:
                for m in jwt_re.finditer(str(blob)):
                    jwts.add(m.group(0))

        def b64url_decode(seg):
            seg += '=' * (-len(seg) % 4)
            return base64.urlsafe_b64decode(seg.encode()).decode(errors='replace')

        for token in list(jwts)[:5]:
            try:
                header = json.loads(b64url_decode(token.split('.')[0]))
                payload = json.loads(b64url_decode(token.split('.')[1]))
            except Exception:
                continue
            alg = str(header.get('alg', '?'))
            entry = {"alg": alg, "kid": header.get('kid', ''), "claims": sorted(payload.keys())[:15]}
            jwt_findings.append(entry)
            if alg.lower() == 'none':
                findings.append(("CRITICAL", "JWT", "alg=none accepted in a token — signature can be bypassed (auth bypass risk)"))
            elif alg.startswith('HS'):
                findings.append(("INFO", "JWT", f"Token uses {alg} — ensure public key is not used as HMAC secret (confusion attack)"))
            elif alg.startswith('RS') is False and alg != 'none':
                findings.append(("MEDIUM", "JWT", f"Uncommon JWT alg: {alg}"))
            if 'exp' not in payload:
                findings.append(("MEDIUM", "JWT", "Token has no 'exp' claim — never expires (session fixation risk)"))
            else:
                try:
                    exp_left = int(payload['exp']) - int(datetime.now().timestamp())
                    if exp_left > 60 * 60 * 24 * 400:
                        findings.append(("LOW", "JWT", f"Very long token lifetime (~{exp_left // 86400} days)"))
                except Exception:
                    pass
            if not any(k in payload for k in ('iss', 'aud')):
                findings.append(("LOW", "JWT", "Token lacks 'iss'/'aud' claims — replay across services possible"))
            if not header.get('kid'):
                findings.append(("LOW", "JWT", "No 'kid' in header — key rotation/selection is ambiguous"))

        if not jwts:
            jwt_findings.append({"alg": "-", "kid": "", "claims": []})

        # ---------- store ----------
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.results['api_audit_findings'] = sorted(findings, key=lambda x: sev_rank.get(x[0], 5))
        self.results['api_audit_endpoints'] = endpoint_rows
        self.results['api_audit_ratelimit'] = rate_result
        self.results['api_audit_jwt'] = jwt_findings

    # ---------------------------------------------------------- External Intelligence
    # Takeover service signatures: (cname_suffix, service, body_regex)
    TAKEOVER_SERVICES = [
        ("herokuapp.com", "Heroku", r"(?i)no such app|herokucdn\.com/error-no-such-app"),
        ("github.io", "GitHub Pages", r"(?i)there isn't a github pages site here|browsers searching for what you meant"),
        ("azurewebsites.net", "Azure App Service", r"(?i)404 - web app not found|this web app has been stopped"),
        ("cloudapp.net", "Azure Cloud Service", r"(?i)404 - web app not found"),
        ("blob.core.windows.net", "Azure Blob", r"(?i)resource not found|blob not found"),
        ("amazonaws.com", "AWS S3/ELB", r"(?i)nosuchbucket|no such bucket|the specified bucket does not exist"),
        ("s3.amazonaws.com", "AWS S3", r"(?i)nosuchbucket|no such bucket|the specified bucket does not exist"),
        ("cloudfront.net", "CloudFront", r"(?i)bad request|generated by cloudfront"),
        ("shopify.com", "Shopify", r"(?i)sorry, this shop is currently unavailable"),
        ("myshopify.com", "Shopify", r"(?i)sorry, this shop is currently unavailable"),
        ("tumblr.com", "Tumblr", r"(?i)there's nothing here|whatever you were looking for does not exist"),
        ("wordpress.com", "WordPress.com", r"(?i)do you want to register"),
        ("bitbucket.org", "Bitbucket", r"(?i)repository not found"),
        ("gitlab.io", "GitLab Pages", r"(?i)404 page not found"),
        ("fastly.net", "Fastly", r"(?i)fastly error: unknown domain"),
        ("pantheon.io", "Pantheon", r"(?i)404 error unknown site"),
        ("surge.sh", "Surge", r"(?i)project not found"),
        ("netlify.com", "Netlify", r"(?i)not found - request id"),
        ("netlify.app", "Netlify", r"(?i)not found - request id"),
        ("ghost.io", "Ghost", r"(?i)ghost cloud|the thing you were looking for"),
        ("zendesk.com", "Zendesk", r"(?i)this help center no longer exists"),
        ("statuspage.io", "Statuspage", r"(?i)status page|no longer exists"),
        ("helpjuice.com", "Helpjuice", r"(?i)we could not find what you're looking for"),
        ("intercom.help", "Intercom", r"(?i)this page is not available"),
        ("cargo.site", "Cargo", r"(?i)cargo site does not exist"),
        ("unbouncepages.com", "Unbounce", r"(?i)this page does not exist"),
        ("fly.dev", "Fly.io", r"(?i)404 not found|no such app"),
        ("vercel.app", "Vercel", r"(?i)deployment_not_found|the deployment could not be found"),
        ("render.com", "Render", r"(?i)service not found|project not found"),
        ("webflow.io", "Webflow", r"(?i)the page you are looking for doesn't exist"),
        ("readme.io", "ReadMe", r"(?i)project not found"),
        ("gitbook.io", "GitBook", r"(?i)page not found"),
        ("wixsite.com", "Wix", r"(?i)domain is not connected|error404"),
        ("weebly.com", "Weebly", r"(?i)weebly|404 error"),
    ]

    async def external_intel(self):
        """CT log subdomains (crt.sh), Wayback Machine history, subdomain takeover check."""
        ct_hosts = set()
        wayback_urls = []
        ext_findings = []
        takeover_risks = []

        # crt.sh / Wayback reject non-browser User-Agents (502) — use a browser UA here
        _oss_headers = {"Accept": "application/json",
                        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                       "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")}

        # ---------- 1) Certificate Transparency (crt.sh) ----------
        try:
            r = None
            for attempt in range(3):        # crt.sh rate-limits with 502 — retry politely
                async with self.sem:
                    r = await self.client.get(f"https://crt.sh/?q=%25.{self.domain}&output=json",
                                              timeout=45.0, headers=_oss_headers)
                if r.status_code == 200:
                    break
                await asyncio.sleep(5 + attempt * 5)
            if r.status_code != 200:
                raise RuntimeError(f"crt.sh returned HTTP {r.status_code} (try again later)")
            entries = r.json()
            for e in entries[:6000]:
                for nm in str(e.get('name_value', '')).split('\n'):
                    nm = nm.strip().lower().lstrip('*.')
                    if nm and (nm == self.domain or nm.endswith('.' + self.domain)) \
                            and re.match(r'^[\w.\-]+$', nm):
                        ct_hosts.add(nm)
            for h in sorted(ct_hosts):
                entry = f"{h} (crt.sh)"
                if entry not in self.results['subdomains']:
                    self.results['subdomains'].append(entry)
            if ct_hosts:
                ext_findings.append(("INFO", "CT Logs",
                                     f"crt.sh returned {len(ct_hosts)} unique certificate names"))
        except Exception as e:
            self.results['errors'].append(
                f"CT logs (crt.sh): {type(e).__name__}{': ' + str(e) if str(e) else ''}")

        # ---------- 2) Wayback Machine historical URLs ----------
        cdx_limit = 3000 if self.deep else 1000
        wb_params = {}
        wb_paths = set()
        wb_js = set()
        wb_sensitive = set()
        try:
            cdx = ("https://web.archive.org/cdx/search/cdx"
                   f"?url={self.domain}/*&output=json&fl=original&collapse=urlkey"
                   f"&filter=statuscode:200&limit={cdx_limit}")
            async with self.sem:
                r = await self.client.get(cdx, timeout=30.0, headers=_oss_headers)
            if r.status_code != 200:
                raise RuntimeError(f"archive.org returned HTTP {r.status_code} (Wayback may be temporarily offline)")
            rows = r.json()
            for row in rows[1:]:    # row 0 = header
                if isinstance(row, list) and row and isinstance(row[0], str):
                    wayback_urls.append(row[0])
            for u in wayback_urls:
                try:
                    p = urlparse(u)
                except Exception:
                    continue
                if p.path:
                    clean = unquote(p.path.split('?')[0])
                    wb_paths.add(clean)
                    if re.search(r'(?i)\.(env|git|svn|htaccess|bak|old|sql|dump|zip|tar|gz)$'
                                 r'|/(admin|wp-admin|phpmyadmin|backup|debug|console)'
                                 r'|(password|secret|token|key|credential)', clean):
                        wb_sensitive.add(clean)
                if p.query:
                    for k in parse_qs(p.query):
                        if len(k) < 40:
                            wb_params[k] = wb_params.get(k, 0) + 1
                if re.search(r'(?i)\.js$', p.path):
                    wb_js.add(p.path)
            for sp in sorted(wb_sensitive)[:20]:
                ext_findings.append(("MEDIUM", "Wayback History",
                                     f"Sensitive path was public before: {sp} (archive.org)"))
            if wayback_urls:
                ext_findings.append(("INFO", "Wayback History",
                                     f"{len(wayback_urls)} historical URLs, {len(wb_params)} unique params, "
                                     f"{len(wb_paths)} unique paths"))
        except Exception as e:
            self.results['errors'].append(
                f"Wayback CDX: {type(e).__name__}{': ' + str(e) if str(e) else ''}")

        # ---------- 3) Dangling subdomain takeover check ----------
        hosts = set(ct_hosts)
        for s in list(self.results.get('subdomains', [])):
            host = str(s).split(' ')[0].split(' -> ')[0].strip().lower()
            if host.endswith('.' + self.domain):
                hosts.add(host)
        for c in ("www", "mail", "dev", "test", "staging", "blog", "shop", "app", "api",
                  "admin", "cdn", "portal", "demo", "beta"):
            hosts.add(f"{c}.{self.domain}")
        hosts.discard(self.domain)
        host_list = sorted(hosts)[: (60 if self.deep else 25)]

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout

        async def get_cname(host):
            try:
                ans = await resolver.resolve(host, 'CNAME')
                return str(ans[0].target).rstrip('.').lower()
            except Exception:
                pass
            # DoH fallback (TCP/53-blocked networks)
            try:
                async with httpx.AsyncClient(timeout=8) as c:
                    rr = await c.get("https://cloudflare-dns.com/dns-query",
                                     params={"name": host, "type": "CNAME"},
                                     headers={"Accept": "application/dns-json"})
                    if rr.status_code == 200:
                        for ans in rr.json().get("Answer", []):
                            if ans.get("type") == 5:
                                return str(ans.get("data", "")).rstrip('.').lower()
            except Exception:
                pass
            return ""

        async def check_takeover(host):
            cname = await get_cname(host)
            if not cname:
                return
            for suffix, service, sig in self.TAKEOVER_SERVICES:
                if cname == suffix or cname.endswith('.' + suffix):
                    body = ""
                    for scheme in ("https", "http"):
                        try:
                            async with self.sem:
                                rr = await self.client.get(f"{scheme}://{host}/", timeout=8.0)
                            body = rr.text[:80_000]
                            break
                        except Exception:
                            continue
                    m = re.search(sig, body) if body else None
                    if m:
                        takeover_risks.append(f"{host} -> {cname} [{service}] RISK")
                        ext_findings.append(("HIGH", "Subdomain Takeover (likely)",
                                             f"{host} -> {cname} ({service}) serves takeover signature: "
                                             f"'{m.group(0)[:45]}' — register/claim or remove the DNS record"))
                    else:
                        ext_findings.append(("INFO", "Takeover check",
                                             f"{host} -> {cname} ({service}) — no takeover signature (likely claimed)"))
                    return

        await asyncio.gather(*[check_takeover(h) for h in host_list])

        # ---------- store ----------
        self.results['ct_hosts'] = sorted(ct_hosts)
        self.results['wayback'] = {
            "total_urls": len(wayback_urls),
            "sample_urls": sorted(wayback_urls)[:150],
            "unique_paths": len(wb_paths),
            "parameters": dict(sorted(wb_params.items(), key=lambda x: -x[1])[:60]),
            "js_files": sorted(wb_js)[:60],
            "sensitive_paths": sorted(wb_sensitive)[:40],
        }
        self.results['takeover'] = takeover_risks
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        merged = list(ext_findings)
        self.results['ext_findings'] = sorted(merged, key=lambda x: sev_rank.get(x[0], 5))

    # ---------------------------------------------------------- CVE & Misconfig Scan
    # (product, rule_major_or_None, mode, boundary_tuple, cve, severity, title)
    #   mode: 'eq' = exact match, 'lt' = version below boundary
    #   rule_major: restrict to that major version (None = any older major too)
    CVE_RULES = [
        ("apache",    None, "eq", (2, 4, 49), "CVE-2021-41773", "CRITICAL", "Path traversal + RCE via mod_cgi"),
        ("apache",    None, "eq", (2, 4, 50), "CVE-2021-42013", "CRITICAL", "Path traversal + RCE (incomplete 41773 fix)"),
        ("apache",    None, "lt", (2, 4, 49), "CVE-2021-40438", "HIGH",     "mod_proxy SSRF (fixed in 2.4.49)"),
        ("nginx",     None, "lt", (1, 20, 1), "CVE-2021-23017", "HIGH",     "Resolver off-by-one DNS poisoning (fixed 1.20.1)"),
        ("jquery",    None, "lt", (3, 5, 0),  "CVE-2020-11022", "MEDIUM",   "XSS via htmlPrefilter (jQuery < 3.5.0)"),
        ("jquery",    None, "lt", (3, 4, 0),  "CVE-2019-11358", "MEDIUM",   "Prototype pollution (jQuery < 3.4.0)"),
        ("jquery",    None, "lt", (3, 0, 0),  "CVE-2015-9251",  "MEDIUM",   "Cross-domain AJAX XSS (jQuery < 3.0.0)"),
        ("jquery ui", None, "lt", (1, 13, 0), "CVE-2021-41182", "MEDIUM",   "XSS in jQuery UI widgets (< 1.13.0)"),
        ("bootstrap", None, "lt", (4, 3, 1),  "CVE-2019-8331",  "MEDIUM",   "XSS in tooltip/popover (< 4.3.1 / 3.4.1)"),
        ("tomcat",    9,    "lt", (9, 0, 31), "CVE-2020-1938",  "HIGH",     "Ghostcat AJP file read (9.x < 9.0.31)"),
        ("tomcat",    8,    "lt", (8, 5, 51), "CVE-2020-1938",  "HIGH",     "Ghostcat AJP file read (8.5.x < 8.5.51)"),
        ("drupal",    7,    "lt", (7, 31),    "CVE-2014-3704",  "CRITICAL", "SQLi 'Drupageddon' (7.x < 7.31)"),
        ("drupal",    7,    "lt", (7, 58),    "CVE-2018-7600",  "CRITICAL", "RCE 'Drupalgeddon2' (7.x < 7.58)"),
        ("drupal",    8,    "lt", (8, 5, 1),  "CVE-2018-7600",  "CRITICAL", "RCE 'Drupalgeddon2' (8.x < 8.5.1)"),
        ("wordpress", None, "lt", (5, 8, 3),  "CVE-2022-21661", "MEDIUM",   "WP_Query SQLi (WordPress < 5.8.3)"),
        ("joomla",    3,    "lt", (3, 4, 6),  "CVE-2015-8562",  "CRITICAL", "Session deserialization RCE (< 3.4.6)"),
    ]

    # Active probes: (path, expect_regex_or_None, severity, id, title)
    MISCONFIG_PROBES = [
        ("/.git/HEAD",        r"(?m)^ref: refs/",         "HIGH",     "Exposed .git",            "Git repository metadata public (source + history leak)"),
        ("/.env",             r"(?i)(app_key|db_password|secret|api_key)\s*=", "CRITICAL", "Exposed .env", "Environment file with secrets is public"),
        ("/.svn/wc.db",       r"(?i)SQLite",              "HIGH",     "Exposed .svn",            "Subversion working copy database public"),
        ("/actuator/env",     r"(?i)activeProfiles|propertySources", "HIGH", "Spring Actuator /env", "Spring Boot config exposed (env vars, credentials)"),
        ("/actuator/heapdump", None,                      "CRITICAL", "Heapdump",                "JVM heapdump downloadable (secrets/session tokens in memory)"),
        ("/_ignition/health", r"(?i)can_execute_command|ignition",   "HIGH",     "Laravel Ignition",       "Ignition debug exposed — verify CVE-2021-3129 RCE (Ignition < 2.5.1)"),
        ("/phpinfo.php",      r"(?i)phpinfo\(\)|PHP Version", "MEDIUM", "phpinfo()",              "phpinfo() exposed (paths, versions, config leak)"),
        ("/server-status",    r"(?i)Apache Server Status", "MEDIUM",   "Apache server-status",    "Server status page public (traffic/worker info)"),
        ("/server-info",      r"(?i)Server Information",  "MEDIUM",   "Apache server-info",      "Apache config dump public"),
        ("/web.config",       r"(?i)<configuration>",     "MEDIUM",   "web.config",              "IIS config exposed (connection strings possible)"),
        ("/h2-console",       r"(?i)H2 Console|H2 Database", "HIGH",  "H2 Console",              "H2 database console exposed (RCE if reachable)"),
    ]

    async def cve_scan(self):
        """Version fingerprinting -> CVE correlation + active misconfiguration probes."""
        findings = []          # (severity, id, title, evidence)
        versions = []          # (product, version, source)

        # ---------- 1) gather page material ----------
        html, headers_blob = "", ""
        try:
            async with self.sem:
                resp = await self.client.get(self.scalar_results.get('final_url', self.base_url + "/"))
            html = resp.text[:500_000]
            headers_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
        except Exception as e:
            self.results['errors'].append(f"CVE scan: fetch failed: {e}")

        blob = headers_blob + "\n" + html

        def _ver_tuple(ver_str):
            try:
                return tuple(int(x) for x in re.findall(r'\d+', ver_str)[:4])
            except Exception:
                return ()

        def _cmp(a, b):
            """-1/0/1 comparison with zero-padding to equal length."""
            n = max(len(a), len(b))
            a = a + (0,) * (n - len(a))
            b = b + (0,) * (n - len(b))
            return (a > b) - (a < b)

        def add_version(product, ver_str, source):
            parts = _ver_tuple(ver_str)
            if not parts:
                return
            versions.append((product, ver_str, source))
            for prod, rule_major, mode, boundary, cve, sev, title in self.CVE_RULES:
                if prod != product:
                    continue
                if rule_major is not None and parts[0] != rule_major:
                    continue
                hit = (_cmp(parts, boundary) == 0) if mode == 'eq' else (_cmp(parts, boundary) < 0)
                if hit:
                    findings.append((sev, cve, title,
                                     f"detected {product} {ver_str} ({source})"))

        # --- Server / X-Powered-By headers ---
        server_h = re.search(r'(?i)(?:^|[\s;])server\s*:\s*([\w\-]+)/([\d.]+)', headers_blob)
        if server_h:
            add_version(server_h.group(1).lower().replace('microsoft-', ''), server_h.group(2), 'Server header')
        xpb = re.search(r'(?i)(?:^|[\s;])x-powered-by\s*:\s*(php)[/ ]v?([\d.]+)', headers_blob)
        if xpb:
            add_version('php', xpb.group(2), 'X-Powered-By')

        # --- generator meta ---
        gen = re.search(r'(?i)<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']?([^"\'>]+)', html)
        if gen:
            g = gen.group(1)
            gm = re.search(r'(?i)(wordpress|drupal|joomla|typo3|ghost)\s*v?([\d.]+)', g)
            if gm:
                add_version(gm.group(1).lower(), gm.group(2), 'meta generator')

        # --- WP version from asset links ---
        wp = re.search(r'(?i)wp-(?:includes|content)/[^"\']+?ver=([\d.]+)', html)
        if wp:
            add_version('wordpress', wp.group(1), 'wp asset ver=')

        # --- JS libraries ---
        js_checks = [
            (r'(?i)jquery[.-]([\d]+\.[\d.]+)(?:\.min)?\.js', 'jquery'),
            (r'(?i)jquery-ui[.-](?:min\.)?([\d]+\.[\d.]+)', 'jquery ui'),
            (r'(?i)bootstrap[.-]([\d]+\.[\d.]+)', 'bootstrap'),
            (r'(?i)react@([\d]+\.[\d.]+)', 'react'),
            (r'(?i)vue(?:\.min)?@?([\d]+\.[\d.]+)', 'vue'),
            (r'(?i)angular(?:\.js)?[@/](?:v)?([\d]+\.[\d.]+)', 'angular'),
            (r'(?i)swagger-ui(?:-bundle)?(?:\.min)?\.js[^"\']*?(\d+\.\d+\.\d+)', 'swagger-ui'),
            (r'(?i)lodash[.-]([\d]+\.[\d.]+)\.js', 'lodash'),
            (r'(?i)axios[.-]([\d]+\.[\d.]+)\.js', 'axios'),
        ]
        for pat, prod in js_checks:
            m = re.search(pat, blob)
            if m:
                add_version(prod, m.group(1), 'JS asset')

        # --- OpenSSL / server software from SSL module results ---
        # (filled by tls/ssl modules if run — best effort)

        # ---------- 2) active misconfig probes ----------
        probes = [(p, rx, sev, pid, title) for p, rx, sev, pid, title in self.MISCONFIG_PROBES if p and pid]
        if not self.deep:
            probes = probes[:7]

        async def probe(path, expect, sev, pid, title):
            url = urljoin(self.base_url + "/", path.lstrip('/'))
            try:
                async with self.sem:
                    r = await self.client.get(url, headers={"Accept": "text/html,application/json,*/*"})
            except Exception:
                return
            ok = False
            if r.status_code == 200 and len(r.content) > 0:
                if expect is None:
                    ok = True
                elif re.search(expect, r.text[:200_000]):
                    ok = True
            elif pid == "Heapdump" and r.status_code == 200:
                ok = True
            if ok:
                size = len(r.content)
                findings.append((sev, pid, title, f"{path} -> HTTP {r.status_code} ({size:,} bytes)"))
                self.results['paths'].append({'path': path, 'status': r.status_code,
                                              'type': r.headers.get('content-type', '').split(';')[0],
                                              'size': len(r.content),
                                              'source': 'cve-scan', 'flagged': True})

        await asyncio.gather(*[probe(*pr) for pr in probes])

        # --- directory listing detection (from any fetched page title) ---
        if re.search(r'(?i)<title>\s*index of\s*/', html):
            findings.append(("MEDIUM", "Directory Listing", "Index of / enabled",
                             "server lists directory contents on homepage root"))

        # ---------- store ----------
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.results['versions'] = sorted(set(versions))
        self.results['cve_findings'] = sorted(findings, key=lambda x: sev_rank.get(x[0], 5))

    # ---------------------------------------------------------- Deep Crawler & Params
    async def deep_crawler(self):
        """Multi-page BFS crawl: pages, forms, query parameters, JS endpoints,
        reflection detection (benign canary — detection only)."""
        max_pages = 40 if self.deep else 15
        max_depth = 3 if self.deep else 2

        start = str(self.scalar_results.get('final_url', self.base_url + "/"))
        queue = deque([(start, 0)])
        visited = set()
        pages = []                      # (url, status, title)
        params = {}                     # name -> {"urls": [sample urls], "reflected": bool, "pages": set}
        forms = []
        endpoints = set()
        js_files = set()
        internal_links = set()
        skip_ext = re.compile(r'(?i)\.(png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|pdf|zip|gz|mp4|webp)(\?|$)')

        def register_params(page_url, html_body=""):
            try:
                q = urlparse(page_url).query
            except Exception:
                q = ""
            if not q:
                return
            for k, vals in parse_qs(q, keep_blank_values=True).items():
                if len(k) > 40:
                    continue
                e = params.setdefault(k, {"urls": [], "reflected": False, "pages": set()})
                if page_url not in e["urls"] and len(e["urls"]) < 5:
                    e["urls"].append(page_url)
                e["pages"].add(page_url)

        # ---------- BFS crawl ----------
        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                async with self.sem:
                    r = await self.client.get(url, headers={"Accept": "text/html,application/xhtml+xml,*/*"})
                body = r.text[:600_000]
            except Exception:
                continue

            title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            title = title_m.group(1).strip()[:80] if title_m else ""
            pages.append((str(r.url), r.status_code, title))
            register_params(url, body)
            register_params(str(r.url), body)

            # directory listing on any page
            if re.search(r'(?i)<title>\s*index of\s*/', body) and not any(f[1] == 'Directory Listing' for f in self.results.get('cve_findings', [])):
                self.results['cve_findings'].append(
                    ("MEDIUM", "Directory Listing", "Index of / enabled", f"on {url}"))

            # links
            for m in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', body, re.I):
                href = m.group(1).strip()
                if href.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
                    continue
                full = urljoin(str(r.url), href)
                try:
                    p = urlparse(full)
                except Exception:
                    continue
                if p.scheme not in ('http', 'https'):
                    continue
                netloc = p.netloc.lower().split('@')[-1]
                if netloc not in (self.netloc.lower(), self.domain.lower()):
                    continue
                internal_links.add(full)
                if skip_ext.search(full) or full in visited:
                    continue
                if depth + 1 <= max_depth and full not in visited:
                    queue.append((full, depth + 1))
                register_params(full)

            # forms
            for m in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', body, re.I | re.S):
                inner = m.group(2)
                method_m = re.search(r'<form[^>]*method=["\']([^"\']*)["\']', m.group(0), re.I)
                method = (method_m.group(1) if method_m else "GET").upper()
                fields = re.findall(r'<(?:input|select|textarea)[^>]*name=["\']([^"\']+)["\']', inner, re.I)
                for f in fields:
                    if len(f) <= 40:
                        e = params.setdefault(f, {"urls": [], "reflected": False, "pages": set()})
                        e["pages"].add(str(r.url))
                        if method == "GET" and str(r.url) not in e["urls"] and len(e["urls"]) < 5:
                            e["urls"].append(str(r.url))
                rec = {"action": m.group(1) or "(same page)", "method": method, "fields": fields[:20],
                       "page": str(r.url)}
                if rec not in forms:
                    forms.append(rec)

            # scripts + inline API paths
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I):
                js_files.add(urljoin(str(r.url), m.group(1)))
            for m in re.finditer(r'["\'](/(?:api|rest|graphql|v\d|wp-json|oauth)[\w\-/{}.?=&%]*)["\']', body, re.I):
                endpoints.add(m.group(1))

        # ---------- JS bundle analysis (same-origin, capped) ----------
        async def analyze_js(u):
            try:
                async with self.sem:
                    r = await self.client.get(u)
                if r.status_code != 200:
                    return
                b = r.text[:800_000]
                for m in re.finditer(r'["\'`](/(?:api|rest|graphql|auth|oauth|v\d+)[\w\-/{}.?=&%$]*)["\'`]', b):
                    endpoints.add(m.group(1))
                for m in re.finditer(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\(\s*["\'`]([^"\'`]{3,200})["\'`]', b):
                    v = m.group(1)
                    if v.startswith('/'):
                        endpoints.add(v)
            except Exception:
                pass

        same_origin_js = [u for u in sorted(js_files) if urlparse(u).netloc.lower().split('@')[-1] == self.netloc.lower()]
        await asyncio.gather(*[analyze_js(u) for u in same_origin_js[: (15 if self.deep else 8)]])

        # ---------- reflection test (benign canary, detection only) ----------
        canary = "nv" + re.sub(r'[^a-z0-9]', '', __import__('secrets').token_hex(4))
        testable = [e for e in params.values() if e["urls"] and not e["reflected"]][:8]
        async def test_reflect(entry):
            sample = entry["urls"][0]
            try:
                p = urlparse(sample)
                q = dict(parse_qs(p.query, keep_blank_values=True))
                if not q:
                    return
                key = next(iter(q))
                q[key] = [canary]
                new_q = "&".join(f"{k}={v}" for k, v in
                                 ((k2, (v2[0] if isinstance(v2, list) else v2)) for k2, v2 in q.items()))
                target = f"{p.scheme}://{p.netloc}{p.path}?{new_q}"
                async with self.sem:
                    r = await self.client.get(target, headers={"Accept": "text/html,*/*"})
                if canary in r.text:
                    entry["reflected"] = True
                    entry["reflected_on"] = key
            except Exception:
                pass

        await asyncio.gather(*[test_reflect(e) for e in testable])

        reflected = [(k, e) for k, e in params.items() if e.get("reflected")]

        # ---------- store ----------
        self.results['crawl'] = {
            "pages_crawled": len(pages),
            "pages": [{"url": u, "status": s, "title": t} for u, s, t in pages[:60]],
            "internal_links": sorted(internal_links)[:200],
            "parameters": [{"name": k, "seen_on": len(v["pages"]), "reflected": bool(v.get("reflected"))}
                           for k, v in sorted(params.items())],
            "forms": forms[:40],
            "js_files": sorted(same_origin_js)[:80],
            "endpoints_found": sorted(endpoints)[:300],
        }
        self.results['crawl_params'] = sorted(params.keys())
        self.results['reflected_params'] = sorted(k for k, _ in reflected)

    # ---------------------------------------------------------- TLS Deep Analysis
    async def tls_audit(self):
        """TLS version/cipher matrix, weak crypto, cert chain key size, OCSP, HSTS."""
        findings = []          # (severity, id, detail)
        matrix = []            # (version, supported, cipher, bits, note)
        host = self.domain
        port = self.parsed.port or 443

        versions = [
            ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
            ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
            ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
            ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
        ]

        def try_version(const):
            """Handshake forcing one TLS version. Returns (cipher, bits) or None."""
            if const is None:
                return None
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # re-enable protocols some builds disable by default
                for optname in ("OP_NO_TLSv1", "OP_NO_TLSv1_1", "OP_NO_TLSv1_2"):
                    opt = getattr(ssl, optname, None)
                    if opt:
                        ctx.options &= ~opt
                ctx.minimum_version = const
                ctx.maximum_version = const
            except (ValueError, AttributeError, ssl.SSLError):
                return "UNSUPPORTED_BUILD"
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as s:
                        c = s.cipher()
                        return (c[0] if c else "?", c[2] if c else 0, s.version() or "?")
            except (ssl.SSLError, OSError, ConnectionError):
                return None

        WEAK_HARD_RE = re.compile(r'(?i)(\bNULL\b|EXPORT|ANON|\bMD5\b|RC4|\-DES\b|DES-CBC3|\b3DES\b)')
        WEAK_LEGACY_RE = re.compile(r'(?i)(CBC|\-SHA$)')   # legacy, not broken

        # ---------- version/cipher matrix ----------
        for name, const in versions:
            res = try_version(const)
            if res == "UNSUPPORTED_BUILD":
                matrix.append((name, "-", "-", "-", "client build cannot test"))
            elif res is None:
                matrix.append((name, "no", "-", "-", "not negotiated"))
                if name in ("TLS 1.0", "TLS 1.1"):
                    findings.append(("INFO", f"{name} disabled", f"{name} not offered ✅ (deprecated)"))
            else:
                cipher, bits, nego = res
                matrix.append((name, "yes", cipher, str(bits), nego))
                if name == "TLS 1.0":
                    findings.append(("HIGH", "TLS 1.0 enabled",
                                     "TLS 1.0 accepted — BEAST/POODLE-class risks (PCI DSS: disable)"))
                elif name == "TLS 1.1":
                    findings.append(("MEDIUM", "TLS 1.1 enabled",
                                     "TLS 1.1 accepted — deprecated (RFC 8996), disable it"))
                if WEAK_HARD_RE.search(cipher or ""):
                    findings.append(("HIGH", "Weak cipher", f"{name} negotiates broken-class cipher: {cipher} ({bits}-bit)"))
                elif WEAK_LEGACY_RE.search(cipher or ""):
                    findings.append(("LOW", "Legacy cipher",
                                     f"{name} negotiates legacy CBC/SHA1 cipher: {cipher} — prefer AEAD (GCM/CHACHA20)"))
                elif bits and isinstance(bits, int) and 0 < bits < 128 and name != "TLS 1.3":
                    findings.append(("MEDIUM", "Short key", f"{name} cipher strength only {bits}-bit"))

        tls12 = next((m for m in matrix if m[0] == "TLS 1.2" and m[1] == "yes"), None)
        tls13 = next((m for m in matrix if m[0] == "TLS 1.3" and m[1] == "yes"), None)
        if tls12 and not tls13:
            findings.append(("LOW", "No TLS 1.3", "TLS 1.3 not offered — consider enabling for forward secrecy"))

        # ---------- full cert chain via openssl (optional, richer details) ----------
        cert_info = {}
        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host,
                "-showcerts",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            text = out.decode(errors='replace')
            for pat, key in (
                (r'(?m)^Server public key is\s+(\d+)\s+bit$', 'public_key_bits'),
                (r'(?m)^Signature Algorithm:\s+(\S+)', 'signature_alg'),
                (r'(?m)^OCSP response:\s+(.+)$', 'ocsp_response'),
                (r'(?m)^Verification error:\s+(.+)$', 'verify_error'),
                (r'(?m)^Protocol\s+:\s+(\S+)', 'negotiated_protocol'),
                (r'(?m)^Cipher\s+:\s+(\S+)', 'negotiated_cipher'),
            ):
                m = re.search(pat, text)
                if m:
                    cert_info[key] = m.group(1).strip()
            # Distinguish RSA vs EC key: parse the leaf cert itself
            pem_m = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.S)
            if pem_m:
                try:
                    p2 = await asyncio.create_subprocess_exec(
                        "openssl", "x509", "-noout", "-text",
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    out2, _ = await asyncio.wait_for(
                        p2.communicate(pem_m.group(0).encode()), timeout=10)
                    xt = out2.decode(errors='replace')
                    km = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', xt)
                    if km:
                        cert_info['public_key_bits'] = km.group(1)
                    if re.search(r'(?m)^\s*ASN1 OID:|NIST CURVE:', xt):
                        curve = re.search(r'NIST CURVE:\s*(\S+)', xt)
                        cert_info['key_type'] = f"EC{curve.group(1) if curve else ''}"
                    elif re.search(r'(?m)^\s*Exponent:', xt):
                        cert_info['key_type'] = 'RSA'
                    if re.search(r'(?i)sha1WithRSA|md5WithRSA|ecdsa-with-SHA1', xt):
                        cert_info['signature_alg'] = re.search(
                            r'(?i)(\S*sha1\S*|\S*md5\S*)', xt).group(1)
                except Exception:
                    pass
        except FileNotFoundError:
            cert_info['note'] = 'openssl CLI not installed — skipping chain details'
        except Exception as e:
            cert_info['note'] = f'openssl probe failed: {type(e).__name__}'

        # key size findings (RSA vs EC are different scales!)
        try:
            kbits = int(cert_info.get('public_key_bits', '0'))
            ktype = cert_info.get('key_type', 'RSA')     # default assumption: RSA
            if ktype.startswith('EC'):
                if kbits and kbits < 256:
                    findings.append(("HIGH", "Short EC key", f"EC key is only {kbits}-bit (< P-256)"))
                elif kbits and kbits >= 256:
                    findings.append(("INFO", "Strong EC key", f"{ktype} {kbits}-bit ✅ (modern)"))
            else:
                if kbits and kbits < 2048:
                    findings.append(("HIGH", "Short RSA key", f"RSA key is {kbits}-bit (< 2048 — weak)"))
                elif kbits and kbits >= 4096:
                    findings.append(("INFO", "Strong key", f"RSA {kbits}-bit ✅"))
        except ValueError:
            pass
        if re.search(r'(?i)sha1|md5', cert_info.get('signature_alg', '')):
            findings.append(("HIGH", "Weak cert signature", f"Certificate signed with {cert_info['signature_alg']}"))
        ocsp = cert_info.get('ocsp_response', '')
        if ocsp and 'no response' not in ocsp.lower():
            cert_info['ocsp_stapled'] = 'yes ✅'
            findings.append(("INFO", "OCSP stapling", "OCSP response stapled ✅"))
        elif ocsp:
            cert_info['ocsp_stapled'] = 'no'
            findings.append(("LOW", "No OCSP stapling", "No OCSP response stapled (revocation checking slower)"))
        if 'verify_error' in cert_info:
            findings.append(("MEDIUM", "Cert verify failed", f"openssl verify: {cert_info['verify_error'][:80]}"))

        # ---------- HSTS ----------
        headers = self.scalar_results.get('http_headers') or {}
        hsts = headers.get('strict-transport-security', '')
        if not hsts:
            try:
                async with self.sem:
                    r = await self.client.get(self.base_url + "/")
                hsts = r.headers.get('strict-transport-security', '')
            except Exception:
                pass
        if hsts:
            cert_info['hsts'] = hsts
            mx = re.search(r'max-age=(\d+)', hsts)
            if mx and int(mx.group(1)) < 15552000:   # < 180 days
                findings.append(("MEDIUM", "HSTS max-age short",
                                 f"HSTS max-age={mx.group(1)}s (< 180 days recommended)"))
            if 'includesubdomains' not in hsts.lower():
                findings.append(("LOW", "HSTS scope", "HSTS missing 'includeSubDomains'"))
        else:
            findings.append(("MEDIUM", "No HSTS", "Strict-Transport-Security header missing"))

        # ---------- store ----------
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.results['tls_matrix'] = matrix
        self.results['tls_cert'] = cert_info
        self.results['tls_findings'] = sorted(findings, key=lambda x: sev_rank.get(x[0], 5))

    # ---------------------------------------------------------- Supply Chain / Third-Party Risk
    # (url substring, vendor, category, note)
    VENDORS = [
        ("google-analytics.com", "Google Analytics", "Analytics", "page data flows to Google"),
        ("googletagmanager.com", "Google Tag Manager", "Tag Manager", "executes arbitrary tags — high impact if account is compromised"),
        ("doubleclick.net", "Google Ads (DoubleClick)", "Advertising", "cross-site ad tracking"),
        ("googlesyndication.com", "Google AdSense", "Advertising", "third-party ad frames"),
        ("googleapis.com", "Google APIs", "API/CDN", "fonts/maps/api loads from Google"),
        ("gstatic.com", "Google Static", "CDN", "static assets from Google"),
        ("fonts.googleapis.com", "Google Fonts", "Font", "font CSS from Google"),
        ("facebook.net", "Meta/Facebook", "Advertising", "social pixel — tracking"),
        ("fbcdn.net", "Meta CDN", "CDN", "Meta-hosted assets"),
        ("connect.facebook.net", "Meta Pixel", "Advertising", "visitor tracking pixel"),
        ("hotjar.com", "Hotjar", "Analytics/Replay", "session replay — records user interaction"),
        ("segment.com", "Segment", "CDN/CDP", "customer data pipeline"),
        ("segment.io", "Segment", "CDP", "customer data pipeline"),
        ("mixpanel.com", "Mixpanel", "Analytics", "product analytics"),
        ("amplitude.com", "Amplitude", "Analytics", "product analytics"),
        ("clarity.ms", "Microsoft Clarity", "Analytics/Replay", "session replay by Microsoft"),
        ("newrelic.com", "New Relic", "APM", "JS monitoring"),
        ("nr-data.net", "New Relic", "APM", "JS monitoring"),
        ("sentry.io", "Sentry", "Error Tracking", "JS error reporting — may send request data"),
        ("datadoghq.com", "Datadog", "APM", "RUM monitoring"),
        ("optimize.google.com", "Google Optimize", "AB Testing", "page variant injection"),
        ("optimizely.com", "Optimizely", "AB Testing", "page variant injection"),
        ("unpkg.com", "unpkg", "JS CDN", "npm package CDN — packages change over time"),
        ("cdn.jsdelivr.net", "jsDelivr", "JS CDN", "npm package CDN"),
        ("cdnjs.cloudflare.com", "cdnjs", "JS CDN", "public library CDN"),
        ("ajax.googleapis.com", "Google Hosted Libraries", "JS CDN", "public library CDN"),
        ("bootstrapcdn.com", "BootstrapCDN", "JS CDN", "public library CDN"),
        ("code.jquery.com", "jQuery CDN", "JS CDN", "jQuery from jQuery project"),
        ("stripe.com", "Stripe", "Payments", "payment processing — PCI scope"),
        ("js.stripe.com", "Stripe", "Payments", "payment processing — PCI scope"),
        ("paypal.com", "PayPal", "Payments", "payment processing"),
        ("paypalobjects.com", "PayPal", "Payments", "payment processing"),
        ("braintreegateway.com", "Braintree", "Payments", "payment processing"),
        ("recaptcha.net", "reCAPTCHA", "Bot Protection", "Google captcha"),
        ("google.com/recaptcha", "reCAPTCHA", "Bot Protection", "Google captcha"),
        ("hcaptcha.com", "hCaptcha", "Bot Protection", "captcha service"),
        ("cloudflare.com", "Cloudflare", "CDN/Security", "CDN/WAF/DDoS provider"),
        ("cloudflareinsights.com", "Cloudflare Insights", "Analytics", "RUM beacon"),
        ("akamai", "Akamai", "CDN", "CDN/edge provider"),
        ("fastly.net", "Fastly", "CDN", "CDN/edge provider"),
        ("cloudfront.net", "CloudFront", "CDN", "AWS CDN"),
        ("intercom.io", "Intercom", "Support Chat", "chat widget — third-party iframe/JS"),
        ("intercomcdn.com", "Intercom", "Support Chat", "chat widget assets"),
        ("zendesk.com", "Zendesk", "Support Chat", "support widget"),
        ("zdassets.com", "Zendesk", "Support Chat", "support widget assets"),
        ("drift.com", "Drift", "Support Chat", "conversational marketing widget"),
        ("hubspot.com", "HubSpot", "Marketing", "marketing/forms/tracking"),
        ("hs-scripts.com", "HubSpot", "Marketing", "marketing tracking"),
        ("mailchimp.com", "Mailchimp", "Email Marketing", "signup/list forms"),
        ("mcfeely" , "Mailchimp", "Email Marketing", "signup/list forms"),
        ("doubleverify", "DoubleVerify", "Ad Verification", "ad verification frames"),
        ("typekit.net", "Adobe Typekit", "Font", "web fonts from Adobe"),
        ("js.netmng" , "NetMng", "Advertising", "ad tech"),
        ("youtube.com", "YouTube", "Embed", "embedded video"),
        ("ytimg.com", "YouTube", "Embed", "embedded video assets"),
        ("vimeo.com", "Vimeo", "Embed", "embedded video"),
        ("twitter.com", "Twitter/X", "Social Embed", "embedded social content"),
        ("platform.twitter.com", "Twitter/X", "Social Embed", "embedded social content"),
        ("licdn.com", "LinkedIn", "Social Embed", "insight tag / embeds"),
        ("snap.licdn.com", "LinkedIn", "Social Embed", "ad insight tag"),
        ("tiktok.com", "TikTok", "Social Embed", "embed/tracking"),
        ("criteo.com", "Criteo", "Advertising", "retargeting ads"),
        ("taboola.com", "Taboola", "Advertising", "content recommendation ads"),
        ("outbrain.com", "Outbrain", "Advertising", "content recommendation ads"),
        ("auth0.com", "Auth0", "SSO/Auth", "external identity provider"),
        ("okta.com", "Okta", "SSO/Auth", "external identity provider"),
        ("onelogin.com", "OneLogin", "SSO/Auth", "external identity provider"),
        ("salesforce.com", "Salesforce", "CRM", "CRM embeds/forms"),
        ("force.com", "Salesforce", "CRM", "CRM-hosted endpoints"),
        ("zoominfo", "ZoomInfo", "Data/Tracking", "B2B data enrichment"),
        ("wistia.com", "Wistia", "Embed", "hosted video player"),
    ]

    async def supply_chain(self):
        """Map third-party resources (scripts/styles/iframes/forms/DNS) and audit SRI/vendor risk."""
        findings = []
        html = ""
        page_url = str(self.scalar_results.get('final_url', self.base_url + "/"))
        try:
            async with self.sem:
                r = await self.client.get(page_url)
            html = r.text[:600_000]
            page_url = str(r.url)
        except Exception as e:
            self.results['errors'].append(f"supply: homepage fetch failed: {type(e).__name__}")

        def vendors_in(url):
            u = url.lower()
            return [v for v in self.VENDORS if v[0].lower() in u]

        # ---------- scan HTML resources ----------
        resources = []      # {kind, url, sri, vendor, vendor_known}
        ext_form_actions = []
        for kind, pat in (
            ("script", r'<script[^>]+src=["\']([^"\']+)["\']'),
            ("stylesheet", r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']'),
            ("iframe", r'<iframe[^>]+src=["\']([^"\']+)["\']'),
        ):
            for m in re.finditer(pat, html, re.I):
                raw = m.group(1).strip()
                full = urljoin(page_url, raw)
                p = urlparse(full)
                if p.scheme not in ('http', 'https'):
                    continue
                same = p.netloc.lower().split('@')[-1] == self.netloc.lower()
                if not same:
                    vs = vendors_in(full)
                    resources.append({"kind": kind, "url": full, "raw": raw, "same_origin": False,
                                      "sri": None,
                                      "vendor": vs[0][1] if vs else None,
                                      "vendor_known": bool(vs)})
        # SRI presence needs tag context — re-scan with tag bodies
        sri_map = {}
        for m in re.finditer(r'<(script|link)\b[^>]*>', html, re.I):
            tag = m.group(0)
            src_m = re.search(r'(?:src|href)=["\']([^"\']+)["\']', tag)
            if src_m and 'integrity=' in tag.lower():
                sri_map[src_m.group(1)] = True
        for rec in resources:
            raw = rec.get("raw", "")
            rec["sri"] = bool(sri_map.get(raw) or sri_map.get(raw.split('?')[0]) or
                              sri_map.get(rec["url"].split('?')[0]))
            if rec["kind"] == "iframe":
                rec["sri"] = True    # SRI not applicable to iframes
        # third-party form actions
        for m in re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I):
            action = m.group(1).strip()
            if not action:
                continue
            full = urljoin(page_url, action)
            p = urlparse(full)
            if p.scheme in ('http', 'https') and p.netloc and \
                    p.netloc.lower().split('@')[-1] != self.netloc.lower():
                ext_form_actions.append((p.scheme, full))
        # dns-prefetch / preconnect hosts
        preconnect = sorted(set(re.findall(r'rel=["\'](?:preconnect|dns-prefetch)["\'][^>]*href=["\'](?:https?:)?//([^"\']+)', html, re.I)))

        # ---------- DNS-level providers ----------
        providers = {"ns": [], "mx": [], "spf_includes": []}
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self.timeout
            try:
                ans = await resolver.resolve(self.domain, 'NS')
                providers["ns"] = sorted({str(x.target).rstrip('.').lower() for x in ans})
            except Exception:
                pass
            try:
                ans = await resolver.resolve(self.domain, 'MX')
                providers["mx"] = sorted({str(x.exchange).rstrip('.').lower() for x in ans if str(x.exchange) != '.'})
            except Exception:
                pass
        except Exception:
            pass
        try:
            async with self.sem:
                r = await self.client.get(self.base_url + "/")
            for txt in re.findall(r'(?i)v=spf1([^"\'>]+)', r.text + " " + " ".join(
                    v for k, v in r.headers.items() if 'spf' in str(v).lower())):
                for inc in re.findall(r'include:([\w.\-]+)', txt):
                    providers["spf_includes"].append(inc.lower())
        except Exception:
            pass

        # ---------- vendor rollup ----------
        vend = {}
        for rec in resources:
            if not rec.get("vendor"):
                continue
            v = vend.setdefault(rec["vendor"], {"name": rec["vendor"], "category": "?", "count": 0,
                                                "resources": [], "sri_missing": 0, "note": ""})
            v["count"] += 1
            if len(v["resources"]) < 6:
                v["resources"].append(rec["url"])
            if not rec.get("sri"):
                v["sri_missing"] += 1
        for name, _, cat, note in self.VENDORS:
            if name in vend and vend[name]["category"] == "?":
                vend[name]["category"] = cat
                vend[name]["note"] = note
        vendors = sorted(vend.values(), key=lambda x: -x["count"])

        # ---------- findings ----------
        exec_res = [r for r in resources if r["kind"] in ("script", "stylesheet")]
        no_sri = [r for r in exec_res if not r.get("sri")]
        unknown = [r for r in exec_res if r.get("vendor_known") is False]
        if exec_res and no_sri:
            sev = "HIGH" if unknown else "MEDIUM"
            findings.append((sev, "No Subresource Integrity",
                             f"{len(no_sri)}/{len(exec_res)} third-party executable resources lack SRI — "
                             f"a CDN/vendor compromise can inject code (add integrity=...)"))
        for r in unknown[:8]:
            findings.append(("HIGH", "Unknown third-party script source",
                             f"{r['kind']} loaded from unrecognized host: {r['url'][:100]}"))
        if ext_form_actions:
            for scheme, u in ext_form_actions[:6]:
                sev = "CRITICAL" if scheme == "http" else "MEDIUM"
                findings.append((sev, "Form submits to third party",
                                 f"form action → {u[:100]} (submitted data leaves this origin)"))
        scripts3p = [r for r in resources if r["kind"] == "script"]
        if scripts3p:
            try:
                hdrs = self.scalar_results.get('http_headers') or {}
                csp = hdrs.get('content-security-policy', '')
            except Exception:
                csp = ""
            if not csp:
                findings.append(("MEDIUM", "Third-party scripts without CSP",
                                 f"{len(scripts3p)} external scripts execute with no Content-Security-Policy"))
        iframes3p = [r for r in resources if r["kind"] == "iframe"]
        if iframes3p:
            findings.append(("INFO", "Third-party iframes",
                             f"{len(iframes3p)} external iframe(s): " +
                             ", ".join((r.get('vendor') or urlparse(r['url']).netloc) for r in iframes3p[:5])))
        self.results['supply'] = {
            "page": page_url,
            "vendors": vendors,
            "resources": resources[:60],
            "resources_total": len(resources),
            "third_party_exec": len(exec_res),
            "sri_missing": len(no_sri),
            "unknown_sources": [r["url"] for r in unknown],
            "external_form_actions": [u for _, u in ext_form_actions],
            "preconnect": preconnect,
            "providers": providers,
            "findings": findings,
        }

    # ---------------------------------------------------------- Asset Criticality Classification
    CRIT_WORDS = {
        "admin": 90, "administrator": 92, "login": 88, "signin": 85, "auth": 84, "sso": 90, "oauth": 82,
        "vpn": 86, "panel": 80, "dashboard": 76, "manage": 78, "console": 78, "cpanel": 88,
        "api": 70, "graphql": 68, "rest": 55, "pay": 90, "billing": 86, "checkout": 92, "cart": 74,
        "bank": 95, "db": 95, "sql": 90, "database": 92, "phpmyadmin": 97, "adminer": 95,
        "wp-admin": 92, "wp-login": 90, "mail": 78, "webmail": 86, "owa": 88, "exchange": 84,
        "staging": 72, "stage": 72, "dev": 60, "test": 56, "demo": 42, "beta": 56, "uat": 72,
        "sandbox": 66, "internal": 86, "intranet": 88, "portal": 76, "crm": 82, "erp": 86,
        "upload": 76, "backup": 92, "bak": 88, "grafana": 80, "jenkins": 86, "gitlab": 80,
        "gitea": 74, "kibana": 80, "elastic": 74, "k8s": 86, "kube": 86, "prometheus": 74,
        "monitor": 64, "metrics": 60, "status": 54, "shop": 76, "store": 76, "account": 76,
        "user": 60, "member": 66, "remote": 82, "gateway": 74, "jira": 76, "confluence": 76,
        "jenkins": 86, "sonar": 74, "registry": 78, "docker": 78, "harbor": 76, "backend": 74,
        "internal-api": 84, "cms": 66, "editor": 70, "config": 82, "setup": 76, "install": 80,
        "search": 40, "cdn": 40, "static": 30, "img": 28, "assets": 30, "blog": 32, "news": 34,
        "docs": 36, "doc": 36, "help": 40, "support": 52, "www": 46, "mail-in": 74, "smtp": 72,
        "autodiscover": 82, "secure": 74, "billing-api": 90,
    }
    CRIT_PORTS = {
        22: 72, 21: 66, 23: 88, 25: 56, 110: 70, 143: 70, 445: 92, 1433: 95, 3306: 96, 3389: 92,
        5432: 96, 5900: 76, 6379: 92, 8080: 54, 8443: 56, 8500: 82, 9090: 62, 9200: 86, 11211: 74,
        2375: 96, 2376: 90, 5672: 72, 9092: 72, 27017: 94, 11211: 74, 5984: 82, 15672: 76,
    }

    async def criticality_classify(self):
        """Rule-based criticality scoring (0-100) for discovered assets."""
        assets = {}      # name -> {score, tier, reasons, type}

        def add(name, atype, score, reason):
            if not name:
                return
            name = name.strip().lower().rstrip('.')
            if not name or name in ('-',):
                return
            a = assets.setdefault(name, {"asset": name, "type": atype, "score": 0, "reasons": []})
            if score > a["score"]:
                a["score"] = score
            if reason and reason not in a["reasons"] and len(a["reasons"]) < 5:
                a["reasons"].append(reason)

        # subdomains / host
        hosts = set()
        for s in self.results.get('subdomains', []):
            hosts.add(str(s).split(' ')[0].split(' -> ')[0].strip().lower())
        hosts.add(self.domain.lower())
        for h in hosts:
            labels = h.split('.')
            for lab in labels:
                for w, sc in self.CRIT_WORDS.items():
                    if w in lab:
                        add(h, "host", sc, f"keyword '{w}'")
                        break
        # main target baseline score
        add(self.domain, "target", 60, "primary target")

        # ports (against main host)
        for p in self.results.get('open_ports', []):
            try:
                port = int(str(p).split('/')[0])
            except Exception:
                continue
            if port in self.CRIT_PORTS:
                add(self.domain, "target", self.CRIT_PORTS[port], f"open risky port {port}")

        # paths
        for p in self.results.get('paths', []):
            if not isinstance(p, dict):
                continue
            path = str(p.get('path', ''))
            st = p.get('status')
            best = 0
            why = ""
            for w, sc in self.CRIT_WORDS.items():
                if w in path.lower() and sc > best:
                    best, why = sc, f"path keyword '{w}'"
            if best:
                add(f"{self.netloc}{path}", "path", best, why)
                if st == 200 and best >= 80:
                    add(f"{self.netloc}{path}", "path", min(best + 5, 100), "accessible (HTTP 200)")
                elif st in (401, 403) and best >= 70:
                    add(f"{self.netloc}{path}", "path", best, f"auth wall (HTTP {st})")

        # findings raise attached-asset score
        critical_findings = [f for f in (list(self.results.get('cve_findings', [])) +
                                         [(x[0], x[1], x[2], '') for x in self.results.get('ext_findings', [])
                                          if isinstance(x, (list, tuple)) and len(x) >= 3])
                             if isinstance(f, (list, tuple)) and len(f) >= 2 and f[0] in ('CRITICAL', 'HIGH')]
        if critical_findings:
            add(self.domain, "target", max(65, assets.get(self.domain, {}).get("score", 0)),
                f"{len(critical_findings)} critical/high findings attached")

        # tiers
        def tier(sc):
            if sc >= 80:
                return "CRITICAL"
            if sc >= 60:
                return "HIGH"
            if sc >= 35:
                return "MEDIUM"
            return "LOW"

        out = sorted(assets.values(), key=lambda x: (-x["score"], x["asset"]))
        for a in out:
            a["tier"] = tier(a["score"])
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in out:
            counts[a["tier"]] += 1
        self.results['criticality'] = {"assets": out[:150], "tiers": counts,
                                       "method": "rule-based scoring (keyword/port/finding signals, 0-100)"}

    # ---------------------------------------------------------- Behavioral Anomaly Detection (ML)
    async def anomaly_detection(self):
        """Lightweight unsupervised anomaly detection on HTTP response behaviour:
        content-hash clustering (soft-404), latency/size z-scores, IQR outliers, k-means (k=2)."""
        findings = []
        n_rand = 10 if self.deep else 6
        static_paths = ["", "index.html", "about", "contact", "products", "news", "login",
                        "images/", "assets/", "css/", "js/", "api/", "robots.txt", "favicon.ico",
                        "admin", "backup", "config", "sitemap.xml", ".git/HEAD", ".env"]
        rand_tokens = ["nv-a" + hashlib.md5(f"anom{i}".encode()).hexdigest()[:9] for i in range(n_rand)]
        probes = [(p, False) for p in static_paths[: (20 if self.deep else 14)]]
        probes += [(t, True) for t in rand_tokens]                    # known-nonexistent
        # add flagged/discovered paths if available (up to 10)
        for pd in [x for x in self.results.get('paths', []) if isinstance(x, dict)][:10]:
            u = str(pd.get('path', '')).lstrip('/')
            if u and (u, False) not in probes:
                probes.append((u, False))

        async def probe(path, is_random):
            url = urljoin(self.base_url + "/", path)
            t0 = time.time()
            try:
                async with self.sem:
                    r = await self.client.get(url, follow_redirects=True)
                latency = (time.time() - t0) * 1000
                body = r.text[:200_000]
                norm = re.sub(r'[a-f0-9]{8,}', '@', re.sub(r'\d+', '#', body.lower()))
                h = hashlib.sha1(norm.encode('utf-8', 'replace')).hexdigest()[:12]
                title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
                return {"path": path, "random": is_random, "status": r.status_code,
                        "size": len(r.content), "latency_ms": round(latency, 1),
                        "hash": h, "title": (title_m.group(1).strip()[:60] if title_m else ""),
                        "final_url": str(r.url)}
            except Exception:
                return None

        rows = [x for x in await asyncio.gather(*[probe(*p) for p in probes]) if x]
        if not rows:
            self.results['errors'].append("anomaly: no responses collected")
            return

        # ---------- soft-404 detection ----------
        rand_ok = [r for r in rows if r["random"] and r["status"] == 200]
        rand_total = len([r for r in rows if r["random"]])
        soft404 = bool(rand_total and len(rand_ok) / rand_total >= 0.5)
        masked = []
        if soft404:
            groups = defaultdict(list)
            for r in rows:
                if r["status"] == 200:
                    groups[r["hash"]].append(r)
            for h, members in groups.items():
                if any(m["random"] for m in members) and len(members) >= 3:
                    masked = members
                    findings.append(("MEDIUM", "Soft-404 behaviour",
                                     f"{len(members)} paths return an identical '200 OK' page "
                                     f"(hash {h}) even for random/nonexistent URLs — path discovery "
                                     f"will report false 200s"))
                    break
            if not masked:
                findings.append(("MEDIUM", "Soft-404 behaviour",
                                 f"{len(rand_ok)}/{rand_total} random nonexistent URLs returned HTTP 200"))
        elif rand_total:
            findings.append(("INFO", "Clean 404s ✅",
                             f"random URLs correctly return non-200 ({rand_total - len(rand_ok)}/{rand_total})"))

        # ---------- latency z-score ----------
        lats = [r["latency_ms"] for r in rows if r["latency_ms"] > 0]
        if len(lats) >= 6:
            mean = statistics.fmean(lats)
            sd = statistics.pstdev(lats) or 1.0
            slow = [r for r in rows if r["latency_ms"] and (r["latency_ms"] - mean) / sd > 3]
            for r in slow[:5]:
                findings.append(("LOW", "Latency outlier",
                                 f"{r['path']} took {r['latency_ms']}ms (z={(r['latency_ms'] - mean) / sd:.1f}) — "
                                 f"may be dynamic/behind extra processing"))
        # ---------- size IQR outliers (among same status) ----------
        by_status = defaultdict(list)
        for r in rows:
            by_status[r["status"]].append(r)
        for st, group in by_status.items():
            if len(group) < 6:
                continue
            sizes = sorted(x["size"] for x in group)
            q1 = statistics.median(sizes[:len(sizes) // 2]) or 0
            q3 = statistics.median(sizes[len(sizes) - len(sizes) // 2:]) or 0
            iqr = q3 - q1
            if iqr <= 0:
                continue
            for x in group:
                if x["size"] > q3 + 1.5 * iqr and x["size"] > 2000:
                    findings.append(("LOW", "Response-size outlier",
                                     f"{x['path']} returned {x['size']:,}B vs IQR fence {int(q3 + 1.5 * iqr):,}B (status {st})"))
        # ---------- status anomalies ----------
        for r in rows:
            if r["status"] >= 500:
                findings.append(("MEDIUM", "Server error response",
                                 f"{r['path']} → HTTP {r['status']} (server-side errors on probe)"))
            elif r["status"] in (401, 403) and not r["random"]:
                findings.append(("INFO", "Auth-gated path",
                                 f"{r['path']} → HTTP {r['status']}"))

        # ---------- k-means (k=2) on [status/100, log2(size), log2(latency)] ----------
        pts = []
        for r in rows:
            pts.append((r, [r["status"] / 100.0,
                            math.log2(r["size"] + 1),
                            math.log2(max(r["latency_ms"], 1.0))]))
        centroids = [pts[0][1][:], max(pts, key=lambda x: x[1][1])[1][:]]
        assign = [0] * len(pts)
        for _ in range(12):
            changed = False
            for i, (_, v) in enumerate(pts):
                d0 = sum((v[j] - centroids[0][j]) ** 2 for j in range(3))
                d1 = sum((v[j] - centroids[1][j]) ** 2 for j in range(3))
                a = 0 if d0 <= d1 else 1
                if a != assign[i]:
                    assign[i] = a
                    changed = True
            if not changed:
                break
            for k in (0, 1):
                members = [v for i, (_, v) in enumerate(pts) if assign[i] == k]
                if members:
                    centroids[k] = [sum(m[j] for m in members) / len(members) for j in range(3)]
        small = 0 if assign.count(0) <= assign.count(1) else 1
        outliers = [pts[i][0] for i, a in enumerate(assign) if a == small and assign.count(small) < len(pts) * 0.35]
        if outliers and len(outliers) <= max(6, len(pts) // 4):
            findings.append(("INFO", "k-means outlier cluster",
                             f"{len(outliers)} response(s) grouped as statistically distinct: " +
                             ", ".join(o["path"] for o in outliers[:6])))

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.results['anomaly'] = {
            "probed": len(rows),
            "soft404": soft404,
            "masked_paths": [m["path"] for m in masked][:40],
            "samples": rows[:80],
            "kmeans_outliers": [o["path"] for o in outliers][:20],
            "findings": sorted(findings, key=lambda x: sev_rank.get(x[0], 5)),
        }

    # ---------------------------------------------------------- Threat Intel Feeds
    async def threat_intel(self):
        """Keyless public feeds: AlienVault OTX, OpenPhish, SSLBL, Spamhaus Zen (DoH).
        Optional: ABUSEIPDB_KEY for AbuseIPDB check."""
        findings = []
        sources = []

        # ---------- IPs to check ----------
        ips = sorted({str(i) for i in self.results.get('ips', []) if str(i)})[:6]
        if not ips:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = self.timeout
                ans = await resolver.resolve(self.domain, 'A')
                ips = sorted({x.address for x in ans})[:6]
            except Exception:
                try:
                    async with httpx.AsyncClient(timeout=8) as c:
                        rr = await c.get("https://cloudflare-dns.com/dns-query",
                                         params={"name": self.domain, "type": "A"},
                                         headers={"Accept": "application/dns-json"})
                        ips = sorted({a["data"] for a in rr.json().get("Answer", [])
                                      if a.get("type") == 1})[:6]
                except Exception:
                    pass

        # ---------- 1) AlienVault OTX ----------
        for indicator, itype in ([(self.domain, "domain")] + [(ip, "IPv4") for ip in ips[:3]]):
            try:
                async with self.sem:
                    r = await self.client.get(
                        f"https://otx.alienvault.com/api/v1/indicators/{itype}/{indicator}/general",
                        timeout=15.0, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    data = r.json()
                    pc = data.get("pulse_info", {}).get("count", 0) or 0
                    pulse_names = [p.get("name", "") for p in
                                   (data.get("pulse_info", {}).get("pulses") or [])[:4]]
                    sources.append({"source": "AlienVault OTX", "target": indicator,
                                    "status": "listed" if pc else "clean",
                                    "detail": f"{pc} pulse(s)" + (": " + "; ".join(pulse_names) if pulse_names else "")})
                    if pc:
                        sev = "HIGH" if pc >= 5 else "MEDIUM"
                        findings.append((sev, "OTX pulse match",
                                         f"{indicator} appears in {pc} AlienVault threat pulse(s)"
                                         + (f" — {', '.join(pulse_names)}" if pulse_names else "")))
                    break       # OTX working → skip remaining retries
            except Exception:
                continue
        if not sources:
            sources.append({"source": "AlienVault OTX", "target": "-", "status": "unavailable",
                            "detail": "request failed (network/limits)"})

        # ---------- 2) OpenPhish phishing feed ----------
        try:
            async with self.sem:
                r = await self.client.get("https://openphish.com/feed.txt", timeout=20.0)
            if r.status_code == 200:
                hits = [ln.strip() for ln in r.text.splitlines()
                        if self.domain in ln.lower()][:5]
                total = len(r.text.splitlines())
                sources.append({"source": "OpenPhish", "target": self.domain,
                                "status": "listed" if hits else "clean",
                                "detail": f"{total} active phishing URLs scanned"})
                if hits:
                    findings.append(("CRITICAL", "Active phishing",
                                     f"{len(hits)} open phish URL(s) targeting this domain: {hits[0][:90]}"))
        except Exception:
            sources.append({"source": "OpenPhish", "target": "-", "status": "unavailable",
                            "detail": "feed download failed"})

        # ---------- 3) SSLBL (abuse.ch) IP blacklist ----------
        if ips:
            try:
                async with self.sem:
                    r = await self.client.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
                                              timeout=25.0)
                if r.status_code == 200:
                    text = r.text
                    hits = [ip for ip in ips if f'"{ip}"' in text]
                    sources.append({"source": "SSLBL", "target": ", ".join(ips),
                                    "status": "listed" if hits else "clean",
                                    "detail": "SSL cert blacklist scan"})
                    for ip in hits:
                        m = re.search(rf'"{re.escape(ip)}",\s*"([^"]+)"', text)
                        findings.append(("HIGH", "SSLBL listed IP",
                                         f"{ip} is on abuse.ch SSLBL as botnet C2"
                                         + (f" ({m.group(1)})" if m else "")))
            except Exception:
                sources.append({"source": "SSLBL", "target": "-", "status": "unavailable",
                                "detail": "blacklist download failed"})

        # ---------- 4) Spamhaus Zen via DoH ----------
        for ip in ips[:4]:
            try:
                if ':' in ip:
                    continue      # IPv6 reverse zones unsupported here
                rev = ".".join(reversed(ip.split('.')))
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.get("https://cloudflare-dns.com/dns-query",
                                    params={"name": f"{rev}.zen.spamhaus.org", "type": "TXT"},
                                    headers={"Accept": "application/dns-json"})
                answers = [a for a in r.json().get("Answer", []) if a.get("type") == 16]
                if not answers:
                    sources.append({"source": "Spamhaus Zen", "target": ip, "status": "clean",
                                    "detail": "no TXT answer (not listed)"})
                    continue
                data = str(answers[0].get("data", "")).strip('"')
                if data.startswith("127.255.255."):
                    sources.append({"source": "Spamhaus Zen", "target": ip, "status": "skipped",
                                    "detail": f"resolver refused ({data}) — public resolver not permitted"})
                elif data.startswith("127.0.0."):
                    code = data.split(".")[-1]
                    reasons = {"2": "explicit drop zone", "3": "CBL", "4": "DSBL",
                               "6": "systems compromised", "7": "house", "8": "SOULL",
                               "9": "CSS prefix/proxy", "10": "missing PTR"}
                    findings.append(("HIGH", "Spamhaus listed",
                                     f"{ip} listed in Spamhaus Zen (127.0.0.{code}"
                                     + (f": {reasons.get(code, 'listed')}" if code in reasons else "") + ")"))
                    sources.append({"source": "Spamhaus Zen", "target": ip, "status": "listed",
                                    "detail": data})
                else:
                    sources.append({"source": "Spamhaus Zen", "target": ip, "status": "clean",
                                    "detail": f"TXT {data[:40]}"})
            except Exception:
                sources.append({"source": "Spamhaus Zen", "target": ip, "status": "unavailable",
                                "detail": "DoH query failed"})

        # ---------- 5) AbuseIPDB (optional key) ----------
        key = os.environ.get("ABUSEIPDB_KEY", "").strip()
        if key and ips:
            try:
                async with self.sem:
                    r = await self.client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ips[0], "maxAgeInDays": 90},
                        headers={"Key": key, "Accept": "application/json"}, timeout=12.0)
                d = r.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                sources.append({"source": "AbuseIPDB", "target": ips[0], "status": "listed" if score else "clean",
                                "detail": f"{score}% confidence, {d.get('totalReports', 0)} reports"})
                if score >= 25:
                    findings.append(("HIGH", "AbuseIPDB reports",
                                     f"{ips[0]} has {score}% abuse confidence ({d.get('totalReports', 0)} reports, "
                                     f"usage: {d.get('usageType', '?')})"))
            except Exception:
                sources.append({"source": "AbuseIPDB", "target": ips[0], "status": "unavailable",
                                "detail": "check failed"})
        elif not key:
            sources.append({"source": "AbuseIPDB", "target": "-", "status": "skipped",
                            "detail": "set ABUSEIPDB_KEY to enable (optional)"})

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.results['intel'] = {"ips": ips, "sources": sources,
                                 "findings": sorted(findings, key=lambda x: sev_rank.get(x[0], 5))}

    # ---------------------------------------------------------- Breach / Credential Monitoring
    async def breach_monitor(self):
        """Domain/credential exposure monitoring via Have I Been Pwned (API key required for
        enumeration — free at haveibeenpwned.com/APIKey). Keyless mode reports setup guidance
        plus any phishing exposure already found in threat intel."""
        findings = []
        checks = []
        key = os.environ.get("HIBP_API_KEY", "").strip()
        breaches = []

        if not key:
            checks.append({
                "check": "HIBP API key",
                "status": "NOT CONFIGURED",
                "detail": "Set HIBP_API_KEY (free for non-commercial use at haveibeenpwned.com/APIKey) "
                          "to enable breach + credential monitoring",
            })
        else:
            # 1) domain breach enumeration
            try:
                async with self.sem:
                    r = await self.client.get(
                        "https://haveibeenpwned.com/api/v3/breaches",
                        params={"domain": self.domain},
                        headers={"hibp-api-key": key, "user-agent": "NULLVEIL-Recon"}, timeout=20.0)
                if r.status_code == 200:
                    data = r.json()
                    for b in data[:40]:
                        breaches.append({"name": b.get("Name"), "title": b.get("Title"),
                                         "date": b.get("BreachDate"),
                                         "pwn_count": b.get("PwnCount"),
                                         "classes": (b.get("DataClasses") or [])[:8],
                                         "verified": b.get("IsVerified")})
                    checks.append({"check": "Domain breach records (HIBP)", "status": "OK",
                                   "detail": f"{len(breaches)} breach record(s) matched to {self.domain}"})
                    for b in breaches[:12]:
                        findings.append(("CRITICAL" if (b["pwn_count"] or 0) >= 1_000_000 else "HIGH",
                                         "Breach exposure",
                                         f"{b['title']} ({b['date']}) — {b['pwn_count']:,} accounts, "
                                         f"data: {', '.join(b['classes']) or 'n/a'}"))
                elif r.status_code == 401:
                    checks.append({"check": "HIBP API key", "status": "INVALID",
                                   "detail": "HIBP rejected the key (401) — check HIBP_API_KEY"})
                else:
                    checks.append({"check": "Domain breach records (HIBP)", "status": "ERROR",
                                   "detail": f"HTTP {r.status_code}"})
            except Exception as e:
                checks.append({"check": "Domain breach records (HIBP)", "status": "ERROR",
                               "detail": type(e).__name__})

            # 2) harvested target emails (module 6/12) — exposure check, capped
            emails = [e for e in sorted(set(self.results.get('emails', [])))
                      if re.match(r'^[\w.+\-]+@[\w.\-]+\.\w{2,}$', str(e))][:10]
            for em in emails:
                try:
                    async with self.sem:
                        r = await self.client.get(
                            f"https://haveibeenpwned.com/api/v3/breachedaccount/{em}",
                            params={"truncateResponse": "true"},
                            headers={"hibp-api-key": key, "user-agent": "NULLVEIL-Recon"}, timeout=15.0)
                    if r.status_code == 200:
                        names = [b.get("Name") for b in r.json()][:10]
                        findings.append(("HIGH", "Email in breaches",
                                         f"{em} found in {len(names)} breach(es): {', '.join(names)}"))
                    elif r.status_code == 404:
                        pass      # not found — good
                    elif r.status_code == 429:
                        checks.append({"check": "Email enumeration", "status": "RATE LIMITED",
                                       "detail": "HIBP throttled — remaining emails skipped"})
                        break
                except Exception:
                    pass
            if emails:
                checks.append({"check": "Email enumeration (HIBP)", "status": "OK",
                               "detail": f"{len(emails)} harvested target email(s) checked"})

        # 3) keyless: re-surface phishing exposure from threat intel if present
        for f in self.results.get('intel', {}).get('findings', []):
            if isinstance(f, (list, tuple)) and len(f) == 3 and f[1] == "Active phishing":
                findings.append(f)      # (severity, check, detail) — same shape as ours
        if not key and not findings:
            findings.append(("INFO", "Monitoring not active",
                             "Breach/credential monitoring needs a free HIBP_API_KEY — "
                             "dark-web marketplace scraping is intentionally not performed"))

        self.results['breach'] = {"key_present": bool(key), "provider": "Have I Been Pwned",
                                  "checks": checks, "breaches": breaches,
                                  "findings": findings}

    # ---------------------------------------------------------- Compliance Mapping
    async def compliance_map(self):
        """Map collected technical evidence to PCI-DSS v4.0 / ISO 27001:2022 Annex A / SOC 2 TSC.
        Evidence-based partial assessment only — NOT a certification or audit."""
        ran = {ATTACK_MODULES[i - 1][0] for i in self.attack_set if 0 < i <= MAX_MODULE}
        ev = {}
        # TLS / crypto
        tls_m = self.results.get('tls_matrix', [])
        ev['tls_run'] = bool(tls_m)
        ev['tls10'] = any(m[0] == "TLS 1.0" and m[1] == "yes" for m in tls_m)
        ev['tls11'] = any(m[0] == "TLS 1.1" and m[1] == "yes" for m in tls_m)
        ev['tls12'] = any(m[0] == "TLS 1.2" and m[1] == "yes" for m in tls_m)
        ev['tls13'] = any(m[0] == "TLS 1.3" and m[1] == "yes" for m in tls_m)
        ev['weak_crypto'] = any(f[1] in ("Weak cipher", "Short RSA key", "Short EC key",
                                         "Weak cert signature", "No TLS 1.3") and f[0] in ("HIGH", "CRITICAL")
                                for f in self.results.get('tls_findings', []))
        ev['no_legacy_tls'] = ev['tls_run'] and not ev['tls10'] and not ev['tls11']
        # headers
        ev['http_run'] = 'http' in ran
        ev['hdr_present'] = len(self.results.get('security_headers', []))
        ev['hdr_missing'] = len(self.results.get('missing_security_headers', []))
        ev['hsts'] = any('strict-transport-security' in h for h in self.results.get('security_headers', []))
        ev['csp'] = any('content-security-policy' in h for h in self.results.get('security_headers', []))
        # vulnerabilities / exposure
        ev['cve_run'] = 'cve' in ran
        cve_high = [f for f in self.results.get('cve_findings', []) if f[0] in ('CRITICAL', 'HIGH')]
        cve_med = [f for f in self.results.get('cve_findings', []) if f[0] == 'MEDIUM']
        ev['vuln_high'] = len(cve_high)
        ev['vuln_med'] = len(cve_med)
        ev['exposed_debug'] = any(f[1] in ('Exposed .git', 'Exposed .env', 'Exposed .svn', 'phpinfo()',
                                           'Heapdump', 'Spring Actuator /env', 'Apache server-status',
                                           'Apache server-info', 'Directory Listing', 'web.config',
                                           'H2 Console', 'Laravel Ignition')
                                  for f in self.results.get('cve_findings', []))
        ev['secrets_found'] = len(self.results.get('secrets', []))
        ev['secrets_run'] = 'content' in ran
        # email auth
        ev['email_run'] = 'email' in ran
        ev['spf'] = bool(self.results.get('spf', ''))
        ev['dmarc'] = bool(self.results.get('dmarc', ''))
        ev['dmarc_enforce'] = str(self.results.get('dmarc_policy', '')).lower() in ('reject', 'quarantine')
        # API audit
        ev['audit_run'] = 'audit' in ran
        audit = self.results.get('api_audit_findings', [])
        ev['audit_high'] = len([f for f in audit if f[0] in ('CRITICAL', 'HIGH')])
        # supply chain
        ev['supply_run'] = 'supply' in ran
        sup = self.results.get('supply', {})
        ev['sri_missing'] = sup.get('sri_missing', 0)
        ev['third_party_exec'] = sup.get('third_party_exec', 0)
        # threat intel / breach
        ev['intel_run'] = 'intel' in ran
        ev['intel_listed'] = len([f for f in self.results.get('intel', {}).get('findings', [])
                                  if f[0] in ('CRITICAL', 'HIGH')])
        ev['breach_run'] = 'breach' in ran
        ev['breach_findings'] = len([f for f in self.results.get('breach', {}).get('findings', [])
                                     if f[0] in ('CRITICAL', 'HIGH')])
        # anomaly
        ev['anom_run'] = 'anom' in ran
        ev['soft404'] = self.results.get('anomaly', {}).get('soft404', False)
        # criticality
        crit = self.results.get('criticality', {})
        ev['assets_classified'] = len(crit.get('assets', []))

        YES, NO, PART, NEED = "PASS", "FAIL", "PARTIAL", "EVIDENCE REQUIRED"

        def run(key):
            return key in ran

        # (framework, ref, title, fn(ev)->(status, evidence))
        CONTROLS = [
            # ---------------- PCI-DSS v4.0 ----------------
            ("PCI-DSS v4.0", "2.2.5", "System components have only necessary functions enabled",
             lambda e: (NO, "debug/admin surfaces exposed (.git/.env/actuator/phpinfo/server-status)")
             if e['exposed_debug'] else
             (PART, f"{e['hdr_missing']} security headers missing") if run('http') and e['hdr_missing'] else
             (YES, "no exposed debug/config surfaces in probe scope") if e['cve_run'] else (NEED, "run -a cve,http")),
            ("PCI-DSS v4.0", "4.2.1", "Strong cryptography protects cardholder data in transit",
             lambda e: (NO, "legacy TLS 1.0/1.1 accepted") if e['tls10'] or e['tls11'] else
             (NO, "weak crypto negotiated") if e['weak_crypto'] else
             (YES, "TLS 1.2+ only, modern ciphers") if e['tls_run'] else (NEED, "run -a tls")),
            ("PCI-DSS v4.0", "6.2.4", "Secure coding techniques mitigate common software attacks",
             lambda e: (PART, f"CSP: {'yes' if e['csp'] else 'missing'}; "
                              f"reflected params / XSS candidates reported separately") if e['http_run'] else (NEED, "run -a http,crawl")),
            ("PCI-DSS v4.0", "6.3.1", "Vulnerabilities are identified and remediated",
             lambda e: (NO, f"{e['vuln_high']} critical/high finding(s)") if e['vuln_high'] else
             (PART, f"{e['vuln_med']} medium finding(s)") if e['vuln_med'] else
             (YES, "no critical/high CVE-class findings") if e['cve_run'] else (NEED, "run -a cve")),
            ("PCI-DSS v4.0", "6.5.1", "Software engineering techniques prevent code injection",
             lambda e: (NO, "insecure config surfaces (.git/.env) leak code/config") if e['exposed_debug'] else
             (PART, "no CSP/secret-scan baseline available") if not run('content') else (YES, "no exposed source/config"),),
            ("PCI-DSS v4.0", "8.4.2", "MFA for all access into the CDE",
             lambda e: (PART, f"API auth findings: {e['audit_high']} high/critical (MFA itself not network-testable)")
             if e['audit_run'] else (NEED, "MFA is org-policy evidence; run -a audit for API auth posture")),
            ("PCI-DSS v4.0", "10.2.1", "Audit logs capture all access to network resources",
             lambda e: (NEED, "log pipeline is organizational evidence — not assessable externally")),
            ("PCI-DSS v4.0", "11.3.1", "Internal/external vulnerability scans performed",
             lambda e: (YES, f"this scan = technical evidence ({e['cve_run'] and 'cve module run' or 'partial'})")
             if e['cve_run'] else (PART, "recon-only; schedule authenticated ASV scans")),
            ("PCI-DSS v4.0", "12.8.5", "Third-party service provider management",
             lambda e: (PART, f"{e['third_party_exec']} third-party executable resources; "
                              f"SRI missing on {e['sri_missing']}") if e['supply_run'] else (NEED, "run -a supply")),
            # ---------------- ISO 27001:2022 (Annex A) ----------------
            ("ISO 27001:2022", "A.5.10", "Inventory of information and associated assets",
             lambda e: (YES, f"{e['assets_classified']} assets classified + subdomains/ports inventoried")
             if e['assets_classified'] else (PART, "run -a crit to classify the inventory")),
            ("ISO 27001:2022", "A.5.15", "Access control",
             lambda e: (NO, f"{e['audit_high']} high/critical API auth/access findings") if e['audit_high'] else
             (PART, "external view only — run -a audit") if e['audit_run'] else (NEED, "run -a audit")),
            ("ISO 27001:2022", "A.5.16", "Identity management",
             lambda e: (PART, "user/author enumeration results in -a users report") if run('users') else (NEED, "run -a users")),
            ("ISO 27001:2022", "A.5.7", "Threat intelligence",
             lambda e: (NO, f"{e['intel_listed']} malicious listing(s) on public feeds") if e['intel_listed'] else
             (YES, "feeds checked, no listings") if e['intel_run'] else (NEED, "run -a intel")),
            ("ISO 27001:2022", "A.5.23", "Information security for cloud services",
             lambda e: (PART, "cloud/CDN providers identified in -a supply") if e['supply_run'] else (NEED, "run -a supply")),
            ("ISO 27001:2022", "A.5.29", "Information security during supplier development",
             lambda e: (NO, "third-party executable code without SRI") if e['sri_missing'] else
             (YES, "third-party scripts carry integrity checks") if e['supply_run'] else (NEED, "run -a supply")),
            ("ISO 27001:2022", "A.8.8", "Management of technical vulnerabilities",
             lambda e: (NO, f"{e['vuln_high']} critical/high vulnerabilities identified") if e['vuln_high'] else
             (PART, f"{e['vuln_med']} medium finding(s)") if e['vuln_med'] else
             (YES, "no critical/high vulnerabilities in scope") if e['cve_run'] else (NEED, "run -a cve")),
            ("ISO 27001:2022", "A.8.9", "Configuration management",
             lambda e: (NO, "debug/directory-listing/server-status surfaces exposed") if e['exposed_debug'] else
             (PART, "headers baseline only") if e['http_run'] else (NEED, "run -a cve,http")),
            ("ISO 27001:2022", "A.8.16", "Monitoring activities",
             lambda e: (PART, "external monitoring evidence: threat feeds + anomaly module")
             if e['intel_run'] or e['anom_run'] else (NEED, "run -a intel,anom")),
            ("ISO 27001:2022", "A.8.19", "Installation of software on operational systems",
             lambda e: (PART, f"soft-404 masking {'present' if e['soft404'] else 'absent'} in probe baseline")
             if e['anom_run'] else (NEED, "run -a anom")),
            ("ISO 27001:2022", "A.8.24", "Use of cryptography",
             lambda e: (NO, "legacy TLS/weak ciphers enabled") if (e['tls10'] or e['tls11'] or e['weak_crypto']) else
             (YES, "TLS 1.2+ with modern cipher suites") if e['tls_run'] else (NEED, "run -a tls")),
            ("ISO 27001:2022", "A.8.26", "Application security requirements",
             lambda e: (PART, f"security headers present: {e['hdr_present']}, missing: {e['hdr_missing']}")
             if e['http_run'] else (NEED, "run -a http")),
            ("ISO 27001:2022", "A.5.14", "Information transfer",
             lambda e: (NO, "form submits data to third-party origin") if
             any(f[1] == "Form submits to third party" for f in sup.get('findings', [])) else
             (PART, "email transport auth (SPF/DMARC) reviewed") if e['email_run'] else (NEED, "run -a email,supply")),
            # ---------------- SOC 2 TSC ----------------
            ("SOC 2 TSC", "CC6.1", "Logical access security software / infrastructure",
             lambda e: (NO, f"{e['audit_high']} unprotected/weak-auth API endpoints") if e['audit_high'] else
             (PART, "external API posture only") if e['audit_run'] else (NEED, "run -a audit")),
            ("SOC 2 TSC", "CC6.6", "Threats outside system boundaries",
             lambda e: (NO, "legacy TLS accepted — boundary encryption weakened") if (e['tls10'] or e['tls11']) else
             (YES, "modern TLS baseline") if e['tls_run'] else (NEED, "run -a tls")),
            ("SOC 2 TSC", "CC6.7", "Transmission and movement of data",
             lambda e: (NO, "cleartext (http) third-party form action") if
             any(f[0] == "CRITICAL" and f[1] == "Form submits to third party" for f in sup.get('findings', [])) else
             (YES, "no cleartext third-party submission found") if e['supply_run'] else (NEED, "run -a supply")),
            ("SOC 2 TSC", "CC7.1", "Detection of configuration events / vulnerabilities",
             lambda e: (PART, f"feeds checked: {'listed' if e['intel_listed'] else 'clean'}") if e['intel_run'] else (NEED, "run -a intel,cve")),
            ("SOC 2 TSC", "CC7.2", "Monitoring for anomalies",
             lambda e: (YES, "anomaly baseline computed (soft-404/latency/size/k-means)") if e['anom_run']
             else (NEED, "run -a anom")),
            ("SOC 2 TSC", "CC8.1", "Change management",
             lambda e: (PART, "exposed staging/dev/test subdomains indicate unmanaged environments") if
             any(re.search(r'(?i)(staging|stage|dev|test|uat|sandbox)', a.get('asset', ''))
                 for a in crit.get('assets', [])) else
             (YES, "no staging/dev hosts flagged") if e['assets_classified'] else (NEED, "run -a crit")),
            ("SOC 2 TSC", "CC9.2", "Vendor and business partner risk",
             lambda e: (PART, f"{e['third_party_exec']} third-party resources, SRI gaps: {e['sri_missing']}")
             if e['supply_run'] else (NEED, "run -a supply")),
            ("SOC 2 TSC", "C1.1", "Encryption in transit",
             lambda e: (NO, "weak/legacy transport crypto") if (e['tls10'] or e['tls11'] or e['weak_crypto']) else
             (YES, "TLS 1.2+ enforced in tested handshakes") if e['tls_run'] else (NEED, "run -a tls")),
            ("SOC 2 TSC", "P4.2", "Disposal of data / sensitive data exposure",
             lambda e: (NO, f"{e['secrets_found']} secret/leak indicator(s) in public content") if e['secrets_found'] else
             (YES, "no secret patterns in public content") if e['secrets_run'] else (NEED, "run -a content")),
        ]

        frameworks = defaultdict(lambda: {"pass": 0, "fail": 0, "partial": 0, "needed": 0, "controls": []})
        for fw, ref, title, fn in CONTROLS:
            try:
                status, evid = fn(ev)
            except Exception:
                status, evid = NEED, "error evaluating evidence"
            rec = {"ref": ref, "title": title, "status": status, "evidence": evid}
            frameworks[fw]["controls"].append(rec)
            if status == YES:
                frameworks[fw]["pass"] += 1
            elif status == NO:
                frameworks[fw]["fail"] += 1
            elif status == PART:
                frameworks[fw]["partial"] += 1
            else:
                frameworks[fw]["needed"] += 1
        total_c = sum(len(v["controls"]) for v in frameworks.values())
        assessable = sum(v["pass"] + v["fail"] + v["partial"] for v in frameworks.values())
        fails = sum(v["fail"] for v in frameworks.values())
        coverage = round(100 * assessable / total_c) if total_c else 0
        self.results['compliance'] = {
            "frameworks": {k: dict(v) for k, v in frameworks.items()},
            "coverage_pct": coverage,
            "total_controls": total_c,
            "total_fail": fails,
            "disclaimer": ("Evidence-based partial technical mapping only. This is NOT a certification, "
                           "audit, or gap assessment — most controls require organizational evidence "
                           "(policies, contracts, logs, personnel). Use as input to a real audit program."),
        }

    # ---------------------------------------------------------- Attack Path Graph + Chain Hypotheses
    CHAIN_RULES = [
        # (id, title, required fact keys, narrative steps, impact, confidence)
        ("src-to-creds", "Source/config disclosure → credential replay",
         ["exposed_git_or_env"],
         ["{target} serves repository/environment files publicly",
          "history & config likely contain keys, tokens, DB credentials",
          "recovered credentials replayed against login/admin surfaces"],
         "Full account or database compromise", "HIGH (facts confirmed)"),
        ("takeover-session", "Dangling subdomain takeover → session/token theft",
         ["takeover"],
         ["DNS points {takeover} at an unclaimed service",
          "attacker claims the host and serves content on your domain",
          "same-site cookies/tokens scoped to parent domain become reachable"],
         "Session hijack / SSO abuse on parent domain", "MEDIUM — verify ownership first"),
        ("cors-auth-bypass", "CORS reflection + credentials → cross-origin data theft",
         ["cors_reflect_creds"],
         ["API reflects arbitrary Origin with Access-Control-Allow-Credentials: true",
          "authenticated browser sessions permit cross-origin reads",
          "victim data exfiltrated by a malicious page while logged in"],
         "Authenticated data theft at scale", "HIGH (headers observed)"),
        ("verbose-error-recon", "Verbose errors → internal recon → targeted exploit",
         ["verbose_errors"],
         ["stack traces/DB errors expose versions, paths, framework internals",
          "internal topology & versions mapped without access",
          "combined with known-version CVEs → focused exploitation"],
         "Accelerated intrusion path", "MEDIUM — depends on disclosed detail"),
        ("xss-chain", "Reflected input + weak headers → account takeover chain",
         ["reflected_param", "no_csp"],
         ["parameter echo found (no output encoding evidence)",
          "no CSP to constrain injected script",
          "successful XSS steals session tokens / performs actions as victim"],
         "Account takeover via victim browser", "MEDIUM — payload not executed (manual verification)"),
        ("transport-intercept", "Legacy TLS → MITM of session cookies",
         ["legacy_tls"],
         ["TLS 1.0/1.1 or weak cipher accepted",
          "network attacker downgrades/intercepts transport",
          "session cookies / credentials captured in transit"],
         "Credential & session interception", "HIGH (handshake observed)"),
        ("supply-inject", "Third-party script without SRI → supply-chain execution",
         ["thirdparty_no_sri"],
         ["executable script loaded from third party without integrity pin",
          "compromised CDN/vendor can run arbitrary JS on your origin",
          "script runs with full same-origin privileges (cookies, DOM, API calls)"],
         "Mass client-side compromise", "MEDIUM — requires vendor incident"),
        ("exposed-ops-surface", "Exposed ops/debug surface → server takeover primitive",
         ["exposed_ops"],
         ["ops endpoints reachable (heapdump/actuator/phpinfo/h2/server-status)",
          "memory/config/secrets recovered from dumps or verbose output",
          "recovered secrets feed directly into admin access attempts"],
         "Server-side compromise path", "HIGH — reachable ops surface confirmed"),
        ("open-redirect-login", "Open/insecure auth flow → credential harvesting",
         ["auth_weak"],
         ["API auth weaknesses detected (missing/expired token checks)",
          "auth flows abusable for token forgery or brute force staging",
          "harvested credentials reused across services (password spraying)"],
         "Unauthorized access to protected resources", "MEDIUM — depends on exact weakness"),
    ]

    async def attack_graph(self):
        """Build asset/finding graph, enumerate attack paths (BFS), generate chain hypotheses.
        Report-only: no exploitation is performed or simulated beyond narrative reasoning."""
        nodes = {}
        edges = []

        def node(nid, label, ntype, sev="INFO", score=None):
            if nid not in nodes:
                nodes[nid] = {"id": nid, "label": label[:60], "type": ntype,
                              "sev": sev, "score": score}
            return nid

        def edge(a, b, rel):
            if a and b and a != b:
                edges.append({"from": a, "to": b, "rel": rel})

        critmap = {a["asset"]: a for a in self.results.get('criticality', {}).get('assets', [])}
        tid = node("host:" + self.domain, self.domain, "target",
                   score=critmap.get(self.domain, {}).get("score", 60))

        # subdomains + IPs
        for s in list(self.results.get('subdomains', []))[:120]:
            host = str(s).split(' ')[0].split(' -> ')[0].strip().lower()
            if not host or host == self.domain:
                continue
            c = critmap.get(host, {})
            sid = node("host:" + host, host, "subdomain",
                       sev="HIGH" if c.get("tier") in ("CRITICAL", "HIGH") else "INFO",
                       score=c.get("score"))
            edge(tid, sid, "exposes")
            m = re.search(r'->\s*([\d.]+)', str(s))
            if m:
                ipid = node("ip:" + m.group(1), m.group(1), "ip")
                edge(sid, ipid, "resolves-to")
        for ip in [str(x) for x in self.results.get('ips', [])][:12]:
            edge(tid, node("ip:" + ip, ip, "ip"), "resolves-to")

        # ports on target
        for p in self.results.get('open_ports', []):
            port = str(p).split('/')[0]
            pscore = self.CRIT_PORTS.get(int(port), 40) if port.isdigit() else 40
            pid = node(f"port:{port}", f":{port}", "port",
                       sev="HIGH" if pscore >= 80 else "INFO", score=pscore)
            edge(tid, pid, "listens")

        # flagged paths
        for pd in [x for x in self.results.get('paths', []) if isinstance(x, dict)][:60]:
            if not (pd.get('flagged') or pd.get('status') in (401, 403)):
                continue
            pth = str(pd.get('path'))
            pnode = node("path:" + pth, pth, "path", sev="HIGH" if pd.get('flagged') else "INFO")
            edge(tid, pnode, "hosts")

        # findings nodes
        all_findings = []
        all_findings += [(f[0], f[1], f[3] if len(f) > 3 else "", "cve") for f in self.results.get('cve_findings', [])]
        all_findings += [(f[0], f[1], f[2], "ext") for f in self.results.get('ext_findings', [])]
        all_findings += [(f[0], f[1], f[2], "audit") for f in self.results.get('api_audit_findings', [])]
        all_findings += [(f[0], f[1], f[2], "tls") for f in self.results.get('tls_findings', [])]
        all_findings += [(f[0], f[1], f[2], "supply") for f in self.results.get('supply', {}).get('findings', [])]
        all_findings += [(f[0], f[1], f[2], "intel") for f in self.results.get('intel', {}).get('findings', [])]
        for sev, fid, det, src in all_findings:
            if sev in ("CRITICAL", "HIGH"):
                fnode = node("find:" + fid, fid, "finding", sev=sev)
                edge(tid, fnode, f"has-finding ({src})")

        # ---------- facts for chain rules ----------
        cve_ids = {f[1] for f in self.results.get('cve_findings', [])}
        audit_ids = {f[1] for f in self.results.get('api_audit_findings', [])}
        ext_ids = {f[1] for f in self.results.get('ext_findings', [])}
        sup_find = self.results.get('supply', {}).get('findings', [])
        facts = {
            "exposed_git_or_env": bool(cve_ids & {'Exposed .git', 'Exposed .env', 'Exposed .svn'}) or self.results.get('secrets'),
            "takeover": bool(self.results.get('takeover')),
            "cors_reflect_creds": any("CORS" in str(a) and "credential" in str(a).lower()
                                      for a in audit_ids) or any("CORS" in str(a) for a in audit_ids),
            "verbose_errors": any("verbose" in str(a).lower() or "stack" in str(a).lower()
                                  or "error" in str(a).lower() for a in audit_ids),
            "reflected_param": bool(self.results.get('reflected_params')),
            "no_csp": 'content-security-policy' in [h.lower() for h in self.results.get('missing_security_headers', [])],
            "legacy_tls": any(f[1] in ("TLS 1.0 enabled", "TLS 1.1 enabled")
                              for f in self.results.get('tls_findings', [])),
            "thirdparty_no_sri": any(f[1] == "No Subresource Integrity" for f in sup_find),
            "exposed_ops": bool(cve_ids & {'phpinfo()', 'Heapdump', 'Spring Actuator /env',
                                           'Apache server-status', 'Apache server-info', 'H2 Console',
                                           'Laravel Ignition', 'Directory Listing'}),
            "auth_weak": bool(audit_ids & {'Missing auth on endpoint', 'Weak/expired token acceptance',
                                           'Broken object-level auth (BOLA)'}),
        }
        facts["takeover"] = facts["takeover"] or any("Takeover" in t for t in ext_ids)

        # ---------- chain hypotheses ----------
        tk = self.results.get('takeover', [])
        tk_name = tk[0].split(' ')[0] if tk else self.domain
        chains = []
        for cid, title, req, steps, impact, conf in self.CHAIN_RULES:
            if not all(facts.get(k) for k in req):
                continue
            narrative = [s.format(target=self.domain, takeover=tk_name) for s in steps]
            sev = "CRITICAL" if conf.startswith("HIGH") and cid in (
                "src-to-creds", "cors-auth-bypass", "exposed-ops-surface") else "HIGH"
            chains.append({"id": cid, "severity": sev, "title": title, "steps": narrative,
                           "impact": impact, "confidence": conf,
                           "action": "Validate manually on an authorized target; remediate the first step "
                                     "to break the chain."})
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        chains.sort(key=lambda c: (sev_rank.get(c["severity"], 3), c["id"]))

        # ---------- BFS attack paths (entry → crown jewels) ----------
        adj = defaultdict(set)
        for e in edges:
            adj[e["from"]].add(e["to"])
            adj[e["to"]].add(e["from"])
        entries = [nid for nid, n in nodes.items()
                   if (n["type"] == "finding" and n["sev"] in ("CRITICAL", "HIGH"))
                   or (n["type"] == "path" and n["sev"] == "HIGH")]
        crowns = [nid for nid, n in nodes.items()
                  if n["type"] == "target" or (n.get("score") or 0) >= 80]
        paths = []
        seen_paths = set()
        for src in entries[:12]:
            queue = deque([(src, [src])])
            hops = 0
            while queue and hops < 400:
                hops += 1
                cur, path = queue.popleft()
                if len(path) > 5:
                    continue
                for nxt in adj.get(cur, ()):
                    if nxt in path:
                        continue
                    newp = path + [nxt]
                    if nxt in crowns:
                        key = tuple(newp)
                        if key not in seen_paths:
                            seen_paths.add(key)
                            paths.append(newp)
                    else:
                        queue.append((nxt, newp))
                if len(paths) >= 15:
                    break
            if len(paths) >= 15:
                break
        attack_paths = []
        for p in paths[:15]:
            labels = [nodes[x]["label"] for x in p]
            worst = max((nodes[x].get("sev") == "CRITICAL" and 3 or
                         nodes[x].get("sev") == "HIGH" and 2 or 1) for x in p)
            attack_paths.append({"hops": labels,
                                 "severity": "CRITICAL" if worst >= 3 and len(p) >= 3 else
                                             ("HIGH" if worst >= 2 else "MEDIUM"),
                                 "length": len(p)})

        # ---------- DOT export ----------
        colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
                  "LOW": "#38bdf8", "INFO": "#94a3b8"}
        dot = ["digraph NULLVEIL {", "  rankdir=LR;", '  node [shape=box, style="rounded,filled", '
                                                     'fontname="Helvetica", fontsize=10];']
        for n in nodes.values():
            fill = colors.get(n["sev"], "#94a3b8")
            label = n["label"].replace('"', "'")
            dot.append(f'  "{n["id"]}" [label="{label}\\n({n["type"]})" fillcolor="{fill}"];')
        for e in edges:
            dot.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["rel"]}"];')
        dot.append("}")
        dot_text = "\n".join(dot)
        if getattr(self, "dot_path", None):
            try:
                with open(self.dot_path, "w", encoding="utf-8") as fh:
                    fh.write(dot_text)
            except Exception as e:
                self.results['errors'].append(f"dot export failed: {e}")

        self.results['graph'] = {
            "nodes": list(nodes.values()),
            "edges": edges[:400],
            "node_count": len(nodes),
            "edge_count": len(edges),
            "facts": {k: bool(v) for k, v in facts.items()},
            "attack_paths": attack_paths,
            "chains": chains,
            "dot_exported": bool(getattr(self, "dot_path", None)),
        }

    # ---------------------------------------------------------- Multi-Target / Cross-Org Correlation
    async def correlate_targets(self):
        """Correlate the primary target with related/extra domains (own estate):
        shared NS / MX / IP / CDN / cert-SAN → relationship matrix.
        Extra domains come from --correlate or are auto-derived from certificate SANs."""

        def apex(host):
            parts = str(host).lower().rstrip('.').split('.')
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return str(host).lower()

        # ---------- gather candidate targets ----------
        explicit = []
        for d in str(getattr(self, "correlate_list", "") or "").split(","):
            d = d.strip().lower().lstrip("*.")
            if d and d not in explicit:
                explicit.append(d)
        auto = []
        for san in self.scalar_results.get('ssl_san', []) or []:
            a = apex(re.sub(r'^\*', '', str(san)))
            if a and a != apex(self.domain) and a not in auto:
                auto.append(a)
        auto = auto[:4]
        extra = [t for t in explicit if t != self.domain][:7]
        targets = list(dict.fromkeys([self.domain] + auto + extra))[:9]
        if len(targets) <= 1 and not explicit:
            self.results['correlation'] = {
                "targets": [{"domain": self.domain, "ns": [], "mx": [], "ips": [], "title": "",
                             "server": "", "note": "primary"}],
                "links": [], "findings": [],
                "note": "no related domains found (cert SANs are single-org) — "
                        "use --correlate a.com,b.com to compare your own domains",
            }
            return

        # ---------- light profile per target ----------
        async def profile(dom):
            info = {"domain": dom, "ns": [], "mx": [], "ips": [], "title": "", "server": "", "error": ""}
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = min(self.timeout, 8)
                for rtype, key in (("NS", "ns"), ("MX", "mx"), ("A", "ips")):
                    try:
                        ans = await resolver.resolve(dom, rtype)
                        if rtype == "NS":
                            info[key] = sorted({str(x.target).rstrip('.').lower() for x in ans})
                        elif rtype == "MX":
                            info[key] = sorted({str(x.exchange).rstrip('.').lower()
                                                for x in ans if str(x.exchange) != '.'})[:4]
                        else:
                            info[key] = sorted({x.address for x in ans})[:4]
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                async with self.sem:
                    r = await self.client.get(f"https://{dom}/", follow_redirects=True, timeout=12.0)
                info["server"] = str(r.headers.get("server", ""))[:40]
                m = re.search(r'<title[^>]*>(.*?)</title>', r.text[:200_000], re.I | re.S)
                if m:
                    info["title"] = m.group(1).strip()[:70]
            except Exception:
                try:
                    async with self.sem:
                        r = await self.client.get(f"http://{dom}/", follow_redirects=True, timeout=12.0)
                    info["server"] = str(r.headers.get("server", ""))[:40]
                    m = re.search(r'<title[^>]*>(.*?)</title>', r.text[:200_000], re.I | re.S)
                    if m:
                        info["title"] = m.group(1).strip()[:70]
                except Exception as e:
                    info["error"] = type(e).__name__
            return info

        profiles = await asyncio.gather(*[profile(d) for d in targets])

        # ---------- pairwise correlation ----------
        findings = []
        links = []
        for i in range(len(profiles)):
            for j in range(i + 1, len(profiles)):
                a, b = profiles[i], profiles[j]
                shared = {}
                for key, label in (("ns", "nameservers"), ("mx", "mail providers"),
                                   ("ips", "IP addresses")):
                    common = sorted(set(a.get(key, [])) & set(b.get(key, [])))
                    if common:
                        shared[label] = common
                if a.get("server") and a.get("server") == b.get("server"):
                    shared["server banner"] = [a["server"]]
                if not shared:
                    continue
                conf = len(shared)
                rel = ("likely same organization" if conf >= 2 or ("nameservers" in shared and "mail providers" in shared)
                       else "shared infrastructure (verify ownership)")
                links.append({"a": a["domain"], "b": b["domain"], "shared": shared,
                              "relation": rel, "confidence": conf})
                findings.append(("INFO", "Shared infrastructure",
                                 f"{a['domain']} ↔ {b['domain']}: " +
                                 "; ".join(f"{k}: {', '.join(v[:3])}" for k, v in shared.items()) +
                                 f" → {rel}"))
                if "IP addresses" in shared and conf == 1:
                    findings.append(("LOW", "Shared hosting",
                                     f"{a['domain']} & {b['domain']} co-hosted on {', '.join(shared['IP addresses'])} "
                                     f"(co-tenant risk: compromise of one exposes the other)"))
        if explicit and not links:
            findings.append(("INFO", "No shared infra",
                             "explicit targets share no NS/MX/IP — separate estates"))

        self.results['correlation'] = {
            "targets": profiles,
            "auto_derived": auto,
            "explicit": extra,
            "links": links,
            "findings": findings,
        }

    # ---------------------------------------------------------- Screenshot Capture
    async def screenshot_capture(self):
        """Headless-browser page snapshots (EyeWitness/Aquatone-style).
        Optional dependency: pip install playwright && playwright install chromium"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.results['screenshots'] = {
                "available": False, "shots": [],
                "note": "playwright not installed — pip install playwright && playwright install chromium",
            }
            self.results['errors'].append(
                "screenshot: playwright missing — run: pip install playwright && playwright install chromium")
            return

        # pick URLs: homepage + flagged paths + a few discovered (cap 12 normal / 24 deep)
        urls = [self.base_url + "/"]
        seen = {urls[0]}
        for pd in [x for x in self.results.get('paths', []) if isinstance(x, dict)]:
            if pd.get('flagged') or pd.get('status') in (200, 401, 403):
                u = urljoin(self.base_url + "/", str(pd.get('path', '')).lstrip('/'))
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
            if len(urls) >= (24 if self.deep else 12):
                break
        out_dir = os.path.join(os.getcwd(), "nullveil_shots",
                                re.sub(r'[^A-Za-z0-9._-]', '_', self.domain))
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            self.results['screenshots'] = {"available": False, "shots": [],
                                           "note": f"cannot create dir: {e}"}
            return

        shots = []
        # pre-flight: is a chromium binary actually present?
        try:
            import glob as _glob
            _cache = os.path.expanduser("~/.cache/ms-playwright")
            _has_browser = bool(_glob.glob(os.path.join(_cache, "chromium*", "chrome*", "chrome")) or
                                 _glob.glob(os.path.join(_cache, "chromium*")))
            if not _has_browser and not os.environ.get("NULLVEIL_FORCE_SHOT"):
                self.results['screenshots'] = {
                    "available": False, "shots": [],
                    "note": "browser binary not downloaded — run: playwright install chromium",
                }
                self.results['errors'].append(
                    "screenshot: browser binary missing — run: playwright install chromium")
                return
        except Exception:
            pass
        try:
            async with async_playwright() as pw:
                try:
                    browser = await pw.chromium.launch(
                        headless=True, args=["--no-sandbox", "--disable-gpu"])
                except Exception as e:
                    self.results['screenshots'] = {
                        "available": False, "shots": [],
                        "note": f"chromium unavailable ({type(e).__name__}) — run: playwright install chromium",
                    }
                    self.results['errors'].append(
                        "screenshot: browser binary missing — run: playwright install chromium")
                    return
                ctx = await browser.new_context(
                    viewport={"width": 1366, "height": 900},
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) NULLVEIL-Recon/3.1 (screenshot)")
                sem = asyncio.Semaphore(3)   # gentle parallelism

                async def shoot(i, u):
                    async with sem:
                        rec = {"url": u, "file": "", "status": "", "title": "", "error": ""}
                        try:
                            page = await ctx.new_page()
                            resp = await page.goto(u, timeout=int(self.timeout * 1000) + 8000,
                                                   wait_until="domcontentloaded")
                            rec["status"] = resp.status if resp else ""
                            await page.wait_for_timeout(600)     # let late JS settle
                            rec["title"] = (await page.title() or "")[:80]
                            fname = f"{i:02d}-" + re.sub(r'[^A-Za-z0-9._-]', '_',
                                                         urlparse(u).path.strip('/') or 'index')[:60] + ".png"
                            fpath = os.path.join(out_dir, fname)
                            await page.screenshot(path=fpath, full_page=False)
                            rec["file"] = fpath
                            await page.close()
                        except Exception as e:
                            rec["error"] = type(e).__name__
                        return rec

                results_ = await asyncio.gather(*[shoot(i, u) for i, u in enumerate(urls)])
                shots = [r for r in results_ if r.get("file") or r.get("error")]
                await browser.close()
        except Exception as e:
            self.results['errors'].append(f"screenshot: playwright engine failed: {type(e).__name__} — {e}")

        ok = [s for s in shots if s.get("file")]
        self.results['screenshots'] = {
            "available": True, "dir": out_dir,
            "captured": len(ok), "attempted": len(shots),
            "shots": shots,
        }

    # ---------------------------------------------------------- Nuclei Template Scan
    async def nuclei_scan(self):
        """Run ProjectDiscovery nuclei (if installed) against the target and parse JSONL findings."""
        import shutil as _shutil
        exe = _shutil.which("nuclei") or _shutil.which("nuclei.exe")
        if not exe:
            self.results['nuclei'] = {
                "available": False, "findings": [],
                "note": "nuclei binary not found — install: "
                        "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest "
                        "(or download from github.com/projectdiscovery/nuclei/releases)",
            }
            self.results['errors'].append(
                "nuclei: binary missing — install from projectdiscovery.io, then re-run -a nuclei")
            return

        cmd = [exe, "-u", self.base_url, "-jsonl", "-silent", "-no-color", "-duc",
               "-severity", "critical,high,medium",
               "-timeout", str(max(self.timeout, 8)),
               "-retries", "1",
               "-c", str(min(self.concurrency, 25)),
               "-stats"]
        custom = str(getattr(self, "nuclei_templates", "") or "")
        if custom:
            cmd += ["-t", custom]
        findings = []
        stdout_lines = []
        version = ""
        wall_limit = 1800 if self.deep else 900
        try:
            # version (fast)
            try:
                vproc = await asyncio.create_subprocess_exec(
                    exe, "-version", stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT)
                vout, _ = await asyncio.wait_for(vproc.communicate(), timeout=15)
                m = re.search(r'Nuclei(?: Engine)?\s+Version:\s*([^\s]+)', vout.decode('utf-8', 'replace'))
                version = m.group(1) if m else ""
            except Exception:
                pass
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try:
                stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=wall_limit)
                stdout_lines = stdout_bytes.decode('utf-8', 'replace').splitlines()
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                self.results['errors'].append(f"nuclei: stopped after {wall_limit}s wall-time cap")
        except Exception as e:
            self.results['errors'].append(f"nuclei: execution failed: {type(e).__name__} — {e}")
            self.results['nuclei'] = {"available": False, "findings": [],
                                      "note": f"execution failed: {type(e).__name__}"}
            return

        parsed = 0
        for line in stdout_lines:
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            parsed += 1
            sev = str(j.get("info", {}).get("severity", "info")).upper()
            tid = j.get("template-id") or j.get("templateID") or "?"
            name = str(j.get("info", {}).get("name", tid))[:100]
            matched = str(j.get("matched-at") or j.get("matched") or j.get("host") or "")[:120]
            cves = j.get("info", {}).get("classification", {}) or {}
            cve_id = cves.get("cve-id") or cves.get("cve_id") or ""
            findings.append((sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO",
                             f"nuclei:{tid}",
                             f"{name} — matched: {matched}" + (f" [{cve_id}]" if cve_id else "")))
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.results['nuclei'] = {
            "available": True, "binary": exe, "version": version,
            "templates": custom or "default (nuclei built-in templates)",
            "severity_filter": "critical,high,medium",
            "templates_run": parsed,
            "findings": sorted(findings, key=lambda x: sev_rank.get(x[0], 5)),
        }

    # ---------------------------------------------------------- Scan History
    HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".nullveil", "history")

    def _history_save(self, report=None):
        """Auto-save every completed scan for --history / --resume."""
        if getattr(self, "no_history", False):
            return None
        try:
            os.makedirs(self.HISTORY_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            hid = f"{ts}-{hashlib.md5((self.domain + ts).encode()).hexdigest()[:6]}"
            report = report or self.export_dict()
            entry = {
                "id": hid, "target": self.base_url, "domain": self.domain,
                "when": datetime.now().isoformat(), "duration_s": round(self.scan_duration, 1),
                "version": __version__,
                "modules_run": [ATTACK_MODULES[i - 1][0] for i in
                                sorted(self.attack_set) if 0 < i <= MAX_MODULE],
                "summary": report.get("summary", {}),
                "report": report,
                "_raw": {"results": {k: v for k, v in self.results.items()},
                         "scalar": dict(self.scalar_results)},
            }
            with open(os.path.join(self.HISTORY_DIR, hid + ".json"), "w", encoding="utf-8") as fh:
                json.dump(entry, fh, ensure_ascii=False, default=str)
            # prune: keep newest 200 entries
            files = sorted(f for f in os.listdir(self.HISTORY_DIR) if f.endswith(".json"))
            for old in files[:-200]:
                try:
                    os.remove(os.path.join(self.HISTORY_DIR, old))
                except Exception:
                    pass
            return hid
        except Exception:
            return None

    def _history_list(self):
        """Return scan entries sorted newest-first."""
        out = []
        try:
            for fn in sorted(os.listdir(self.HISTORY_DIR), reverse=True):
                if not fn.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(self.HISTORY_DIR, fn), encoding="utf-8") as fh:
                        e = json.load(fh)
                    out.append(e)
                except Exception:
                    continue
                if len(out) >= 300:
                    break
        except FileNotFoundError:
            pass
        return out

    def _history_load(self, scan_id=None):
        """Load one history entry (latest for this target, or explicit id)."""
        for e in self._history_list():
            if scan_id:
                if e.get("id") == scan_id or e.get("id", "").startswith(scan_id):
                    return e
            elif e.get("domain", "").lower() == self.domain.lower():
                return e
        return None

    # ---------------------------------------------------------- Evidence / Repro Pack (-R)
    def export_repro(self, path):
        """Benign evidence pack: exact reproduction commands + verification steps for each
        finding, so developers can re-verify without any exploit payload."""
        o = self.base_url.rstrip('/')
        lines = [
            "# NULLVEIL — Evidence & Reproduction Pack",
            "",
            f"**Target:** {self.base_url}  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC  ",
            f"**Version:** {__version__}",
            "",
            "> Every command below is a **benign request** (GET/DNS query) — the same traffic the",
            "> scanner sent. No exploit payloads are included. Run only against systems you own",
            "> or are authorized to test.",
            "",
        ]
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sections = []

        def sec(title, sev, finding_id, detail, cmds, verify):
            sections.append((sev_rank.get(sev, 5), [
                f"## [{sev}] {title}",
                "",
                f"- **ID:** {finding_id}",
                f"- **Evidence:** {detail}",
                "",
                "**Reproduce:**",
                "```bash",
                *cmds,
                "```",
                "",
                f"**Verify:** {verify}",
                "",
            ]))

        # exposed paths / CVE probes with paths
        for f in self.results.get('cve_findings', []):
            sev, fid, title = f[0], f[1], f[2]
            detail = f[3] if len(f) > 3 else ""
            m = re.search(r'(/[^\s,\)\'"]+)', str(detail))
            if m:
                p = m.group(1)
                sec(f"{title}", sev, fid, detail,
                    [f"curl -sI {o}{p} | head -20",
                     f"curl -s {o}{p} | head -40"],
                    f"expected: HTTP {p} content reachable without auth → finding confirmed; "
                    f"after fix expect 401/403/404.")
            elif "version" in title.lower() or "Version" in title:
                sec(f"{title}", sev, fid, detail,
                    [f"curl -sI {o}/ | grep -iE 'server|x-powered-by|frame|generator'",
                     f"curl -s {o}/ | grep -ioE 'ver=[0-9.]+' | head"],
                    "banner/meta should be stripped or updated after remediation.")
            else:
                sec(f"{title}", sev, fid, detail,
                    [f"curl -sI {o}/"],
                    "re-check after remediation; finding detail above documents observed evidence.")
        # flagged paths not already covered
        covered = " ".join(x[1][2] for x in sections)
        for pd in [x for x in self.results.get('paths', []) if isinstance(x, dict)][:40]:
            if not pd.get('flagged'):
                continue
            pth = str(pd.get('path'))
            if pth in covered:
                continue
            sec(f"Exposed path {pth} ({pd.get('type', 'sensitive')})", pd.get('severity', 'HIGH') if isinstance(pd.get('severity'), str) else 'HIGH',
                f"path:{pth}",
                f"HTTP {pd.get('status')} · {pd.get('size', 0)} bytes · type={pd.get('type', '?')}",
                [f"curl -sI {o}{pth}",
                 f"curl -s {o}{pth} | head -40"],
                f"expected now: HTTP {pd.get('status')} → after fix: 401/403/404 with no body.")
        # API audit
        for f in self.results.get('api_audit_findings', []):
            sev, fid, detail = f[0], f[1], f[2]
            m = re.search(r'(https?://[^\s,]+|/[a-z0-9_\-/\.]+)', str(detail), re.I)
            target = m.group(1) if m else o + "/"
            cmds = [f"curl -sI '{target}'"]
            if "CORS" in fid or "cors" in fid.lower():
                cmds = [f"curl -sI -H 'Origin: https://evil.example' '{target}' | grep -i access-control"]
            if "rate" in fid.lower() or "Rate" in fid:
                cmds.append("for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code}\\n' '" + target + "'; done | sort | uniq -c")
            sec(fid, sev, f"audit:{fid}", detail, cmds,
                "compare response headers/codes; after fix the risky condition disappears.")
        # TLS
        for f in self.results.get('tls_findings', []):
            sev, fid, detail = f[0], f[1], f[2]
            cmds = [f"openssl s_client -connect {self.domain}:443 -tls1_2 </dev/null 2>/dev/null | grep -E 'Protocol|Cipher'"]
            if "TLS 1.0" in fid or "TLS 1.1" in fid:
                flag = "tls1" if "1.0" in fid else "tls1_1"
                cmds = [f"openssl s_client -connect {self.domain}:443 -{flag} </dev/null 2>&1 | head -8",
                        f"nmap --script ssl-enum-ciphers -p 443 {self.domain} | head -30"]
            elif "key" in fid.lower():
                cmds = [f"echo | openssl s_client -connect {self.domain}:443 2>/dev/null | openssl x509 -noout -text | grep -E 'Public-Key|Signature Algorithm'"]
            sec(fid, sev, f"tls:{fid}", detail, cmds,
                "re-run the same handshake after remediation: legacy protocol/weak cipher should refuse.")
        # DNS / email
        for sev, msg in self.results.get('email_findings', []):
            dig = f"dig TXT {self.domain} +short"
            if "DMARC" in msg:
                dig = f"dig TXT _dmarc.{self.domain} +short"
            elif "SPF" in msg:
                dig = dig
            elif "DKIM" in msg:
                dig = "dig TXT <selector>._domainkey." + self.domain + " +short"
            sec(msg, sev, "email-auth", msg, [dig],
                "record absent → finding confirmed; publish the record to remediate.")
        # takeover
        for t in self.results.get('takeover', []):
            host = t.split(' ')[0]
            sec("Dangling subdomain (takeover risk)", "HIGH", "ext:takeover", t,
                [f"dig CNAME {host} +short", f"curl -sI https://{host}/ | head -10"],
                "CNAME → unclaimed service + distinct error page → confirm with the vendor's "
                "claim flow (authorized only).")
        # threat intel
        for f in self.results.get('intel', {}).get('findings', []):
            if len(f) >= 3:
                sec(f[1], f[0], "intel", f[2],
                    [f"curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/general' | head -c 400"],
                    "open the feed URL manually to confirm listing.")
        # breaches
        for f in self.results.get('breach', {}).get('findings', []):
            if len(f) >= 3 and f[1] in ("Breach exposure", "Email in breaches"):
                sec(f[1], f[0], "breach", f[2],
                    ["# requires HIBP_API_KEY; then: "
                     "curl -s -H \"hibp-api-key: $HIBP_API_KEY\" "
                     f"'https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}' | head -c 600"],
                    "non-empty JSON array confirms breach record association.")
        # secrets
        for kind, where, where2 in self.results.get('secrets', [])[:15]:
            sec(f"Exposed secret pattern ({kind})", "HIGH", "secret", f"{where} {where2}".strip()[:160],
                [f"curl -s {o}/ | grep -ioE '.{{0,30}}({re.escape(str(kind))[:18]}).{{0,20}}' | head"],
                "value must disappear from public responses after rotation + removal.")

        if not sections:
            lines.append("_No findings to reproduce — scan produced no issues in scope._")
        else:
            sections.sort(key=lambda x: x[0])
            for _, block in sections:
                lines.extend(block)
        lines += [
            "---",
            "**Remediation triage:** fix CRITICAL/HIGH first; re-run NULLVEIL to confirm each "
            "`Reproduce` command now returns the expected 'after fix' result.",
        ]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path







    # ---------------------------------------------------------- Report
    def print_report(self):
        console.print()
        # --- Master header ---
        header_body = Group(
            Align.center(Text.from_markup(f"[bold white]{self.domain}[/]")),
            Align.center(Text.from_markup(
                f"[dim]Scanned:[/] [white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]   "
                f"[dim]Duration:[/] [white]{getattr(self, 'scan_duration', 0):.1f}s[/]   "
                f"[dim]Mode:[/] [bold {'red' if self.deep else 'green'}]{'DEEP' if self.deep else 'NORMAL'}[/]"
            )),
        )
        console.print(Panel(header_body, title="[bold magenta]◈ RECON REPORT ◈[/]",
                            border_style="magenta", box=rbox.DOUBLE_EDGE))

        # --- Risk meter ---
        score, level, color, verdict, bar = _risk_meter(
            set(self.results['secrets']),
            len([h for h in self.results['missing_security_headers'] if h != 'content-encoding']),
            [p for p in self.results['paths'] if p['flagged']],
        )
        risk_body = Group(
            Text.from_markup(f"{bar}  [bold {color}]{score}/100 — {verdict}[/]"),
            Align.center(Text.from_markup(
                f"[dim]Risk Level:[/] [bold {color}]{level}[/]   "
                f"[dim]Secrets:[/] [white]{len(set(self.results['secrets']))}[/]   "
                f"[dim]Flagged Paths:[/] [white]{len([p for p in self.results['paths'] if p['flagged']])}[/]   "
                f"[dim]Missing Headers:[/] [white]{len([h for h in self.results['missing_security_headers'] if h != 'content-encoding'])}[/]"
            )),
        )
        console.print(Panel(risk_body, title=f"[bold {color}]◈ EXPOSURE LEVEL ◈[/]",
                            border_style=color, box=rbox.ROUNDED))

        # --- Summary grid ---
        t = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_magenta",
                  show_header=True, title="[bold magenta]◈ SCAN SUMMARY ◈[/]")
        t.add_column("Module", style="cyan")
        t.add_column("Findings", justify="right", style="bold white")
        summary_rows = [
            ("DNS Records", len(self.results['dns'])),
            ("Subdomains", len(set(self.results['subdomains']))),
            ("Open Ports", len(self.results['ports'])),
            ("Discovered Paths", len(self.results['paths'])),
            ("Emails", len(set(self.results['emails']))),
            ("IPs", len(set(self.results['ips']))),
            ("Users", len(set(self.results['users']))),
            ("Secrets / Leaks", len(set(self.results['secrets']))),
            ("Tech Stack", len(set(self.results['tech_stack']))),
            ("API Endpoints", len(self.results.get('api_endpoints', [])) + len(self.results.get('api_endpoints_found', []))),
            ("API Documents", len(self.results.get('api_docs', []))),
            ("Forms", len(self.results.get('forms', []))),
            ("WAF / CDN", len(self.results.get('waf', []))),
            ("Email Issues", len([f for f in self.results.get('email_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Audit Issues", len([f for f in self.results.get('api_audit_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Takeover Risks", len(self.results.get('takeover', []))),
            ("CVE / Misconfig", len([f for f in self.results.get('cve_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Crawled Pages", self.results.get('crawl', {}).get('pages_crawled', 0)),
            ("TLS Issues", len([f for f in self.results.get('tls_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
        ]
        for label, count in summary_rows:
            flag = "[bold red] ⚠[/]" if ("Secret" in label and count) else ""
            t.add_row(label, f"{count}{flag}")
        console.print(t)

        # --- HTTP ---
        if self.scalar_results.get('http_status'):
            status = int(self.scalar_results['http_status'])
            s_color = 'green' if status < 400 else ('yellow' if status < 500 else 'red')
            ht = Table(box=rbox.SIMPLE, header_style="bold bright_cyan",
                       title="[bold bright_cyan]◈ HTTP OVERVIEW ◈[/]")
            ht.add_column("Key", style="dim")
            ht.add_column("Value")
            ht.add_row("Final URL", str(self.scalar_results.get('final_url', '-')))
            ht.add_row("Status", f"[bold {s_color}]{status}[/]")
            if self.scalar_results.get('server'):
                ht.add_row("Server", f"[cyan]{self.scalar_results['server']}[/]")
            if self.scalar_results.get('x_powered_by'):
                ht.add_row("X-Powered-By", f"[cyan]{self.scalar_results['x_powered_by']}[/]")
            console.print(ht)

        # --- Security headers ---
        if self.results['security_headers'] or self.results['missing_security_headers']:
            st = Table(box=rbox.SIMPLE, header_style="bold bright_cyan",
                       title="[bold bright_cyan]◈ SECURITY HEADERS ◈[/]")
            st.add_column("Header")
            st.add_column("Status", justify="center")
            for h in self.results['security_headers']:
                st.add_row(h, "[bold green on dark_green] PRESENT [/]")
            for h in self.results['missing_security_headers']:
                if h == 'content-encoding':
                    continue
                st.add_row(h, "[bold red on dark_red] MISSING [/]")
            console.print(st)

        # --- SSL ---
        if self.scalar_results.get('ssl_issuer'):
            sslt = Table(box=rbox.SIMPLE, header_style="bold bright_cyan",
                         title="[bold bright_cyan]◈ SSL CERTIFICATE ◈[/]")
            sslt.add_column("Key", style="dim")
            sslt.add_column("Value")
            sslt.add_row("Subject", str(self.scalar_results.get('ssl_subject', '-')))
            sslt.add_row("Issuer", str(self.scalar_results.get('ssl_issuer', '-')))
            sslt.add_row("Valid Until", str(self.scalar_results.get('ssl_not_after', '-')))
            days = self.scalar_results.get('ssl_days_left')
            if days is not None:
                color = 'green' if days > 30 else ('yellow' if days > 7 else 'red')
                icon = '✅' if days > 30 else ('⚠️' if days > 7 else '🚨')
                sslt.add_row("Days Left", f"{icon} [{color}]{days} days[/]")
            sans = self.scalar_results.get('ssl_san', [])
            sslt.add_row("SANs", ", ".join(sans[:15]) + (f" (+{len(sans)-15} more)" if len(sans) > 15 else ""))
            console.print(sslt)

        # --- Network ---
        if self.results['dns']:
            self._simple_table("◈ DNS RECORDS ◈", self.results['dns'], style="bright_cyan")

        # --- Email security (SPF/DKIM/DMARC) ---
        if self.results.get('email_findings') or self.results.get('spf') is not None:
            et = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_green",
                       title="[bold green]◈ EMAIL SECURITY ◈[/]")
            et.add_column("Record", style="dim")
            et.add_column("Value")
            et.add_row("Mail Provider", f"[bold cyan]{self.results.get('mail_provider') or '-'}[/]")
            et.add_row("MX", "\n".join(self.results.get('mx', [])) or "[dim]none[/]")
            et.add_row("SPF", f"[white]{self.results.get('spf') or '[bold red]MISSING[/]'}[/]")
            dkim = self.results.get('dkim', {})
            et.add_row("DKIM", (", ".join(f"[cyan]{s}[/]" for s in dkim) if dkim else "[yellow]not found on common selectors[/]"))
            dmarc = self.results.get('dmarc')
            if dmarc:
                pol = self.results.get('dmarc_policy', '?')
                pol_col = {'none': 'red', 'quarantine': 'yellow', 'reject': 'green'}.get(pol, 'white')
                et.add_row("DMARC", f"[white]{dmarc}[/]  [bold {pol_col}]p={pol}[/]")
            else:
                et.add_row("DMARC", "[bold red]MISSING[/]")
            et.add_row("MTA-STS", f"[white]{self.results.get('mta_sts') or '[dim]not found[/]'}[/]")
            et.add_row("BIMI", f"[white]{self.results.get('bimi') or '[dim]not found[/]'}[/]")
            console.print(et)

            findings = self.results.get('email_findings', [])
            if findings:
                sev_col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
                fb = "\n".join(f"  [{sev_col.get(s, 'white')}]{'◈ ' + s:<11}[/] {m}" for s, m in findings)
                console.print(Panel(fb, title="[bold magenta]◈ EMAIL SECURITY FINDINGS ◈[/]",
                                    border_style="magenta", box=rbox.ROUNDED))

        # --- API Security Audit ---
        audit_f = self.results.get('api_audit_findings', [])
        audit_eps = self.results.get('api_audit_endpoints', [])
        if audit_f or audit_eps:
            # findings table
            if audit_f:
                sev_col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
                at = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_red",
                           title="[bold red]◈ API SECURITY FINDINGS ◈[/]")
                at.add_column("Severity", justify="center")
                at.add_column("Check", style="bold")
                at.add_column("Detail")
                for sev, chk, det in audit_f[:40]:
                    at.add_row(f"[{sev_col.get(sev, 'white')}]{sev}[/]", chk, det[:120])
                console.print(at)
            # endpoint classification
            if audit_eps:
                et = Table(box=rbox.SIMPLE, header_style="bold bright_cyan",
                           title="[bold bright_cyan]◈ ENDPOINT CLASSIFICATION ◈[/]")
                et.add_column("Path")
                et.add_column("Status", justify="right")
                et.add_column("Auth", justify="center")
                et.add_column("CORS", justify="center")
                et.add_column("Methods")
                et.add_column("Flags", style="dim")
                for r in audit_eps[:30]:
                    st = r['status']
                    st_col = "green" if st in (200, 201) else ("yellow" if st in (401, 403, 404, 405, 500) else "white")
                    auth_col = "bold red" if r['auth'] == "none" and re.search(r'(?i)/(users?|accounts?|admin|config)', r['path']) else ("green" if r['auth'] == "REQUIRED" else "dim")
                    cors_col = {"REFLECTED+CRED": "bold red", "REFLECTED": "red", "*": "yellow"}.get(r['cors'], "dim")
                    flags = []
                    if r['verbose_error']:
                        flags.append("[red]ERR-LEAK[/]")
                    if r['sensitive_keys']:
                        flags.append(f"[yellow]{len(r['sensitive_keys'])} sensitive keys[/]")
                    et.add_row(r['path'], f"[bold {st_col}]{st}[/]",
                               f"[{auth_col}]{r['auth']}[/]", f"[{cors_col}]{r['cors']}[/]",
                               (r['methods'] or '-')[:28], " ".join(flags) or "-")
                console.print(et)
            # rate limit
            rl = self.results.get('api_audit_ratelimit', {})
            if rl.get('tested'):
                col = "green" if rl['limited'] else "yellow"
                console.print(Panel(f"  [bold {col}]{rl['detail']}[/]",
                                    title="[bold yellow]◈ RATE LIMITING TEST (10 requests) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))
            # JWT
            jwts = self.results.get('api_audit_jwt', [])
            if jwts and jwts[0].get('alg') != '-':
                body = "\n".join(
                    f"  [dim]alg:[/] [bold cyan]{j['alg']}[/]   "
                    f"[dim]kid:[/] {j['kid'] or '[dim]none[/]'}   "
                    f"[dim]claims:[/] [white]{', '.join(j['claims'])}[/]"
                    for j in jwts)
                console.print(Panel(body, title="[bold magenta]◈ JWT ANALYSIS ◈[/]",
                                    border_style="magenta", box=rbox.ROUNDED))

        # --- External Intelligence (CT / Wayback / Takeover) ---
        ext_f = self.results.get('ext_findings', [])
        if ext_f or self.results.get('ct_hosts') or self.results.get('takeover'):
            # takeover risks first — critical if found
            tk = self.results.get('takeover', [])
            if tk:
                console.print(Panel("\n".join(f"  [bold red]⚠ {t}[/]" for t in tk),
                                    title="[bold red]◈ SUBDOMAIN TAKEOVER RISK ◈[/]",
                                    border_style="red", box=rbox.DOUBLE_EDGE))
            wb = self.results.get('wayback', {})
            if wb.get('total_urls') or self.results.get('ct_hosts'):
                head = (f"  [dim]crt.sh subdomains:[/] [bold cyan]{len(self.results.get('ct_hosts', []))}[/]\n"
                        f"  [dim]Wayback URLs:[/] [bold cyan]{wb.get('total_urls', 0)}[/]  "
                        f"[dim]unique paths:[/] [bold cyan]{wb.get('unique_paths', 0)}[/]  "
                        f"[dim]params:[/] [bold cyan]{len(wb.get('parameters', {}))}[/]\n"
                        f"  [dim]historical sensitive paths:[/] "
                        f"[bold {'yellow' if wb.get('sensitive_paths') else 'green'}]{len(wb.get('sensitive_paths', []))}[/]")
                console.print(Panel(head, title="[bold cyan]◈ EXTERNAL INTEL (CT + WAYBACK) ◈[/]",
                                    border_style="cyan", box=rbox.ROUNDED))
                if wb.get('parameters'):
                    shown = ", ".join(list(wb['parameters'].keys())[:40])
                    console.print(Panel(f"  {shown}", title="[dim]Historical query parameters[/]",
                                        border_style="dim", box=rbox.SIMPLE))
            if ext_f:
                sev_col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
                xt = Table(box=rbox.SIMPLE, header_style="bold bright_cyan",
                           title="[bold bright_cyan]◈ EXTERNAL INTEL FINDINGS ◈[/]")
                xt.add_column("Sev", justify="center")
                xt.add_column("Check", style="bold")
                xt.add_column("Detail")
                for sev, chk, det in ext_f[:30]:
                    xt.add_row(f"[{sev_col.get(sev, 'white')}]{sev}[/]", chk, det[:120])
                console.print(xt)

        # --- CVE & Misconfig ---
        versions = self.results.get('versions', [])
        cve_f = self.results.get('cve_findings', [])
        if versions:
            vt = Table(box=rbox.SIMPLE, header_style="bold bright_yellow",
                       title="[bold bright_yellow]◈ VERSION FINGERPRINTS ◈[/]")
            vt.add_column("Product")
            vt.add_column("Version")
            vt.add_column("Source", style="dim")
            for prod, ver, src in versions[:25]:
                vt.add_row(f"[bold]{prod}[/]", f"[cyan]{ver}[/]", src)
            console.print(vt)
        if cve_f:
            sev_col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
            ct = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_red",
                       title="[bold red]◈ CVE / MISCONFIG FINDINGS ◈[/]")
            ct.add_column("Severity", justify="center")
            ct.add_column("ID", style="bold")
            ct.add_column("Detail")
            for sev, vid, title, ev in cve_f[:35]:
                ct.add_row(f"[{sev_col.get(sev, 'white')}]{sev}[/]", vid, f"{title} — {ev}"[:130])
            console.print(ct)

        # --- Deep Crawler ---
        cr = self.results.get('crawl', {})
        if cr.get('pages_crawled'):
            refl = self.results.get('reflected_params', [])
            body = (f"  [dim]Pages crawled:[/] [bold cyan]{cr['pages_crawled']}[/]   "
                    f"[dim]Internal links:[/] [bold cyan]{len(cr.get('internal_links', []))}[/]   "
                    f"[dim]Parameters:[/] [bold cyan]{len(cr.get('parameters', []))}[/]   "
                    f"[dim]Forms:[/] [bold cyan]{len(cr.get('forms', []))}[/]   "
                    f"[dim]JS files:[/] [bold cyan]{len(cr.get('js_files', []))}[/]\n"
                    f"  [dim]Endpoints in source:[/] [bold magenta]{len(cr.get('endpoints_found', []))}[/]")
            console.print(Panel(body, title="[bold magenta]◈ DEEP CRAWLER ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))
            if cr.get('parameters'):
                pt = Table(box=rbox.SIMPLE, header_style="bold bright_magenta",
                           title="[dim]Discovered parameters[/]")
                pt.add_column("Parameter")
                pt.add_column("Seen on", justify="right")
                pt.add_column("Reflected", justify="center")
                for p in cr['parameters'][:30]:
                    r_flag = ("[bold yellow]YES ⚠[/]" if p['reflected'] else "[dim]no[/]")
                    pt.add_row(f"[white]{p['name']}[/]", str(p['seen_on']), r_flag)
                console.print(pt)
            if refl:
                console.print(Panel("  [yellow]" + ", ".join(refl[:30]) + "[/]\n"
                                    "  [dim]Reflected = input echoes back — verify manually for XSS (report only, no exploit sent)[/]",
                                    title="[bold yellow]◈ REFLECTED PARAMETERS (XSS candidates) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))

        # --- TLS Deep Analysis ---
        tls_m = self.results.get('tls_matrix', [])
        if tls_m:
            tt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_green",
                       title="[bold green]◈ TLS VERSION / CIPHER MATRIX ◈[/]")
            tt.add_column("Version")
            tt.add_column("Supported", justify="center")
            tt.add_column("Cipher")
            tt.add_column("Bits", justify="right")
            for name, sup, cipher, bits, note in tls_m:
                col = "green" if sup == "yes" else ("dim" if sup == "no" else "yellow")
                tt.add_row(name, f"[bold {col}]{sup}[/]", cipher, bits)
            console.print(tt)
            ci = self.results.get('tls_cert', {})
            if ci:
                rows = "\n".join(f"  [dim]{k.replace('_', ' '):<20}[/] [white]{v}[/]"
                                 for k, v in ci.items())
                console.print(Panel(rows, title="[bold green]◈ CERTIFICATE CHAIN / OCSP ◈[/]",
                                    border_style="green", box=rbox.ROUNDED))
            tls_f = self.results.get('tls_findings', [])
            if tls_f:
                sev_col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green"}
                ft = Table(box=rbox.SIMPLE, header_style="bold bright_green",
                           title="[bold bright_green]◈ TLS FINDINGS ◈[/]")
                ft.add_column("Sev", justify="center")
                ft.add_column("Check", style="bold")
                ft.add_column("Detail")
                for sev, chk, det in tls_f[:25]:
                    ft.add_row(f"[{sev_col.get(sev, 'white')}]{sev}[/]", chk, det[:120])
                console.print(ft)



        # --- WAF / CDN ---
        if self.results.get('waf') or self.results.get('cdn'):
            wafs = self.results.get('waf', [])
            cdns = self.results.get('cdn', [])
            sec_wafs = self.results.get('waf_security', [])
            grid = "   ".join(
                (f"[bold red]🛡 {w}[/]" if w in sec_wafs else f"[bold cyan]☁ {w}[/]")
                for w in wafs)
            body = f"  [bold white]Detected:[/] {grid}\n"
            body += f"  [dim]Red shield = security WAF · Cyan cloud = CDN/edge only[/]\n\n"
            body += "\n".join(f"  [dim]•[/] [white]{ev}[/]" for ev in self.results.get('waf_evidence', []))
            if not wafs:
                body = "  [bold green]No WAF/CDN fingerprint detected[/]"
            console.print(Panel(body, title="[bold red]◈ WAF / CDN DETECTION ◈[/]",
                                border_style="red" if sec_wafs else "cyan", box=rbox.DOUBLE_EDGE))

        if self.results['subdomains']:
            self._simple_table("◈ SUBDOMAINS ◈", sorted(set(self.results['subdomains'])), style="bright_cyan")
        if self.results['ports']:
            ports_grid = "  ".join(f"[bold green on dark_green] {p} [/]" for p in self.results['ports'])
            console.print(Panel(Align.center(Text.from_markup(ports_grid)),
                                title="[bold green]◈ OPEN PORTS ◈[/]", border_style="green", box=rbox.ROUNDED))

        # --- Paths ---
        if self.results['paths']:
            pt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_red",
                       title="[bold red]◈ DISCOVERED PATHS ◈[/]")
            pt.add_column("Path")
            pt.add_column("Status", justify="right")
            pt.add_column("Type")
            pt.add_column("Size", justify="right")
            for p in sorted(self.results['paths'], key=lambda x: (not x['flagged'], x['path'])):
                status_str = f"[bold red]{p['status']}[/]" if p['status'] >= 500 else (f"[bold yellow]{p['status']}[/]" if p['status'] in (401, 403) else f"[green]{p['status']}[/]")
                mark = " [bold red on red] !! [/]" if p['flagged'] else ""
                pt.add_row(f"{p['path']}{mark}", status_str, p['type'], str(p['size']))
            console.print(pt)

        # --- Tech stack ---
        if self.results['tech_stack']:
            tech_grid = "   ".join(f"[bold magenta]◈[/] [white]{t}[/]" for t in sorted(set(self.results['tech_stack'])))
            console.print(Panel(tech_grid, title="[bold magenta]◈ TECH STACK ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))

        # --- API Docs (swagger/openapi/graphql) ---
        if self.results.get('api_docs'):
            for doc in self.results['api_docs']:
                body = "\n".join([
                    f"  [dim]Source:[/] [white]{doc['source']}[/]",
                    f"  [dim]Title:[/]  [bold cyan]{doc['title']}[/]  [dim]v{doc['version']}[/]",
                    f"  [dim]Server:[/] [white]{doc['server'] or '-'}[/]",
                    f"  [dim]Endpoints:[/] [bold yellow]{len(doc['endpoints'])}[/]",
                ])
                console.print(Panel(body, title=f"[bold green]◈ API DOCUMENT FOUND: {doc['title']} ◈[/]",
                                    border_style="green", box=rbox.DOUBLE_EDGE))
                eps = doc['endpoints'][:60]
                et = Table(box=rbox.SIMPLE, header_style="bold bright_green",
                           title="[dim]API endpoints from spec[/]")
                et.add_column("#", justify="right", style="dim")
                et.add_column("Path")
                for i, ep in enumerate(eps, 1):
                    et.add_row(str(i), ep)
                console.print(et)

        # --- Probed API endpoints ---
        if self.results.get('api_endpoints'):
            at = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_blue",
                       title="[bold bright_blue]◈ LIVE API ENDPOINTS ◈[/]")
            at.add_column("Path")
            at.add_column("Status", justify="right")
            at.add_column("Type")
            at.add_column("Auth", justify="center")
            at.add_column("Info", style="dim")
            for ep in sorted(self.results['api_endpoints'], key=lambda x: (not x['auth_required'], x['path'])):
                st = ep['status']
                st_col = "green" if st in (200, 201) else ("yellow" if st in (401, 403, 405) else "red")
                auth = "[bold yellow]YES[/]" if ep['auth_required'] else "[dim]no[/]"
                info = (ep['snippet'] or "")[:80]
                at.add_row(ep['path'], f"[bold {st_col}]{st}[/]", ep['type'], auth, info)
            console.print(at)

        # --- Discovered API paths (from JS/HTML) ---
        if self.results.get('api_endpoints_found'):
            apis = self.results['api_endpoints_found']
            shown = apis[:60]
            body = "\n".join(f"  [dim]•[/] [white]{a}[/]" for a in shown)
            more = f"\n  [dim]... and {len(apis) - len(shown)} more (see JSON report)[/]" if len(apis) > len(shown) else ""
            console.print(Panel(body + more, title=f"[bold cyan]◈ API PATHS FOUND IN SOURCE ({len(apis)}) ◈[/]",
                                border_style="cyan", box=rbox.ROUNDED))

        # --- Forms ---
        if self.results.get('forms'):
            ft = Table(box=rbox.SIMPLE, header_style="bold bright_yellow",
                       title="[bold bright_yellow]◈ FORMS ON PAGE ◈[/]")
            ft.add_column("Action")
            ft.add_column("Method", justify="center")
            ft.add_column("Fields")
            ft.add_column("Sensitive", justify="center")
            for f in self.results['forms']:
                sens = f['sensitive_fields']
                sens_str = f"[bold red]{', '.join(sens)}[/]" if sens else "[dim]-[/]"
                ft.add_row(f['action'][:60], f['method'], ", ".join(f['fields'][:8])[:60], sens_str)
            console.print(ft)

        # --- Cookies ---
        if self.results.get('cookies'):
            console.print(Panel("  " + "   ".join(self.results['cookies'][:40]),
                                title="[bold yellow]◈ SESSION COOKIES ◈[/]",
                                border_style="yellow", box=rbox.ROUNDED))

        # --- JSON-LD structured data ---
        if self.results.get('jsonld'):
            self._simple_table("◈ STRUCTURED DATA (JSON-LD) ◈", sorted(set(self.results['jsonld']))[:30], style="bright_blue")

        # --- Meta info ---
        if self.results.get('meta'):
            mt = Table(box=rbox.SIMPLE, header_style="bold bright_blue",
                       title="[bold bright_blue]◈ SITE METADATA ◈[/]")
            mt.add_column("Key", style="dim")
            mt.add_column("Value")
            for k, v in self.results['meta'].items():
                val = ", ".join(v) if isinstance(v, list) else v
                mt.add_row(k, str(val)[:120])
            console.print(mt)

        # --- Internal links ---
        if self.results.get('site_links'):
            self._simple_table("◈ INTERNAL LINKS CRAWLED ◈", self.results['site_links'][:40], style="dim")

        # --- Users / emails / ips / phones ---
        if self.results['users']:
            self._simple_table("◈ USERS / AUTHORS ◈", sorted(set(self.results['users'])), style="bright_blue")
        if self.results['emails']:
            self._simple_table("◈ EMAILS ◈", sorted(set(self.results['emails'])), style="bright_yellow")
        if self.results['ips']:
            self._simple_table("◈ IPs ◈", sorted(set(self.results['ips'])), style="bright_green")
        if self.results['phones']:
            self._simple_table("◈ PHONE NUMBERS (heuristic) ◈", self.results['phones'][:30], style="bright_yellow")

        # --- Secrets ---
        if self.results['secrets']:
            body = "\n".join(f"  [bold red]◤[/] [white]{s}[/]" for s in sorted(set(self.results['secrets'])))
            console.print(Panel(body, title="[bold red on red] ◈ ⚠ SECRETS / API KEYS LEAKED ◈ [/]",
                                border_style="red", box=rbox.DOUBLE_EDGE))

        # --- Comments ---
        if self.results['comments']:
            body = "\n".join(f"  [yellow]•[/] {c}" for c in self.results['comments'][:15])
            console.print(Panel(body, title="[bold yellow]◈ INTERESTING HTML COMMENTS ◈[/]",
                                border_style="yellow", box=rbox.ROUNDED))

        # --- Robots / sitemap / js ---
        if self.results['robots']:
            self._simple_table("◈ ROBOTS.TXT ◈", self.results['robots'][:60], style="dim")
        if self.results['sitemap_urls']:
            self._simple_table("◈ SITEMAP URLS ◈", self.results['sitemap_urls'][:40], style="dim")
        if self.results['js_files']:
            self._simple_table("◈ JS FILES / SOURCE MAPS ◈", sorted(set(self.results['js_files']))[:30], style="dim")

        # --- Nuclei template scan ---
        nuc = self.results.get('nuclei', [])
        if isinstance(nuc, dict) and (nuc.get('findings') or nuc.get('note')):
            if nuc.get('findings'):
                sev_col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
                nt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_red",
                           title=f"[bold red]◈ NUCLEI FINDINGS ◈[/] [dim]v{nuc.get('version', '') or 'n/a'} · "
                                 f"{nuc.get('templates_run', 0)} template(s)[/]")
                nt.add_column("Sev", justify="center")
                nt.add_column("ID", style="bold")
                nt.add_column("Detail")
                for sev, fid, det in nuc.get('findings', [])[:50]:
                    nt.add_row(f"[{sev_col.get(sev, 'white')}]{sev}[/]", fid, det[:110])
                console.print(nt)
            elif nuc.get('note'):
                console.print(Panel(f"  [yellow]•[/] {nuc['note']}",
                                    title="[bold yellow]◈ NUCLEI (not available) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))
        # --- Screenshots ---
        shots = self.results.get('screenshots', [])
        if isinstance(shots, dict) and (shots.get('captured') or shots.get('note')):
            if shots.get('captured'):
                body = "\n".join(f"  [green]✓[/] {os.path.basename(str(x.get('file', '')))}  "
                                  f"[dim]{x.get('url', '')[:70]}[/]"
                                  + (f"  [red]{x.get('error')}[/]" if x.get('error') else "")
                                  for x in shots.get('shots', [])[:24])
                console.print(Panel(body + f"\n\n  [dim]dir: {shots.get('dir', '')}[/]",
                                    title=f"[bold green]◈ SCREENSHOTS ({shots.get('captured', 0)}/{shots.get('attempted', 0)}) ◈[/]",
                                    border_style="green", box=rbox.ROUNDED))
            elif shots.get('note'):
                console.print(Panel(f"  [yellow]•[/] {shots['note']}",
                                    title="[bold yellow]◈ SCREENSHOTS (not available) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))

        # --- Errors ---
        if self.results['errors']:
            body = "\n".join(f"  [red]•[/] {e}" for e in self.results['errors'][:10])
            console.print(Panel(body, title="[bold red]◈ ERRORS ◈[/]", border_style="red", box=rbox.ROUNDED))

        # --- Footer ---
        console.print()
        footer = Group(
            Align.center(Text.from_markup("[bold white]NULLVEIL RECON[/]")),
            Align.center(Text.from_markup(f"[dim]Owner:[/] [bold cyan]NULLVEIL[/]  •  [dim]Engine:[/] [bold yellow]DeepHat[/]  •  [dim]v{__version__}[/]")),
            Align.center(Text.from_markup(f"[dim]Scan duration:[/] [white]{getattr(self, 'scan_duration', 0):.1f}s[/]  •  [dim]Report generated:[/] [white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")),
            Align.center(Text.from_markup("[dim]— Use responsibly. Authorized targets only. —[/dim]")),
        )
        console.print(Panel(footer, border_style="bright_blue", box=rbox.DOUBLE, padding=(0, 2)))
        console.print(Panel("[bold green]✓ Recon complete.[/] JSON report save korte: [bold cyan]-o report.json[/] flag use koro.",
                            border_style="green", box=rbox.ROUNDED))

    def _simple_table(self, title, rows, style="bright_cyan"):
        t = Table(box=rbox.SIMPLE, header_style=f"bold {style}",
                  title=f"[bold {style}]{title}[/]")
        t.add_column("#", justify="right", style="dim")
        t.add_column("Value")
        for i, row in enumerate(rows, 1):
            t.add_row(str(i), str(row))
        console.print(t)

    # ---------------------------------------------------------- Export
    def export_dict(self):
        out = {
            "tool": "NULLVEIL Recon",
            "owner": "NULLVEIL",
            "version": __version__,
            "target": self.domain,
            "started": datetime.now().isoformat(),
            "mode": "deep" if self.deep else "normal",
            "modules_run": [ATTACK_MODULES[i - 1][0] for i in
                            sorted(set(self.attack_set) | set(getattr(self, "_resume_done", [])))
                            if 0 < i <= MAX_MODULE],
            "summary": {
                "dns_records": len(self.results['dns']),
                "subdomains": len(set(self.results['subdomains'])),
                "open_ports": len(self.results['ports']),
                "paths": len(self.results['paths']),
                "emails": len(self.results['emails']),
                "ips": len(self.results['ips']),
                "users": len(self.results['users']),
                "secrets": len(set(self.results['secrets'])),
                "tech_stack": sorted(set(self.results['tech_stack'])),
                "api_endpoints": len(self.results.get('api_endpoints', [])) + len(self.results.get('api_endpoints_found', [])),
                "api_documents": len(self.results.get('api_docs', [])),
                "forms": len(self.results.get('forms', [])),
                "waf": self.results.get('waf', []),
                "email_issues": len([f for f in self.results.get('email_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "audit_issues": len([f for f in self.results.get('api_audit_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "takeover_risks": len(self.results.get('takeover', [])),
                "cve_issues": len([f for f in self.results.get('cve_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "crawled_pages": self.results.get('crawl', {}).get('pages_crawled', 0),
                "tls_issues": len([f for f in self.results.get('tls_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "supply_issues": len([f for f in self.results.get('supply', {}).get('findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "critical_assets": len(self.results.get('criticality', {}).get('assets', [])),
                "anomaly_issues": len([f for f in self.results.get('anomaly', {}).get('findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "intel_issues": len([f for f in self.results.get('intel', {}).get('findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "breach_issues": len([f for f in self.results.get('breach', {}).get('findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "compliance_fails": self.results.get('compliance', {}).get('total_fail', 0),
                "attack_chains": len(self.results.get('graph', {}).get('chains', [])),
                "correlated_targets": len(self.results.get('correlation', {}).get('links', [])),
                "nuclei_issues": len([f for f in self.results.get('nuclei', {}).get('findings', [])
                                      if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')]),
                "screenshots": self.results.get('screenshots', {}).get('captured', 0),
            },
            "http": {k: v for k, v in self.scalar_results.items() if k != 'http_headers'},
            "headers": self.scalar_results.get('http_headers', {}),
            "security_headers": self.results['security_headers'],
            "missing_security_headers": self.results['missing_security_headers'],
            "dns": self.results['dns'],
            "subdomains": sorted(set(self.results['subdomains'])),
            "open_ports": self.results['ports'],
            "paths": self.results['paths'],
            "emails": sorted(set(self.results['emails'])),
            "ips": sorted(set(self.results['ips'])),
            "phones": self.results['phones'],
            "users": sorted(set(self.results['users'])),
            "secrets": sorted(set(self.results['secrets'])),
            "tech_stack": sorted(set(self.results['tech_stack'])),
            "comments": self.results['comments'],
            "social_links": self.results['social_links'],
            "robots": self.results['robots'],
            "sitemap_urls": self.results['sitemap_urls'],
            "js_files": sorted(set(self.results['js_files'])),
            "api": {
                "documents": self.results.get('api_docs', []),
                "live_endpoints": self.results.get('api_endpoints', []),
                "paths_in_source": self.results.get('api_endpoints_found', []),
                "forms": self.results.get('forms', []),
                "cookies": self.results.get('cookies', []),
                "json_ld": sorted(set(self.results.get('jsonld', []))),
                "metadata": self.results.get('meta', {}),
                "internal_links": self.results.get('site_links', []),
            },
            "waf": {
                "detected": self.results.get('waf', []),
                "security_wafs": self.results.get('waf_security', []),
                "cdn": self.results.get('cdn', []),
                "evidence": self.results.get('waf_evidence', []),
            },
            "email_security": {
                "mail_provider": self.results.get('mail_provider', ''),
                "mx": self.results.get('mx', []),
                "spf": self.results.get('spf', ''),
                "spf_includes": self.results.get('spf_includes', []),
                "dkim": self.results.get('dkim', {}),
                "dmarc": self.results.get('dmarc', ''),
                "dmarc_policy": self.results.get('dmarc_policy', ''),
                "mta_sts": self.results.get('mta_sts', ''),
                "bimi": self.results.get('bimi', ''),
                "findings": [{"severity": s, "message": m} for s, m in self.results.get('email_findings', [])],
            },
            "api_audit": {
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('api_audit_findings', [])],
                "endpoints": self.results.get('api_audit_endpoints', []),
                "rate_limit": self.results.get('api_audit_ratelimit', {}),
                "jwt": self.results.get('api_audit_jwt', []),
            },
            "external_intel": {
                "ct_subdomains": self.results.get('ct_hosts', []),
                "wayback": self.results.get('wayback', {}),
                "takeover_risks": self.results.get('takeover', []),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('ext_findings', [])],
            },
            "cve": {
                "versions": [{"product": p, "version": v, "source": s} for p, v, s in self.results.get('versions', [])],
                "findings": [{"severity": s, "id": i, "title": t, "evidence": e}
                             for s, i, t, e in self.results.get('cve_findings', [])],
            },
            "crawler": self.results.get('crawl', {}),
            "tls": {
                "matrix": [{"version": v, "supported": s, "cipher": c, "bits": b, "negotiated": n}
                           for v, s, c, b, n in self.results.get('tls_matrix', [])],
                "certificate": self.results.get('tls_cert', {}),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('tls_findings', [])],
            },
            "supply_chain": {
                "page": self.results.get('supply', {}).get('page', ''),
                "vendors": self.results.get('supply', {}).get('vendors', []),
                "resources": self.results.get('supply', {}).get('resources', []),
                "third_party_exec": self.results.get('supply', {}).get('third_party_exec', 0),
                "sri_missing": self.results.get('supply', {}).get('sri_missing', 0),
                "unknown_sources": self.results.get('supply', {}).get('unknown_sources', []),
                "external_form_actions": self.results.get('supply', {}).get('external_form_actions', []),
                "preconnect": self.results.get('supply', {}).get('preconnect', []),
                "providers": self.results.get('supply', {}).get('providers', {}),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('supply', {}).get('findings', [])],
            },
            "criticality": {
                "method": self.results.get('criticality', {}).get('method', ''),
                "tiers": self.results.get('criticality', {}).get('tiers', {}),
                "assets": self.results.get('criticality', {}).get('assets', []),
            },
            "anomaly": {
                "probed": self.results.get('anomaly', {}).get('probed', 0),
                "soft404": self.results.get('anomaly', {}).get('soft404', False),
                "masked_paths": self.results.get('anomaly', {}).get('masked_paths', []),
                "kmeans_outliers": self.results.get('anomaly', {}).get('kmeans_outliers', []),
                "samples": self.results.get('anomaly', {}).get('samples', []),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('anomaly', {}).get('findings', [])],
            },
            "threat_intel": {
                "ips": self.results.get('intel', {}).get('ips', []),
                "sources": self.results.get('intel', {}).get('sources', []),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('intel', {}).get('findings', [])],
            },
            "breach": {
                "key_present": self.results.get('breach', {}).get('key_present', False),
                "provider": self.results.get('breach', {}).get('provider', ''),
                "checks": self.results.get('breach', {}).get('checks', []),
                "breaches": self.results.get('breach', {}).get('breaches', []),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('breach', {}).get('findings', [])],
            },
            "compliance": {
                "coverage_pct": self.results.get('compliance', {}).get('coverage_pct', 0),
                "total_controls": self.results.get('compliance', {}).get('total_controls', 0),
                "total_fail": self.results.get('compliance', {}).get('total_fail', 0),
                "frameworks": self.results.get('compliance', {}).get('frameworks', {}),
                "disclaimer": self.results.get('compliance', {}).get('disclaimer', ''),
            },
            "attack_graph": {
                "node_count": self.results.get('graph', {}).get('node_count', 0),
                "edge_count": self.results.get('graph', {}).get('edge_count', 0),
                "nodes": self.results.get('graph', {}).get('nodes', []),
                "edges": self.results.get('graph', {}).get('edges', []),
                "facts": self.results.get('graph', {}).get('facts', {}),
                "attack_paths": self.results.get('graph', {}).get('attack_paths', []),
                "chains": self.results.get('graph', {}).get('chains', []),
                "dot_exported": self.results.get('graph', {}).get('dot_exported', False),
            },
            "correlation": {
                "targets": self.results.get('correlation', {}).get('targets', []),
                "auto_derived": self.results.get('correlation', {}).get('auto_derived', []),
                "explicit": self.results.get('correlation', {}).get('explicit', []),
                "links": self.results.get('correlation', {}).get('links', []),
                "note": self.results.get('correlation', {}).get('note', ''),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('correlation', {}).get('findings', [])],
            },
            "screenshots": {
                "available": self.results.get('screenshots', {}).get('available', False),
                "dir": self.results.get('screenshots', {}).get('dir', ''),
                "captured": self.results.get('screenshots', {}).get('captured', 0),
                "attempted": self.results.get('screenshots', {}).get('attempted', 0),
                "note": self.results.get('screenshots', {}).get('note', ''),
                "shots": self.results.get('screenshots', {}).get('shots', []),
            },
            "nuclei": {
                "available": self.results.get('nuclei', {}).get('available', False),
                "binary": self.results.get('nuclei', {}).get('binary', ''),
                "version": self.results.get('nuclei', {}).get('version', ''),
                "templates": self.results.get('nuclei', {}).get('templates', ''),
                "severity_filter": self.results.get('nuclei', {}).get('severity_filter', ''),
                "templates_run": self.results.get('nuclei', {}).get('templates_run', 0),
                "note": self.results.get('nuclei', {}).get('note', ''),
                "findings": [{"severity": sev, "id": fid, "detail": det}
                             for sev, fid, det in self.results.get('nuclei', {}).get('findings', [])],
            },
            "errors": self.results['errors'],
        }
        return out

    # ---------------------------------------------------------- HTML Export
    def export_html(self, path):
        """Generate a standalone dark-themed HTML report (no external assets)."""
        from html import escape as _e

        d = self.export_dict()
        s = d['summary']
        risk = _risk_meter(self.results['secrets'],
                           len(self.results['missing_security_headers']),
                           [p for p in self.results['paths'] if str(p.get('status')) in ('200', '403')])
        score, level, color, verdict, _ = risk
        css_color = {"green": "#22c55e", "yellow": "#eab308", "red": "#ef4444"}[color]

        def sec(title, inner, accent="#8b5cf6"):
            if not inner:
                return ""
            return (f'<section class="card" style="border-left-color:{accent}">'
                    f'<h2>{_e(title)}</h2>{inner}</section>')

        def tbl(headers, rows, cls=""):
            th = "".join(f"<th>{_e(str(h))}</th>" for h in headers)
            tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
            return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>' if rows else ""

        def li(items, limit=200):
            if not items:
                return ""
            return "<ul>" + "".join(f"<li>{_e(str(i))}</li>" for i in items[:limit]) + "</ul>"

        parts = []
        # DNS / subdomains / ports
        parts.append(sec("DNS Records", li(d.get('dns', [])), "#06b6d4"))
        parts.append(sec("Subdomains", li(d.get('subdomains', [])), "#06b6d4"))
        ports = d.get('open_ports', [])
        if ports:
            parts.append(sec("Open Ports",
                             "<div class='chips'>" + "".join(f"<span class='chip green'>{p}</span>" for p in ports) + "</div>",
                             "#22c55e"))
        # HTTP + headers
        http = d.get('http', {})
        if http:
            parts.append(sec("HTTP Overview",
                             tbl(["Key", "Value"], [[_e(str(k)), _e(str(v))] for k, v in http.items()]), "#3b82f6"))
        sh = d.get('security_headers', [])
        if sh:
            hdrs = d.get('headers', {})
            parts.append(sec("Security Headers",
                             tbl(["Header", "Value"],
                                 [[_e(str(h)), _e(str(hdrs.get(h, hdrs.get(h.lower(), ''))))]
                                  for h in sh]), "#3b82f6"))
        miss = d.get('missing_security_headers', [])
        if miss:
            parts.append(sec("Missing Security Headers",
                             "<div class='chips'>" + "".join(f"<span class='chip red'>{_e(m)}</span>" for m in miss) + "</div>",
                             "#ef4444"))
        # SSL
        httpd = d.get('http', {})
        ssl_pairs = {k: v for k, v in httpd.items() if k.startswith('ssl_')}
        if ssl_pairs:
            parts.append(sec("SSL Certificate",
                             tbl(["Key", "Value"], [[_e(str(k).replace('ssl_', '').replace('_', ' ')), _e(str(v))]
                                                    for k, v in ssl_pairs.items()]), "#8b5cf6"))
        # WAF
        waf = d.get('waf', {})
        if waf.get('detected'):
            chips = "".join(
                f"<span class='chip {'red' if w in waf.get('security_wafs', []) else 'cyan'}'>{_e(w)}</span>"
                for w in waf['detected'])
            parts.append(sec("WAF / CDN Detection",
                             f"<div class='chips'>{chips}</div>" + li(waf.get('evidence', [])), "#ef4444"))
        # Email security
        em = d.get('email_security', {})
        if em:
            rows = [[k, _e(str(v))] for k, v in em.items()
                    if k not in ('findings', 'dkim', 'spf_includes') and v]
            parts.append(sec("Email Security", tbl(["Record", "Value"], rows), "#22c55e"))
            fnd = em.get('findings', [])
            if fnd:
                parts.append(sec("Email Findings",
                                 tbl(["Severity", "Finding"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else 'yellow'}'>{_e(f['severity'])}</span>",
                                       _e(f['message'])] for f in fnd]), "#eab308"))
        # API Security Audit
        aud = d.get('api_audit', {})
        if aud:
            af = aud.get('findings', [])
            if af:
                parts.append(sec("API Security Findings",
                                 tbl(["Severity", "Check", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else 'yellow'}'>{_e(f['severity'])}</span>",
                                       _e(f['check']), _e(f['detail'])] for f in af]), "#ef4444"))
            aeps = aud.get('endpoints', [])
            if aeps:
                parts.append(sec("Endpoint Classification",
                                 tbl(["Path", "Status", "Auth", "CORS", "Methods", "Flags"],
                                     [[_e(str(r.get('path'))), r.get('status'),
                                       _e(str(r.get('auth'))), _e(str(r.get('cors'))),
                                       _e(str(r.get('methods') or '-')),
                                       _e(', '.join((r.get('verbose_error') and ['ERR-LEAK'] or []) +
                                                    (r.get('sensitive_keys') or ['sensitive keys'] if r.get('sensitive_keys') else [])) or '-')]
                                      for r in aeps[:40]]), "#ef4444"))
            rl = aud.get('rate_limit', {})
            if rl.get('tested'):
                parts.append(sec("Rate Limiting Test",
                                 f"<p><span class='chip {'green' if rl.get('limited') else 'yellow'}'>"
                                 f"{'LIMITED ✅' if rl.get('limited') else 'NO LIMIT'}</span> "
                                 f"{_e(str(rl.get('detail', '')))}</p>", "#eab308"))
            jwts = [j for j in aud.get('jwt', []) if j.get('alg') != '-']
            if jwts:
                parts.append(sec("JWT Analysis",
                                 tbl(["Alg", "kid", "Claims"],
                                     [[_e(str(j['alg'])), _e(str(j.get('kid') or '-')),
                                       _e(', '.join(j.get('claims', [])))] for j in jwts]), "#a78bfa"))
        # External Intelligence (CT / Wayback / Takeover)
        ext = d.get('external_intel', {})
        if ext:
            tk = ext.get('takeover_risks', [])
            if tk:
                parts.append(sec("Subdomain Takeover Risk", li(tk), "#ef4444"))
            wb = ext.get('wayback', {})
            wrows = [["Unique URLs", wb.get('total_urls', 0)], ["Unique paths", wb.get('unique_paths', 0)],
                     ["Query parameters", len(wb.get('parameters', {}))],
                     ["Historical sensitive paths", len(wb.get('sensitive_paths', []))]]
            ctsubs = ext.get('ct_subdomains', [])
            if ctsubs or wb.get('total_urls'):
                parts.append(sec("External Intel (CT + Wayback)",
                                 tbl(["Metric", "Value"], wrows) +
                                 (f"<p class='muted'>crt.sh subdomains: {len(ctsubs)}</p>"
                                  f"<div class='chips'>" +
                                  "".join(f"<span class='chip cyan'>{_e(h)}</span>" for h in ctsubs[:80]) +
                                  "</div>" if ctsubs else ""), "#06b6d4"))
            efind = ext.get('findings', [])
            if efind:
                parts.append(sec("External Intel Findings",
                                 tbl(["Severity", "Check", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else ('yellow' if f['severity'] in ('MEDIUM','LOW') else 'green')}'>{_e(f['severity'])}</span>",
                                       _e(f['check']), _e(f['detail'])] for f in efind[:60]]), "#06b6d4"))
        # CVE / misconfig
        cved = d.get('cve', {})
        if cved:
            vers = cved.get('versions', [])
            if vers:
                parts.append(sec("Version Fingerprints",
                                 tbl(["Product", "Version", "Source"],
                                     [[_e(v['product']), _e(v['version']), _e(v['source'])] for v in vers]), "#f59e0b"))
            cf = cved.get('findings', [])
            if cf:
                parts.append(sec("CVE / Misconfig Findings",
                                 tbl(["Severity", "ID", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else 'yellow'}'>{_e(f['severity'])}</span>",
                                       f"<code>{_e(f['id'])}</code>", _e(f"{f['title']} — {f['evidence']}")] for f in cf[:80]]),
                                 "#ef4444"))
        # Deep crawler
        cr = d.get('crawler', {})
        if cr and cr.get('pages_crawled'):
            parts.append(sec("Deep Crawler",
                             tbl(["URL", "Status", "Title"],
                                 [[_e(str(p['url']))[:110], p['status'], _e(str(p['title']))]
                                  for p in cr.get('pages', [])]), "#a78bfa"))
            cpar = cr.get('parameters', [])
            if cpar:
                parts.append(sec("Discovered Parameters",
                                 tbl(["Parameter", "Seen on", "Reflected"],
                                     [[_e(p['name']), p['seen_on'],
                                       f"<span class='chip yellow'>YES ⚠</span>" if p.get('reflected') else "no"]
                                      for p in cpar[:80]]), "#a78bfa"))
            cforms = cr.get('forms', [])
            if cforms:
                parts.append(sec("Crawled Forms",
                                 tbl(["Action", "Method", "Fields"],
                                     [[_e(str(f['action']))[:80], _e(f['method']), _e(', '.join(f.get('fields', [])[:10]))]
                                      for f in cforms[:40]]), "#eab308"))
            ceps = cr.get('endpoints_found', [])
            if ceps:
                parts.append(sec(f"Endpoints in Source ({len(ceps)})", li(ceps, 150), "#a78bfa"))
        # TLS deep analysis
        tlsd = d.get('tls', {})
        if tlsd:
            mtx = tlsd.get('matrix', [])
            if mtx:
                parts.append(sec("TLS Version / Cipher Matrix",
                                 tbl(["Version", "Supported", "Cipher", "Bits"],
                                     [[m['version'],
                                       f"<span class='chip {'green' if m['supported']=='yes' else ('red' if m['supported']=='no' else 'yellow')}'>{m['supported']}</span>",
                                       _e(str(m['cipher'])), m['bits']] for m in mtx]), "#22c55e"))
            cert = tlsd.get('certificate', {})
            if cert:
                parts.append(sec("Certificate Chain / OCSP",
                                 tbl(["Key", "Value"], [[_e(str(k).replace('_', ' ')), _e(str(v))]
                                                        for k, v in cert.items()]), "#22c55e"))
            tf = tlsd.get('findings', [])
            if tf:
                parts.append(sec("TLS Findings",
                                 tbl(["Severity", "Check", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else ('yellow' if f['severity'] in ('MEDIUM','LOW') else 'green')}'>{_e(f['severity'])}</span>",
                                       _e(f['check']), _e(f['detail'])] for f in tf[:60]]), "#22c55e"))
        # Content / leaks
        for key, title, accent in (("emails", "Emails Found", "#f59e0b"), ("ips", "IP Addresses", "#f59e0b"),
                                   ("users", "Users / Authors", "#f59e0b"), ("secrets", "Secrets / Leaks", "#ef4444"),
                                   ("comments", "HTML Comments", "#94a3b8")):
            vals = sorted(set(d.get(key, [])))
            if vals:
                parts.append(sec(title, li(vals), accent))
        # Paths
        paths = d.get('paths', [])
        if paths:
            rows = []
            for p in paths[:150]:
                st = p.get('status', '') if isinstance(p, dict) else ''
                pth = p.get('path', p) if isinstance(p, dict) else p
                rows.append([_e(str(pth)), f"<span class='chip {'green' if str(st)=='200' else 'yellow'}'>{st}</span>"])
            parts.append(sec("Discovered Paths", tbl(["Path", "Status"], rows), "#f59e0b"))
        # API
        api = d.get('api', {})
        if api:
            docs = api.get('documents', [])
            for doc in docs:
                eps = "".join(f"<li><code>{_e(e)}</code></li>" for e in doc.get('endpoints', [])[:100])
                parts.append(sec(f"API Document: {doc.get('title','API')} (v{doc.get('version','?')})",
                                 f"<p class='muted'>Source: <code>{_e(str(doc.get('source')))}</code> · "
                                 f"Server: <code>{_e(str(doc.get('server','-')))}</code> · "
                                 f"Methods: {_e(', '.join(doc.get('methods', [])))}</p><ul>{eps}</ul>", "#22d3ee"))
            live = api.get('live_endpoints', [])
            if live:
                parts.append(sec("Live API Endpoints",
                                 tbl(["Path", "Status", "Type", "Auth"],
                                     [[_e(str(e['path'])), e['status'], _e(str(e.get('type',''))),
                                       "<span class='chip yellow'>YES</span>" if e.get('auth_required') else "no"]
                                      for e in live[:100]]), "#22d3ee"))
            found = api.get('paths_in_source', [])
            if found:
                parts.append(sec(f"API Paths in Source ({len(found)})", li(found, 120), "#22d3ee"))
            forms = api.get('forms', [])
            if forms:
                parts.append(sec("Forms",
                                 tbl(["Action", "Method", "Fields", "Sensitive"],
                                     [[_e(str(f['action']))[:80], _e(f['method']), _e(', '.join(f['fields'][:8])),
                                       f"<span class='chip red'>{_e(', '.join(f['sensitive_fields']))}</span>" if f.get('sensitive_fields') else '-']
                                      for f in forms]), "#eab308"))
            cookies = api.get('cookies', [])
            if cookies:
                parts.append(sec("Cookies", li(cookies, 60), "#eab308"))
            meta = api.get('metadata', {})
            if meta:
                parts.append(sec("Site Metadata",
                                 tbl(["Key", "Value"], [[_e(str(k)), _e(str(v))[:150]] for k, v in meta.items()]), "#3b82f6"))
        # Tech stack
        tech = d.get('tech_stack', [])
        if tech:
            parts.append(sec("Tech Stack",
                             "<div class='chips'>" + "".join(f"<span class='chip purple'>{_e(t)}</span>" for t in tech) + "</div>",
                             "#8b5cf6"))

        # ===== v3.0.0 new sections =====
        # Supply Chain / Third-Party Risk
        sup = d.get('supply_chain', {})
        if sup:
            vend = sup.get('vendors', [])
            if vend:
                parts.append(sec("Supply Chain Vendors",
                                 tbl(["Vendor", "Category", "Resources", "SRI Missing", "Note"],
                                     [[_e(v['name']), _e(v['category']), v['count'], v['sri_missing'], _e(v['note'][:70])]
                                      for v in vend[:30]]), "#f97316"))
            ext_f = sup.get('findings', [])
            if ext_f:
                parts.append(sec("Supply Chain Findings",
                                 tbl(["Severity", "Check", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else ('yellow' if f['severity'] in ('MEDIUM','LOW') else 'green')}'>{_e(f['severity'])}</span>",
                                       _e(f['check']), _e(f['detail'])] for f in ext_f[:50]]), "#f97316"))
        # Criticality
        crit = d.get('criticality', {})
        if crit:
            tiers = crit.get('tiers', {})
            tchips = "".join(f"<span class='chip {'red' if k in ('CRITICAL','HIGH') else 'yellow'}'>{k}: {v}</span>"
                             for k, v in tiers.items() if v)
            if tchips:
                parts.append(sec("Criticality Tier Summary", f"<div class='chips'>{tchips}</div>", "#eab308"))
            assets = crit.get('assets', [])
            if assets:
                parts.append(sec("Criticality Classification",
                                 tbl(["Asset", "Type", "Score", "Tier", "Reasons"],
                                     [[_e(str(a['asset'])[:80]), _e(a['type']), a['score'],
                                       f"<span class='chip {'red' if a['tier'] in ('CRITICAL','HIGH') else 'yellow'}'>{_e(a['tier'])}</span>",
                                       _e(', '.join(a['reasons'])[:80])] for a in assets[:60]]), "#eab308"))
        # Anomaly Detection
        anom = d.get('anomaly', {})
        if anom:
            sm = anom.get('samples', [])
            if sm:
                parts.append(sec(f"Response Samples ({anom.get('probed', len(sm))} probed)",
                                 tbl(["Path", "Status", "Size", "Latency ms", "Hash", "Title"],
                                     [[_e(str(x['path'])[:60]), x['status'], x['size'], x['latency_ms'], _e(x['hash']), _e(x['title'][:40])]
                                      for x in sm[:60]]), "#8b5cf6"))
            af = anom.get('findings', [])
            if af:
                parts.append(sec("Anomaly Findings",
                                 tbl(["Severity", "Check", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else ('yellow' if f['severity'] in ('MEDIUM','LOW') else 'green')}'>{_e(f['severity'])}</span>",
                                       _e(f['check']), _e(f['detail'])] for f in af[:40]]), "#8b5cf6"))
        # Threat Intel
        ti = d.get('threat_intel', {})
        if ti:
            srcs = ti.get('sources', [])
            if srcs:
                parts.append(sec("Threat Intel Sources",
                                 tbl(["Source", "Target", "Status", "Detail"],
                                     [[_e(s['source']), _e(s['target'][:40]),
                                       f"<span class='chip {'red' if s['status']=='listed' else ('green' if s['status']=='clean' else 'yellow')}'>{_e(s['status'])}</span>",
                                       _e(s['detail'][:90])] for s in srcs[:40]]), "#ef4444"))
        # Breach
        br = d.get('breach', {})
        if br:
            checks = br.get('checks', [])
            brk = br.get('breaches', [])
            rows = [[_e(str(c.get('check'))), _e(str(c.get('status'))), _e(str(c.get('detail'))[:120])] for c in checks]
            rows += [[_e(str(b.get('name',''))), "BREACHED", _e(f"{b.get('date','')} · {b.get('pwn_count',0)} accounts · {', '.join(b.get('classes', []))[:80]}")] for b in brk]
            if rows:
                parts.append(sec("Breach / Credential Monitoring",
                                 tbl(["Check", "Status", "Detail"], rows), "#ef4444"))
        # Compliance
        comp = d.get('compliance', {})
        if comp:
            cov = comp.get('coverage_pct', 0)
            tf = comp.get('total_controls', 0)
            nf = comp.get('total_fail', 0)
            parts.append(sec("Compliance Coverage",
                             f"<div class='chips'>"
                             f"<span class='chip {'green' if cov>=80 else 'yellow' if cov>=50 else 'red'}'>Coverage: {cov}%</span>"
                             f"<span class='chip green'>Pass: {cov}</span>"
                             f"<span class='chip red'>Fail: {nf}</span>"
                             f"<span class='chip yellow'>Controls: {tf}</span></div>"
                             f"<p class='muted'>{_e(comp.get('disclaimer', ''))}</p>", "#3b82f6"))
            fw = comp.get('frameworks', {})
            for fname, fv in fw.items():
                ctrls = fv.get('controls', [])
                if ctrls:
                    parts.append(sec(f"Compliance: {fname}",
                                     tbl(["Ref", "Title", "Status", "Evidence"],
                                         [[_e(str(c['ref'])), _e(str(c['title'])[:80]),
                                           f"<span class='chip {'green' if c['status']=='PASS' else 'red' if c['status']=='FAIL' else 'yellow'}'>{_e(c['status'])}</span>",
                                           _e(str(c['evidence'])[:120])] for c in ctrls[:40]]), "#3b82f6"))
        # Attack Graph
        ag = d.get('attack_graph', {})
        if ag:
            ap = ag.get('attack_paths', [])
            if ap:
                rows = [[p['severity'], " → ".join(_e(str(h)) for h in p['hops'])[:140]] for p in ap[:20]]
                parts.append(sec("Attack Paths",
                                 tbl(["Severity", "Path"], rows), "#ef4444"))
            ch = ag.get('chains', [])
            if ch:
                for c in ch[:20]:
                    steps = "<ol>" + "".join(f"<li>{_e(s)}</li>" for s in c['steps']) + "</ol>"
                    parts.append(sec(f"Chain: {c['title']} (confidence: {c['confidence']})",
                                     steps + f"<p><strong>Impact:</strong> {_e(c['impact'])}</p>", "#ef4444"))
            dot = ag.get('dot_exported')
            if dot:
                parts.append(sec("Graph Export", "<p class='muted'>DOT file exported (--dot flag)</p>", "#64748b"))
        # Correlation
        corr = d.get('correlation', {})
        if corr:
            tgts = corr.get('targets', [])
            if tgts:
                parts.append(sec("Correlated Targets",
                                 tbl(["Domain", "NS", "MX", "IPs", "Title", "Server"],
                                     [[_e(str(t['domain'])), _e(', '.join(t.get('ns', []))[:60]),
                                       _e(', '.join(t.get('mx', []))[:50]),
                                       _e(', '.join(t.get('ips', []))[:50]),
                                       _e(str(t.get('title', ''))[:40]), _e(str(t.get('server', ''))[:30])]
                                      for t in tgts]), "#8b5cf6"))
            links = corr.get('links', [])
            if links:
                rows = [[_e(l['a']), _e(l['b']),
                         _e('; '.join(f"{k}: {', '.join(v)}" for k, v in l['shared'].items())[:100]),
                         _e(l['relation'])] for l in links]
                parts.append(sec("Correlation Matrix",
                                 tbl(["A", "B", "Shared", "Relation"], rows), "#8b5cf6"))
        # Nuclei
        nuc = d.get('nuclei', {})
        if nuc:
            nf = nuc.get('findings', [])
            if nf:
                parts.append(sec(f"Nuclei Scan (v{nuc.get('version','?')} · {nuc.get('templates_run',0)} templates)",
                                 tbl(["Severity", "ID", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else ('yellow' if f['severity']=='MEDIUM' else 'green')}'>{_e(f['severity'])}</span>",
                                       _e(f['id']), _e(str(f['detail'])[:140])] for f in nf[:80]]), "#ef4444"))
            elif nuc.get('note'):
                parts.append(sec("Nuclei Scan", f"<p class='muted'>{_e(nuc['note'])}</p>", "#64748b"))
        # Screenshots
        sh = d.get('screenshots', {})
        if sh and sh.get('captured'):
            imgs = ""
            for x in sh.get('shots', [])[:24]:
                fp = x.get('file', '')
                b64 = ""
                try:
                    if fp and os.path.exists(fp) and os.path.getsize(fp) < 400_000:
                        with open(fp, 'rb') as fh:
                            b64 = base64.b64encode(fh.read()).decode()
                except Exception:
                    b64 = ""
                if b64:
                    imgs += (f"<figure style='display:inline-block;margin:6px;text-align:center'>"
                             f"<img src='data:image/png;base64,{b64}' style='max-width:340px;border-radius:6px;border:1px solid #334155'/>"
                             f"<figcaption class='muted' style='font-size:11px'>{_e(x.get('url','')[:60])}</figcaption></figure>")
            if imgs:
                parts.append(sec(f"Screenshots ({sh.get('captured', 0)})", imgs, "#22c55e"))
            else:
                files = li([x.get('file', '') for x in sh.get('shots', []) if x.get('file')], 40)
                parts.append(sec("Screenshots (files)", files or "<p class='muted'>saved on disk</p>", "#22c55e"))
        elif sh and sh.get('note'):
            parts.append(sec("Screenshots", f"<p class='muted'>{_e(sh['note'])}</p>", "#64748b"))
        # Errors
        errs = d.get('errors', [])
        if errs:
            parts.append(sec("Errors / Warnings", li(errs, 50), "#64748b"))

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NULLVEIL Recon Report — {_e(str(d.get('target', '')))}</title>
<style>
  :root {{ --bg:#0a0e17; --card:#111827; --text:#e5e7eb; --muted:#94a3b8; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
         font-family:'Segoe UI',system-ui,-apple-system,sans-serif; line-height:1.55; }}
  header {{ text-align:center; padding:48px 16px 24px;
            background:radial-gradient(ellipse at top,#1e1b4b66,transparent); }}
  header h1 {{ margin:0; font-size:2.2rem; letter-spacing:6px;
               background:linear-gradient(90deg,#f43f5e,#f59e0b,#22c55e,#06b6d4,#8b5cf6);
               -webkit-background-clip:text; background-clip:text; color:transparent; }}
  header .sub {{ color:var(--muted); margin-top:8px; font-size:.95rem; }}
  main {{ max-width:1100px; margin:0 auto; padding:16px 20px 80px; }}
  .meter {{ background:var(--card); border-radius:14px; padding:22px 26px; margin:24px 0;
            border:1px solid #1f2937; text-align:center; }}
  .meter .bar {{ height:18px; border-radius:9px; background:#1f2937; overflow:hidden; margin:12px 0; }}
  .meter .bar > div {{ height:100%; background:{css_color}; border-radius:9px; }}
  .meter .score {{ font-size:2rem; font-weight:700; color:{css_color}; }}
  .card {{ background:var(--card); border-radius:12px; padding:18px 22px; margin:18px 0;
           border:1px solid #1f2937; border-left:4px solid #8b5cf6; }}
  .card h2 {{ margin:0 0 12px; font-size:1.05rem; letter-spacing:1px; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; font-size:.88rem; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #1f2937; vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; text-transform:uppercase; font-size:.75rem; letter-spacing:.5px; }}
  tr:hover td {{ background:#0f172a; }}
  ul {{ margin:6px 0; padding-left:20px; }} li {{ margin:2px 0; }}
  code {{ background:#0f172a; padding:2px 6px; border-radius:5px; font-size:.85em; color:#22d3ee; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:8px; }}
  .chip {{ padding:3px 11px; border-radius:20px; font-size:.78rem; font-weight:600; }}
  .chip.green {{ background:#22c55e22; color:#22c55e; }} .chip.red {{ background:#ef444422; color:#ef4444; }}
  .chip.yellow {{ background:#eab30822; color:#eab308; }} .chip.cyan {{ background:#06b6d422; color:#06b6d4; }}
  .chip.purple {{ background:#8b5cf622; color:#a78bfa; }}
  .muted {{ color:var(--muted); }}
  footer {{ text-align:center; color:var(--muted); padding:30px; font-size:.82rem; border-top:1px solid #1f2937; margin-top:40px; }}
</style>
</head>
<body>
<header>
  <h1>NULLVEIL</h1>
  <div class="sub">R E C O N &nbsp;R E P O R T<br>
    <strong>{_e(str(d.get('target', '')))}</strong> · Scanned: {_e(str(d.get('started', '')[:19]))} ·
    Duration: {_e(str(round(self.scan_duration, 1)))}s · Modules: {_e(', '.join(d.get('modules_run', [])) or '-')} ·
    Version {_e(str(d.get('version', '')))}
  </div>
</header>
<main>
  <div class="meter">
    <div class="muted">EXPOSURE LEVEL</div>
    <div class="bar"><div style="width:{score}%"></div></div>
    <div class="score">{score}/100 — {verdict}</div>
    <div class="muted">Risk: {level} · Secrets: {s.get('secrets',0)} ·
      Missing headers: {len(self.results['missing_security_headers'])} ·
      Flagged paths: {len([p for p in self.results['paths'] if str(p.get('status')) in ('200','403')])}</div>
  </div>
  {"".join(parts)}
</main>
<footer>
  Generated by <strong>NULLVEIL Recon</strong> v{_e(str(d.get('version','')))} · Owner: NULLVEIL · Engine: DeepHat<br>
  Authorized testing only. This report may contain sensitive data — handle with care.
</footer>
</body>
</html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_doc)



# ---------------------------------------------------------- CLI
def main():
    parser = argparse.ArgumentParser(
        prog="nullveil",
        description="NULLVEIL Recon - Website & Domain Reconnaissance Tool | Owner: NULLVEIL | Engine: DeepHat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  nullveil example.com                -> full scan (all modules)\n"
               "  nullveil example.com -m             -> interactive attack menu\n"
               "  nullveil example.com -a 1,2,5       -> dns + subdomains + ssl only\n"
               "  nullveil https://site.com --deep -o report.json\n"
               "  nullveil example.com -H report.html -> standalone HTML report\n"
               "  nullveil example.com -w mysubs.txt  -> custom subdomain wordlist\n"
               "  nullveil example.com -a supply,graph,comp -> supply chain + attack graph + compliance\n"
               "  nullveil example.com -R repro.md    -> evidence/repro pack (benign, no payloads)\n"
               "  nullveil example.com --dot graph.dot -> export attack path graph as DOT\n"
               "  nullveil example.com --correlate a.com,b.com -> cross-org correlation\n"
               "  HIBP_API_KEY=xxx nullveil example.com -a breach -> breach monitoring\n"
               "  nullveil -l                         -> list attack modules\n\n"
               "Owner: NULLVEIL | Use only on authorized targets."
    )
    parser.add_argument("target", nargs="?", help="Target domain or URL (e.g. example.com)")
    parser.add_argument("-d", "--deep", action="store_true", help="Deep mode: bigger wordlists, more ports, extra path checks")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP/DNS timeout in seconds (default: 10)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Max concurrent requests (default: 100)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Save JSON report to file")
    parser.add_argument("-H", "--html", metavar="FILE", help="Save standalone HTML report to file (e.g. report.html)")
    parser.add_argument("-w", "--wordlist", metavar="FILE", help="Custom subdomain wordlist file (one per line)")
    parser.add_argument("-p", "--ports", type=str, help="Custom comma-separated ports (e.g. 80,443,8080)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Less console output")
    parser.add_argument("-a", "--attack", metavar="LIST", default=None,
                        help="Comma-separated modules: 1=dns,2=sub,3=ports,4=http,5=ssl,6=content,7=robots,8=paths,9=users,10=api,11=waf,12=email,13=audit,14=ext,15=cve,16=crawl,17=tls,18=supply,19=crit,20=anom,21=intel,22=breach,23=comp,24=graph,25=correlate or 'all'")
    parser.add_argument("-m", "--menu", action="store_true", help="Interactive attack selection menu")
    parser.add_argument("-l", "--list-attacks", action="store_true", help="List available attack modules")
    parser.add_argument("-R", "--repro", metavar="FILE", help="Export evidence/reproduction pack (benign, no exploit payloads) to markdown file")
    parser.add_argument("--correlate", metavar="LIST", default=None, help="Comma-separated extra domains for cross-org correlation (e.g. a.com,b.com)")
    parser.add_argument("--hibp-key", metavar="KEY", default=None, help="HaveIBeenPwned API key (optional; also via HIBP_API_KEY env)")
    parser.add_argument("--dot", metavar="FILE", default=None, help="Export Attack Path Graph as DOT file")
    parser.add_argument("--history", action="store_true", help="List saved scan history and exit")
    parser.add_argument("--resume", nargs="?", const="", default=None, metavar="ID",
                        help="Resume a previous scan (latest for target, or give a history ID) — only missing modules run")
    parser.add_argument("--no-history", action="store_true", help="Do not auto-save this scan to history")
    parser.add_argument("--nuclei-templates", metavar="DIR", default=None,
                        help="Custom nuclei template path/dir (used by -a nuclei)")
    parser.add_argument("-V", "--version", action="version", version=f"NULLVEIL Recon v{__version__} | Owner: NULLVEIL | Engine: DeepHat")
    args = parser.parse_args()

    if args.history:
        any_recon = WebsiteRecon("example.com")   # only to reach history helpers
        entries = any_recon._history_list()
        console.print("[bold cyan]NULLVEIL Scan History[/]  [dim](~/.nullveil/history)[/]\n")
        if not entries:
            console.print("  [yellow]No saved scans yet.[/] Run a scan first — every scan auto-saves here.")
        else:
            ht = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_blue")
            ht.add_column("ID", style="bold cyan")
            ht.add_column("Target", style="bold")
            ht.add_column("When")
            ht.add_column("Modules", justify="right")
            ht.add_column("Dur", justify="right")
            for e in entries[:40]:
                ht.add_row(str(e.get("id", "?")), str(e.get("domain", "?"))[:40],
                           str(e.get("when", ""))[:16],
                           str(len(e.get("modules_run", []))),
                           f"{e.get('duration_s', 0)}s")
            console.print(ht)
            console.print("\n[dim]Resume: nullveil <target> --resume [ID][/]")
        return

    if args.list_attacks:
        console.print("[bold cyan]NULLVEIL Attack Modules[/]")
        console.print("")
        for name, idx, title, desc in ATTACK_MODULES:
            console.print(f"  [bold yellow]{idx}[/] = [bold cyan]{title:<22}[/] [dim]({name})[/] — {desc}")
        console.print("\n[bold white]Usage:[/]")
        console.print("  [white]nullveil <target> -a 1,2,5[/]      [dim]# number diye select[/]")
        console.print("  [white]nullveil <target> -a dns,ssl[/]     [dim]# naam diye select[/]")
        console.print("  [white]nullveil <target> -m[/]             [dim]# interactive menu (recommended)[/]")
        console.print("  [white]nullveil <target>[/]                [dim]# default = ALL modules[/]")
        return

    if not args.target:
        parser.print_help()
        console.print("\n[red]Error:[/] target is required (unless using --list-attacks)")
        sys.exit(1)

    # Attack selection: -m menu > -a list > default ALL
    if args.menu:
        attack_indices = attack_menu(args.target)
    elif args.attack is not None:
        attack_indices = parse_attack_list(args.attack)
        if not attack_indices:
            console.print(f"[bold red]Invalid attack list:[/] {args.attack}")
            console.print("[dim]Use -l or --list-attacks to see available modules[/]")
            sys.exit(1)
    else:
        attack_indices = list(range(1, MAX_MODULE + 1))
    ports = None
    if args.ports:
        try:
            ports = sorted(set(int(p.strip()) for p in args.ports.split(',') if p.strip()))
        except ValueError:
            print("[!] Invalid --ports value. Example: --ports 80,443,8080")
            sys.exit(1)

    recon = WebsiteRecon(
        args.target,
        deep=args.deep,
        timeout=args.timeout,
        concurrency=args.concurrency,
        ports=ports,
        wordlist=args.wordlist,
    )
    recon.attack_set = attack_indices
    if args.hibp_key:
        os.environ.setdefault('HIBP_API_KEY', args.hibp_key)
    try:
        recon.correlate_list = args.correlate
    except Exception:
        pass
    try:
        recon.dot_path = args.dot
    except Exception:
        pass
    recon.nuclei_templates = args.nuclei_templates
    recon.no_history = args.no_history
    if args.resume is not None:
        entry = recon._history_load(args.resume or None)
        if entry:
            recon.resume_entry = entry
        else:
            console.print(f"[yellow]No history entry found{' for ' + args.resume if args.resume else ' for ' + recon.domain}[/]"
                          f" — running a fresh scan.")

    try:
        report = asyncio.run(recon.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")
        sys.exit(130)

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            console.print(f"\n[bold green]Report saved:[/] {args.output}")
        except Exception as e:
            console.print(f"\n[bold red]Could not save report:[/] {e}")

    if args.html:
        try:
            recon.export_html(args.html)
            console.print(f"[bold green]HTML report saved:[/] {args.html}")
        except Exception as e:
            console.print(f"[bold red]Could not save HTML report:[/] {e}")

    try:
        if getattr(args, 'repro', None):
            outp = recon.export_repro(args.repro)
            console.print(f"[bold green]Repro pack saved:[/] {outp}")
    except Exception as e:
        console.print(f"[bold red]Failed to export repro:[/] {type(e).__name__} — {e}")


if __name__ == "__main__":
    main()
