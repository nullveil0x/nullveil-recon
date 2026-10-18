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
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import ipaddress

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

__version__ = "1.1.0"

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
        print_banner()
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
        ]
        # Filter by attack set and create coroutines only for selected
        modules = []
        for name, fn, idx in all_modules:
            if idx in self.attack_set:
                modules.append((name, fn(), idx))

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

        self.scan_duration = (datetime.now() - scan_start).total_seconds()

        await self.client.aclose()
        self.print_report()
        return self.export_dict()

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
            "modules_run": [ATTACK_MODULES[i - 1][0] for i in sorted(self.attack_set) if 0 < i <= MAX_MODULE],
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
                        help="Comma-separated modules: 1=dns,2=sub,3=ports,4=http,5=ssl,6=content,7=robots,8=paths,9=users,10=api,11=waf,12=email or 'all'")
    parser.add_argument("-m", "--menu", action="store_true", help="Interactive attack selection menu")
    parser.add_argument("-l", "--list-attacks", action="store_true", help="List available attack modules")
    parser.add_argument("-V", "--version", action="version", version=f"NULLVEIL Recon v{__version__} | Owner: NULLVEIL | Engine: DeepHat")
    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
