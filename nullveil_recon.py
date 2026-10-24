#!/usr/bin/env python3
"""
NULLVEIL Recon - Website & Domain Reconnaissance Tool
Owner/Author: NULLVEIL
Engine: DeepHat
Version: 3.9.0

Features (48 attack modules):
  Recon & discovery
  - DNS Records (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA) + DoH fallback
  - Subdomain Enumeration (wordlist + SSL SAN + crt.sh CT logs)
  - Port Scanning (async TCP, top ports + deep set)
  - HTTP Analysis (headers, security headers, tech stack)
  - SSL/TLS Certificate Analysis + TLS 1.0-1.3 cipher deep audit
  - Content & Data Leakage Analysis (emails, IPs, phones, comments, secrets)
  - Robots.txt & Sitemap.xml parsing
  - Hidden Path / Admin Panel Discovery
  - User/Author Enumeration (WP REST API, ?author=, oEmbed)
  - WAF / CDN Detection, Email Security (SPF/DKIM/DMARC/MTA-STS/BIMI)
  - External Intelligence (CT logs, Wayback, subdomain takeover)
  - CVE & Misconfig Scan, Supply Chain / third-party risk mapping
  - Asset Criticality scoring, ML Anomaly Detection
  - Threat Intel feeds, Breach monitoring, Compliance mapping
  - Attack Path Graph, multi-target correlation
  - Scan-diff change tracking (new subdomains / ports / paths / APIs vs last scan)

  Tier-1 advanced discovery (v3.7.0)
  - JS Secret & Source-Map Miner: source maps, webpack chunks, API keys/tokens, dangerous sinks
  - Historical URL Miner: Wayback / CommonCrawl / OTX — forgotten endpoints & old params
  - Hidden Parameter Miner: Arjun-style GET/POST discovery via response-diff (read-only)
  - GraphQL Deep Audit: introspection, field suggestions, depth-limit checks (query-only)
  - Cloud Storage Enumeration: S3 / Azure / GCP bucket existence + public-list checks (HEAD/GET)

  API discovery & exploitation surface (report-only)
  - API & Full Site Intel (Swagger/OpenAPI probe + parse, JS endpoints, forms)
  - API Security Audit (OWASP API Top 10)
  - Deep Crawler & Params, Screenshot capture, Nuclei template scan
  - Authenticated scan + role diff + backend/admin API audit (session injection)

  Remediation & delivery
  - AI Patch & Remediation Generator (nginx / Cloudflare WAF / code-level fixes)
  - Read-Only PoC Verification Generator (non-destructive curl/dig/openssl)
  - Multi-Channel Webhook Notifications (Slack / Telegram / Discord / Teams)
  - Executive C-Level Report Exporter (HTML + PDF, compliance highlights)
  - Smart deduplication + strict per-module timeouts

  External tool integrations (graceful degradation when absent)
  - Katana crawler       (ProjectDiscovery)  -> URL/JS/endpoint harvesting
  - LinkFinder           (JS analysis)       -> hidden API endpoints
  - FFUF                 (fuzzing)           -> content/API brute-force
  - Nuclei               (templates)         -> vuln template engine
  - Burp Suite / Caido   (traffic bridge)    -> --proxy routing + --har import
  - interactsh-client    (OOB)               -> out-of-band SSRF callbacks

  Extensibility & resilience (v3.8.0)
  - Plugin rule engine: external YAML/JSON rule sets (--rules) extend the
    built-in CVE + misconfiguration knowledge without editing the source
  - Transparent retry layer: automatic exponential backoff on 429/502/503/504
    and connection errors, honouring Retry-After (--retries / --no-retry)

  Output
  - JSON report, standalone HTML report, client-ready PDF, evidence/repro pack
  - Executive report, local web dashboard, scan history + resume (Ctrl+C-safe)

Usage:
  python3 nullveil_recon.py example.com
  python3 nullveil_recon.py example.com --deep --timeout 15 --output report.json
  python3 nullveil_recon.py example.com -m
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
from urllib.parse import urlparse, urljoin, parse_qs, unquote, quote
from collections import defaultdict, deque
import ipaddress
import os
import time
import math
import tempfile
import hashlib
import statistics
import random
import sqlite3
import threading

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
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
except ImportError as e:
    missing = getattr(e, "name", None) or str(e).split("'")[-2] if "'" in str(e) else None
    missing = missing or "unknown module"
    sys.stderr.write(
        f"\n[!] Missing dependency: {missing}\n"
        f"    Fix:  pip install -r requirements.txt\n"
        f"    Or:   pip install 'httpx[http2]' dnspython rich\n\n"
    )
    sys.exit(1)

__version__ = "3.9.0"

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

# Curated API/endpoint fuzzing wordlist for ffuf (-a ffuf). Focused on hidden
# API routes, versioned REST/GraphQL, admin/debug surfaces & framework tells.
FFUF_API_WORDLIST = [
    # --- API roots & versioning ---
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/", "api/v3", "api/v3/",
    "v1", "v1/", "v2", "v2/", "v3", "v3/", "rest", "rest/", "rest/v1", "rest/v2",
    "graphql", "graphql/", "graphiql", "graphql/console", "gql", "api/graphql",
    "v1/graphql", "v2/graphql", "playground", "altair", "graphql/v1",
    "soap", "wsdl", "rpc", "xmlrpc", "jsonrpc", "api/rpc", "api/soap",
    "api-docs", "api/docs", "docs", "docs/", "redoc", "api/explorer",
    "v2/api-docs", "v3/api-docs", "swagger", "swagger/", "swagger.json",
    "swagger/v1/swagger.json", "openapi", "openapi.json", "openapi.yaml",
    "api/openapi.json", "api/swagger.json", "swagger-ui", "swagger-resources",
    "api/swagger", "api/swagger-ui", "swagger-initializer.js",
    "api/v1/openapi.json", "api/v2/openapi.json", "api/v3/openapi.json",
    # --- Auth / identity ---
    "auth", "auth/", "api/auth", "api/auth/", "api/auth/login", "api/auth/register",
    "api/auth/refresh", "api/auth/token", "api/auth/logout", "api/auth/me",
    "login", "login/", "api/login", "logout", "register", "signup", "signin",
    "oauth", "oauth/", "oauth/authorize", "oauth/token", "oauth/callback",
    "api/oauth", "api/oauth/token", "sso", "sso/saml", "sso/oidc",
    "token", "api/token", "api/token/refresh", "jwt", "api/jwt/verify",
    "session", "api/session", "api/session/active", "me", "api/me", "user",
    "api/user", "users", "api/users", "api/users/", "api/v1/users",
    "api/v1/users/", "account", "api/account", "accounts", "api/accounts",
    "profile", "api/profile", "api/me/profile", "whoami", "api/whoami",
    "password/reset", "api/password/reset", "mfa", "api/mfa/verify", "otp",
    "api/otp", "api/otp/verify", "captcha", "api/captcha",
    # --- Common REST resources ---
    "products", "api/products", "api/products/", "api/v1/products",
    "orders", "api/orders", "api/orders/", "api/v1/orders",
    "customers", "api/customers", "api/customers/", "api/v1/customers",
    "items", "api/items", "api/items/", "carts", "api/carts",
    "payments", "api/payments", "api/payments/", "api/v1/payments",
    "invoices", "api/invoices", "api/v1/invoices", "billing", "api/billing",
    "subscriptions", "api/subscriptions", "api/v1/subscriptions",
    "posts", "api/posts", "api/posts/", "api/v1/posts", "pages", "api/pages",
    "comments", "api/comments", "api/v1/comments", "tags", "api/tags",
    "categories", "api/categories", "media", "api/media", "files", "api/files",
    "upload", "api/upload", "uploads", "api/uploads", "download", "api/download",
    "search", "api/search", "api/v1/search", "api/query", "api/filter",
    "reports", "api/reports", "api/v1/reports", "analytics", "api/analytics",
    "stats", "api/stats", "metrics", "api/metrics", "prometheus", "metrics/",
    "notifications", "api/notifications", "api/v1/notifications",
    "messages", "api/messages", "api/v1/messages", "events", "api/events",
    "webhooks", "api/webhooks", "api/v1/webhooks", "api/webhooks/",
    "inventory", "api/inventory", "api/v1/inventory", "stock", "api/stock",
    "reviews", "api/reviews", "api/v1/reviews", "ratings", "api/ratings",
    "transactions", "api/transactions", "api/v1/transactions",
    "refunds", "api/refunds", "coupons", "api/coupons", "discounts",
    "api/discounts", "shipping", "api/shipping", "api/v1/shipping",
    "locations", "api/locations", "api/v1/locations", "stores", "api/stores",
    "branches", "api/branches", "employees", "api/employees",
    "api/v1/employees", "staff", "api/staff", "api/v1/staff",
    "tickets", "api/tickets", "api/v1/tickets", "support", "api/support",
    "chats", "api/chats", "api/v1/chats", "api/chat", "api/v1/chat",
    "contacts", "api/contacts", "api/v1/contacts", "leads", "api/leads",
    "api/v1/leads", "deals", "api/deals", "api/v1/deals",
    # --- Admin / management ---
    "admin", "admin/", "admin/login", "administrator", "admin/dashboard",
    "admin/api", "admin/users", "admin/config", "admin/settings",
    "dashboard", "dashboard/", "api/dashboard", "panel", "backend",
    "manage", "management", "console", "api/console", "controlpanel",
    "cpanel", "wp-admin", "phpmyadmin", "pma", "adminer",
    "manager", "api/manager", "moderator", "api/moderator",
    # --- Debug / internal / dev ---
    "debug", "debug/", "api/debug", "api/debug/", "api/v1/debug",
    "trace", "api/trace", "dump", "api/dump", "test", "test/", "api/test",
    "dev", "dev/", "api/dev", "staging", "api/staging", "sandbox",
    "api/sandbox", "internal", "api/internal", "private", "api/private",
    "hidden", "api/hidden", "secret", "api/secret", "backup", "backups",
    "api/backup", "api/backups", "old", "api/old", "legacy", "api/legacy",
    "tmp", "temp", "api/tmp", "api/temp", "logs", "api/logs", "log",
    "api/log", "error", "api/error", "errors", "api/errors", "exception",
    "api/exception", "trace.axd", "elmah", "elmah.axd", "debug/default/view",
    "_profiler", "_profiler/phpinfo", "server-status", "server-info",
    "phpinfo", "phpinfo.php", "info.php", "test.php", "debug.php",
    "actuator", "actuator/", "actuator/health", "actuator/info",
    "actuator/env", "actuator/metrics", "actuator/mappings",
    "actuator/beans", "actuator/configprops", "actuator/dump",
    "actuator/trace", "actuator/loggers", "actuator/threaddump",
    "jolokia", "jolokia/list", "hawtio", "console/login",
    "manage/env", "management/health", "management/env",
    # --- Config / secrets exposure ---
    ".env", ".env.local", ".env.production", ".env.backup", ".env.bak",
    "config", "config/", "config.json", "config.js", "config.yml",
    "config.yaml", "config.xml", "config.php", "config.bak", "config.old",
    "settings", "settings.json", "appsettings.json", "app.config",
    "web.config", "appsettings.Development.json", "local_settings.py",
    "credentials", "credentials.json", "secrets", "secrets.json",
    "service-account.json", "key.json", "private.pem", "private.key",
    "id_rsa", ".git/HEAD", ".git/config", ".gitignore", ".svn/entries",
    ".hg/hgrc", ".DS_Store", ".idea/workspace.xml", ".vscode/settings.json",
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerenv",
    "Makefile", "pom.xml", "build.gradle", "Cargo.toml", "go.mod",
    ".travis.yml", ".gitlab-ci.yml", "Jenkinsfile", ".github/workflows",
    # --- Framework / CMS endpoints ---
    "wp-json", "wp-json/", "wp-json/wp/v2", "wp-json/wp/v2/users",
    "wp-json/wp/v2/posts", "wp-json/wp/v2/pages", "wp-login.php",
    "xmlrpc.php", "jsonapi", "jsonapi/", "graphql/wp",
    "_next/data", "api/next", "__nextjs_original-stack-frame",
    "api/auth/[...nextauth]", "api/trpc", "trpc", "api/flags",
    "_nuxt", "api/nuxt", "__webpack_hmr",
    ".well-known/openid-configuration", ".well-known/oauth-authorization-server",
    ".well-known/security.txt", ".well-known/assetlinks.json",
    ".well-known/apple-app-site-association", ".well-known/change-password",
    ".well-known/creditcard", "sitemap.xml", "robots.txt", "crossdomain.xml",
    "clientaccesspolicy.xml", "browserlink", "elmah.axd",
    # --- Data / feeds ---
    "feed", "rss", "rss.xml", "atom.xml", "feed.json", "news.json",
    "data", "data.json", "api/data", "api/v1/data", "export", "api/export",
    "import", "api/import", "api/v1/import", "report.json", "index.json",
    "listing.json", "manifest.json", "site.webmanifest", "routes.json",
    "sitemap_index.xml", "opensearch.xml",
    # --- Health / ops ---
    "health", "health/", "api/health", "api/health/", "api/v1/health",
    "healthz", "readyz", "livez", "ping", "api/ping", "status", "status/",
    "api/status", "api/status/", "api/v1/status", "version", "api/version",
    "api/version/", "api/v1/version", "info", "api/info", "api/info/",
    "api/system", "api/system/info", "api/config", "api/config/",
    "api/settings", "api/settings/", "api/v1/settings", "time", "api/time",
    "echo", "api/echo", "api/echo/", "api/reflect", "api/whois",
    # --- Upload / file managers ---
    "uploads/", "files/", "media/", "assets/", "static/", "public/",
    "storage/", "storage/uploads", "var/www", "backup.zip", "backup.tar.gz",
    "site.zip", "www.zip", "dump.sql", "database.sql", "db.sql",
    "export.csv", "users.csv", "data.csv", "backup.sql",
    # --- Method-ish probes & misc API tricks ---
    "api/v1/", "api/v2/", "api/v3/", "api/beta", "api/canary", "api/experimental",
    "api/partner", "api/partners", "api/public", "api/external",
    "api/gateway", "api/proxy", "api/redirect", "api/fetch", "api/request",
    "api/v1/login", "api/v1/register", "api/v1/token", "api/v1/me",
    "api/v1/auth/login", "api/v1/auth/register", "api/v2/auth/login",
    "api/v1/search", "api/v2/search", "api/v1/config", "api/v2/config",
    "api-docs.json", "swagger.yaml", "openapi.yml", "api/schema",
    "schema.json", "api/schema.json", "api/types", "api/models",
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
    ("katana", 28, "Katana Crawler (API)", "ProjectDiscovery katana — deep crawl, JS discovery, endpoint harvesting (needs katana binary)"),
    ("linkfinder", 29, "LinkFinder JS Endpoints", "Extract hidden API endpoints from every JS bundle (needs linkfinder)"),
    ("ffuf", 30, "FFUF API Fuzzing", "Content/API brute-force with curated API wordlist + discovered endpoints (needs ffuf binary)"),
    ("auth", 31, "Authenticated API Scan", "Login engine + session injection + role-diff probe — finds auth-gated / role-hidden APIs"),
    ("ssrf", 32, "SSRF & Internal Pivot", "IP-bypass header fuzz, cloud metadata probing, interactsh OOB callbacks (--oob)"),
    ("smartfuzz", 33, "Smart Context Fuzz", "Context-aware wordlist generation + JS data-flow endpoint resolution + targeted fuzz"),
    ("burp", 34, "Burp / Caido Traffic Bridge", "Import Burp/Caido HAR captures into the API pool + route the whole scan via --proxy for manual follow-up"),
    ("patch", 35, "AI Patch & Remediation Generator", "Template-based, read-only fix suggestions — Nginx/Cloudflare WAF config + code-level remediation per finding"),
    ("poc", 36, "Read-Only PoC Verification Generator", "Non-destructive curl/dig commands that demonstrate a finding exists — no exploit payloads, no active exploitation"),
    ("notify", 37, "Multi-Channel Webhook Notifications", "Push scan summaries to Slack / Telegram / Discord / Teams (--webhook-*) — graceful without deps"),
    ("exec", 39, "Executive Report Exporter", "C-level HTML/PDF report — exposure KPIs, top risks, PCI-DSS/ISO 27001/SOC 2 highlights, remediation priorities"),
    ("jsecret", 40, "JS Secret & Source-Map Miner", "Deep JS mining: source maps, webpack chunks, API keys/tokens, hidden endpoints, dangerous sinks (read-only)"),
    ("wayback", 41, "Historical URL Miner", "Wayback/CommonCrawl/OTX historical URLs — forgotten endpoints, old params & secrets still live (read-only)"),
    ("param", 42, "Hidden Parameter Miner", "Arjun-style GET/POST parameter discovery via response-diff + reflection analysis (read-only, rate-limited)"),
    ("gql", 43, "GraphQL Deep Audit", "Introspection, field-suggestion leakage, depth/complexity abuse checks, batching — report-only, no writes"),
    ("cloudstore", 44, "Cloud Storage Enumeration", "S3/Azure/GCP bucket existence + public-list/ACL misconfig via HEAD/GET only (no writes, no uploads)"),
    ("cvss", 45, "CVSS 4.0 / CWE Risk Scoring", "Re-score every finding with a CVSS 4.0 + 3.1 vector and a CWE weakness ID — industry-standard prioritised risk register"),
    ("attack", 46, "MITRE ATT&CK Mapping", "Map findings to MITRE ATT&CK Enterprise tactics/techniques + export a Navigator layer (JSON) — SOC/blue-team value"),
    ("cveintel", 47, "CVE Intelligence Enricher", "Offline CVE enrichment: CVSS base score, CWE, EPSS-style likelihood, CISA KEV + exploit-availability flags for every fingerprinted version"),
    ("takeover", 48, "Subdomain Takeover v3", "Standalone takeover engine — 70+ provider fingerprints, dangling CNAME + A/NS record proof (read-only, no claims)"),
    ("watch", 49, "Continuous Change Monitor", "Baseline snapshot + drift alerting for repeat scans (--watch/--interval); reports new/removed assets & risk delta"),
    ("vulnverify", 50, "Read-Only Vulnerability Verification", "Benign-marker proof for reflected XSS sinks, SQL error/boolean signature, and param-driven SSRF/path-traversal — detection only, no exploitation, no data extraction"),
]

MAX_MODULE = len(ATTACK_MODULES)

# Module numbers are not necessarily contiguous (the roadmap skips 38), so map
# a module *number* to its registry entry instead of assuming list position.
MODULE_BY_NUM = {num: (name, num, title, desc) for name, num, title, desc in ATTACK_MODULES}


def module_entry(num):
    """Return the registry tuple for a module number (safe against gaps)."""
    return MODULE_BY_NUM.get(num)


# All module *numbers* in registry order (module numbers are non-contiguous).
ALL_MODULE_NUMS = sorted(MODULE_BY_NUM)


# ============================================================ plugin rule engine
class RuleSet:
    """External rule set loaded from YAML/JSON — extends the built-in CVE and
    misconfiguration knowledge without touching the source.

    A rule file is either a single object or a list. Supported shapes::

        # rules/cve.yaml
        cve:
          - product: nginx
            major: null            # optional int, or null for "any major"
            mode: lt               # lt | le | eq | ge | gt
            version: [1, 20, 1]    # comparison boundary
            id: CVE-2021-23017
            severity: HIGH
            title: Resolver off-by-one DNS poisoning

        # rules/misconfig.yaml
        misconfig:
          - path: /.git/config
            match: "(?i)\\[core\\]"   # optional regex, null = any 2xx/403
            severity: HIGH
            id: Exposed .git config
            title: Git config public

    YAML needs ``PyYAML`` (optional); JSON always works with the stdlib.
    """

    def __init__(self):
        self.cve = []          # (product, major, mode, boundary_tuple, id, sev, title)
        self.misconfig = []    # (path, regex_or_None, sev, id, title)
        self.sources = []      # file paths that were loaded
        self.errors = []       # human-readable load problems

    # ---------------------------------------------------------- loading
    def load_paths(self, paths):
        """Load every rule file under each path (file or directory)."""
        import glob as _glob
        files = []
        for p in (paths or []):
            if not p:
                continue
            p = os.path.expanduser(str(p))
            if os.path.isdir(p):
                for ext in ("yml", "yaml", "json"):
                    files += sorted(_glob.glob(os.path.join(p, "**", f"*.{ext}"), recursive=True))
            elif os.path.isfile(p):
                files.append(p)
            else:
                self.errors.append(f"rules: path not found: {p}")
        for f in files:
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    raw = fh.read()
                data = self._parse(raw, f)
                if data is None:
                    continue
                n_cve, n_mis = self._ingest(data, f)
                if n_cve or n_mis:
                    self.sources.append(f)
            except Exception as e:
                self.errors.append(f"rules: {f}: {type(e).__name__} — {e}")
        return self

    @staticmethod
    def _parse(raw, fname):
        text = raw.lstrip()
        if fname.lower().endswith(".json") or text[:1] in "[{":
            import json as _json
            return _json.loads(raw)
        try:
            import yaml  # optional dependency
        except ImportError:
            raise RuntimeError(
                "PyYAML not installed — use .json rule files or: pip install pyyaml")
        return yaml.safe_load(raw)

    def _ingest(self, data, fname):
        n_cve = n_mis = 0
        if isinstance(data, list):
            data = {"cve": data}
        if not isinstance(data, dict):
            return 0, 0
        for item in (data.get("cve") or []):
            rec = self._cve_rule(item)
            if rec:
                self.cve.append(rec)
                n_cve += 1
            else:
                self.errors.append(f"rules: {fname}: skipped malformed cve rule: {item!r}")
        for item in (data.get("misconfig") or data.get("probe") or []):
            rec = self._mis_rule(item)
            if rec:
                self.misconfig.append(rec)
                n_mis += 1
            else:
                self.errors.append(f"rules: {fname}: skipped malformed misconfig rule: {item!r}")
        return n_cve, n_mis

    @staticmethod
    def _ver_tuple(v):
        if isinstance(v, (list, tuple)):
            parts = [re.sub(r"\D", "", str(x)) for x in v]
        else:
            parts = re.split(r"[._-]", str(v))
        out = []
        for p in parts:
            if p == "":
                continue
            if p.isdigit():
                out.append(int(p))
            else:
                break
        return tuple(out)

    @classmethod
    def _cve_rule(cls, item):
        if not isinstance(item, dict):
            return None
        prod = str(item.get("product") or "").strip().lower()
        boundary = cls._ver_tuple(item.get("version", item.get("boundary")))
        mode = str(item.get("mode") or "lt").strip().lower()
        cid = str(item.get("id") or item.get("cve") or "").strip()
        title = str(item.get("title") or "").strip()
        sev = str(item.get("severity") or "MEDIUM").strip().upper()
        if not (prod and boundary and cid):
            return None
        if mode not in ("lt", "le", "eq", "ge", "gt"):
            mode = "lt"
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "MEDIUM"
        major = item.get("major", None)
        try:
            major = int(major) if major is not None else None
        except Exception:
            major = None
        return (prod, major, mode, tuple(boundary), cid, sev, title or cid)

    @staticmethod
    def _mis_rule(item):
        if not isinstance(item, dict):
            return None
        path = str(item.get("path") or "").strip()
        if not path:
            return None
        rx = item.get("match", item.get("regex"))
        rx = str(rx) if rx else None
        if rx:
            try:
                re.compile(rx)          # fail fast on bad patterns
            except re.error:
                rx = None
        sev = str(item.get("severity") or "MEDIUM").strip().upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "MEDIUM"
        pid = str(item.get("id") or path).strip()
        title = str(item.get("title") or pid).strip()
        return (path, rx, sev, pid, title)

    def summary(self):
        return {"files": list(self.sources), "cve_rules": len(self.cve),
                "misconfig_rules": len(self.misconfig), "errors": list(self.errors)}


# ============================================================ timeline DB
class TimelineDB:
    """SQLite-backed scan timeline (``--timeline``).

    Every completed scan is appended to a small, queryable database so an
    operator can answer questions a pile of JSON files cannot: *how has the
    exposure score moved over time?* *when did this subdomain first appear?*
    *which run introduced this finding?*

    The DB is deliberately **append-only and additive** — it is a *second*
    index next to the JSON history, never a replacement. If the DB is missing or
    unwritable the scan is completely unaffected (every method swallows errors):
    the timeline is a convenience, not a dependency.

    Schema (v1)::

        scans(id, when, target, domain, version, duration_s, score, verdict,
              mode, modules, high, critical, secrets, subdomains, ports, paths,
              report_json)
        findings(scan_id, severity, check, detail, source)
        assets(scan_id, kind, value)

    ``assets`` is what makes drift queries cheap: one row per discovered asset
    (subdomain, port, path, …) so "when did X first appear" is a single
    indexed lookup instead of a full-scan diff.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path=None):
        self.path = os.path.expanduser(path or self.default_path())
        self.conn = None
        self.enabled = False
        self.error = None
        # guards writes when one TimelineDB is shared across threads; a no-op
        # for the normal one-DB-per-worker case
        self._lock = threading.Lock()
        self._init_db()

    @staticmethod
    def default_path():
        return os.path.join(WebsiteRecon.HISTORY_DIR, "timeline.db")

    # ---------------------------------------------------------------- setup
    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            # check_same_thread=False + self._lock: safe whether each worker owns
            # its own DB handle or a single handle is shared across threads.
            # timeout=30 + busy_timeout: parallel workers (--workers N) may open
            # the same DB file at once; without a busy timeout the loser of the
            # journal-mode switch raises "database is locked" immediately.
            self.conn = sqlite3.connect(self.path, timeout=30,
                                        check_same_thread=False)
            self.conn.execute("PRAGMA busy_timeout=30000")
            # switching to WAL needs a brief exclusive lock — retry a few times
            for _attempt in range(20):
                try:
                    self.conn.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError:
                    time.sleep(0.1)
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT, target TEXT, domain TEXT, version TEXT,
                    duration_s REAL, score INTEGER, verdict TEXT, mode TEXT,
                    modules TEXT, high INTEGER, critical INTEGER,
                    secrets INTEGER, subdomains INTEGER, ports INTEGER,
                    paths INTEGER, report_json TEXT);
                CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
                CREATE INDEX IF NOT EXISTS idx_scans_when   ON scans(scanned_at);
                CREATE TABLE IF NOT EXISTS findings (
                    scan_id INTEGER, severity TEXT, check_name TEXT,
                    detail TEXT, source TEXT);
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE TABLE IF NOT EXISTS assets (
                    scan_id INTEGER, kind TEXT, value TEXT);
                CREATE INDEX IF NOT EXISTS idx_assets_kv ON assets(kind, value);
                CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
                """
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),))
            self.conn.commit()
            self.enabled = True
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
            self.enabled = False

    def close(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass

    # ---------------------------------------------------------------- write
    def record(self, report, recon=None):
        """Append one finished scan. Returns the new scan id (or None)."""
        if not self.enabled or not isinstance(report, dict):
            return None
        # Serialise writes through the handle lock (matters only when a single
        # TimelineDB is shared across threads) and retry briefly on
        # "database is locked" instead of silently dropping the row.
        last_err = None
        with self._lock:
            for _attempt in range(6):
                try:
                    return self._record_once(report, recon)
                except sqlite3.OperationalError as e:
                    last_err = e
                    if "lock" in str(e).lower():
                        time.sleep(0.2 * (_attempt + 1))
                        continue
                    self.error = f"{type(e).__name__}: {e}"
                    return None
                except Exception as e:
                    self.error = f"{type(e).__name__}: {e}"
                    return None
        if last_err is not None:
            self.error = f"{type(last_err).__name__}: {last_err}"
        return None

    def _record_once(self, report, recon=None):
        if not self.enabled or not isinstance(report, dict):
            return None
        summ = report.get("summary", {}) or {}
        score = None
        verdict = None
        if recon is not None:
            try:
                sc = _batch_score(report)
                if isinstance(sc, dict):
                    score, verdict = sc.get("score"), sc.get("verdict")
            except Exception:
                pass
        if score is None:
            score = summ.get("exposure_score")
        when = report.get("started") or datetime.now().isoformat()
        cur = self.conn.execute(
            """INSERT INTO scans(scanned_at, target, domain, version, duration_s,
                    score, verdict, mode, modules, high, critical, secrets,
                    subdomains, ports, paths, report_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (when, report.get("target", ""), report.get("target", ""),
             report.get("version", __version__),
             report.get("duration_s"), score, verdict, report.get("mode", ""),
             ",".join(report.get("modules_run", []) or []),
             int(summ.get("high", 0) or 0), int(summ.get("critical", 0) or 0),
             int(summ.get("secrets", 0) or 0), int(summ.get("subdomains", 0) or 0),
             int(summ.get("open_ports", 0) or 0), int(summ.get("paths", 0) or 0),
             json.dumps(report, ensure_ascii=False, default=str)))
        scan_id = cur.lastrowid

        # findings need the live recon object (they are a flattened view of
        # it); assets come straight from the report so they are always
        # indexed — that is what makes first-seen queries cheap.
        if recon is not None:
            try:
                for sev, chk, det, src in recon._collect_findings():
                    self.conn.execute(
                        "INSERT INTO findings(scan_id, severity, check_name, detail, source) "
                        "VALUES(?,?,?,?,?)",
                        (scan_id, sev, chk, det[:400], src))
            except Exception:
                pass
        try:
            for kind, values in self._asset_rows(report).items():
                for v in values:
                    self.conn.execute(
                        "INSERT INTO assets(scan_id, kind, value) VALUES(?,?,?)",
                        (scan_id, kind, str(v)[:400]))
        except Exception:
            pass
        self.conn.commit()
        return scan_id

    @staticmethod
    def _asset_rows(report):
        """Flatten a report into {kind: [values]} for the assets table."""
        out = {}
        for kind, key in (("subdomain", "subdomains"), ("port", "open_ports"),
                          ("tech", "tech_stack")):
            vals = [str(x) for x in (report.get(key) or []) if x]
            if vals:
                out[kind] = vals
        paths = []
        for p in (report.get("paths") or []):
            if isinstance(p, dict) and p.get("path"):
                paths.append(p["path"])
            elif p:
                paths.append(str(p))
        if paths:
            out["path"] = paths
        return out

    # ---------------------------------------------------------------- read
    def history(self, domain=None, limit=50):
        """Newest-first scan rows (without the heavy report blob)."""
        if not self.enabled:
            return []
        try:
            q = ("SELECT id, scanned_at, target, domain, version, duration_s, score, "
                 "verdict, mode, high, critical, secrets, subdomains, ports, paths "
                 "FROM scans")
            args = []
            if domain:
                q += " WHERE domain = ?"
                args.append(domain)
            q += " ORDER BY id DESC LIMIT ?"
            args.append(int(limit))
            cols = ["id", "scanned_at", "target", "domain", "version", "duration_s",
                    "score", "verdict", "mode", "high", "critical", "secrets",
                    "subdomains", "ports", "paths"]
            return [dict(zip(cols, row)) for row in self.conn.execute(q, args).fetchall()]
        except Exception:
            return []

    def trend(self, domain, limit=30):
        """Score-over-time series for one domain, oldest-first."""
        rows = self.history(domain, limit=limit)
        return list(reversed([{"when": r["scanned_at"], "score": r["score"],
                               "verdict": r["verdict"]} for r in rows]))

    def first_seen(self, kind, value):
        """Scan id/when a particular asset value first appeared."""
        if not self.enabled:
            return None
        try:
            row = self.conn.execute(
                "SELECT a.scan_id, s.scanned_at, s.domain FROM assets a "
                "JOIN scans s ON s.id = a.scan_id "
                "WHERE a.kind = ? AND a.value = ? ORDER BY a.scan_id ASC LIMIT 1",
                (kind, str(value))).fetchone()
            if row:
                return {"scan_id": row[0], "when": row[1], "domain": row[2]}
        except Exception:
            pass
        return None

    def latest(self, domain=None):
        h = self.history(domain, limit=1)
        return h[0] if h else None

    def stats(self):
        if not self.enabled:
            return {"enabled": False, "path": self.path, "error": self.error,
                    "scans": 0, "domains": 0, "findings": 0, "assets": 0}
        try:
            scans = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            domains = self.conn.execute("SELECT COUNT(DISTINCT domain) FROM scans").fetchone()[0]
            findings = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            assets = self.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            return {"enabled": True, "path": self.path, "error": None,
                    "scans": scans, "domains": domains, "findings": findings,
                    "assets": assets}
        except Exception as e:
            return {"enabled": True, "path": self.path, "error": str(e),
                    "scans": 0, "domains": 0, "findings": 0, "assets": 0}

    def summary(self):
        return self.stats()


# ============================================================ evasion transport
# Coherent, browser-like request profiles. Each profile is a *set* of headers
# that belong together (a real Chrome does not send a Firefox UA with a Safari
# Accept-Language), so rotating between them stays believable instead of
# producing the header mish-mash that naive evasion scripts leak.
_EVASION_PROFILES = [
    {  # Chrome / Windows
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Chrome / macOS
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Firefox / Windows
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
                      "Gecko/20100101 Firefox/125.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Safari / macOS
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                      "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
]

# Evasion levels → (rotate_ua, jitter_max_seconds, extra_headers)
#   none  : no evasion at all (fastest, most obvious)
#   light : rotate the browser profile per request + small jitter
#   stealth: rotate + coherence-preserving header order + wider jitter
_EVASION_LEVELS = {
    "none":    {"rotate": False, "jitter": 0.0,  "coherent": False},
    "light":   {"rotate": True,  "jitter": 0.25, "coherent": False},
    "stealth": {"rotate": True,  "jitter": 0.8,  "coherent": True},
}


class EvasionTransport(httpx.AsyncBaseTransport):
    """WAF-evasion layer: per-request browser-profile rotation + request jitter.

    Sits *below* the retry layer and *above* the real transport, so it sees
    every request the scan issues. It rewrites the request headers to a
    coherent, real-browser profile (rotating between them) and introduces a
    small random delay, which smooths the machine-gun signature that gets a
    scanner rate-limited or fingerprinted in the first place.

    It is deliberately **not** a WAF bypass tool: it never forges auth, never
    tampers with payloads and never mutates the target's state — it only makes
    the scan's *own* traffic look like an ordinary visitor's.
    """

    def __init__(self, transport, level="light", rotate_every=1):
        self._transport = transport
        self.level = level if level in _EVASION_LEVELS else "none"
        self.cfg = _EVASION_LEVELS[self.level]
        self.rotate_every = max(1, int(rotate_every))
        self._count = 0
        self._idx = random.randrange(len(_EVASION_PROFILES))
        self.requests = 0     # total requests rewritten (scan-level metric)

    async def handle_async_request(self, request):
        self._count += 1
        self.requests += 1
        if self.cfg["rotate"] and self._count % self.rotate_every == 0:
            self._idx = (self._idx + 1) % len(_EVASION_PROFILES)
        if self.cfg["rotate"]:
            profile = _EVASION_PROFILES[self._idx]
            # Build a fresh header block: the profile wins, but we keep the
            # scanner's own identity header out of the way and preserve any
            # auth header the session layer injected.
            keep = {}
            for k, v in request.headers.items():
                lk = k.lower()
                if lk in ("authorization", "cookie", "x-api-key", "x-auth-token"):
                    keep[k] = v
            new_headers = list(profile.items()) + list(keep.items())
            try:
                request.headers = httpx.Headers(new_headers)
            except Exception:
                for k, v in profile.items():
                    request.headers[k] = v
        if self.cfg["jitter"]:
            await asyncio.sleep(random.uniform(0, self.cfg["jitter"]))
        return await self._transport.handle_async_request(request)


# ============================================================ plugin system
class PluginContext:
    """Read-only view of a finished scan handed to a plugin's ``run()``.

    Plugins are ordinary Python modules loaded from a path (``--plugin``). They
    receive this context, may read any result the scan produced, and return a
    list of findings ``(severity, check, detail)`` — or nothing.

    The context is deliberately **read-only-ish**: a plugin *can* reach the
    live ``recon`` object, but the documented surface is the helpers below.
    """

    def __init__(self, recon):
        self.recon = recon
        self.results = recon.results
        self.report = None       # filled by the engine after run()
        self.target = getattr(recon, "domain", "")
        self.base_url = getattr(recon, "base_url", "")
        self.version = __version__

    # convenience accessors ------------------------------------------------
    def get(self, key, default=None):
        return self.results.get(key, default)

    def summary(self):
        return (self.report or {}).get("summary", {})

    def findings(self):
        """The flat, normalised finding list every reporting module sees."""
        try:
            return self.recon._collect_findings()
        except Exception:
            return []

    def log(self, msg):
        console.print(f"[dim cyan]plugin:[/] {msg}")


class PluginManager:
    """Load and run external Python plugin modules (``--plugin``).

    A plugin is a ``.py`` file that defines ``def run(ctx)`` (required) and
    optionally ``NAME`` / ``VERSION`` module attributes. ``run`` may return an
    iterable of ``(severity, check, detail)`` tuples — each becomes a normal
    finding that flows into CVSS, ATT&CK, remediation, the report and
    notifications.

    Safety: loading a plugin executes arbitrary local Python. It is an
    **operator-supplied** file, exactly like a build script — only load plugins
    you trust.
    """

    def __init__(self):
        self.plugins = []      # (name, module)
        self.errors = []
        self.produced = 0

    def load_paths(self, paths):
        import importlib.util
        for p in (paths or []):
            if not p:
                continue
            p = os.path.expanduser(str(p))
            if not os.path.isfile(p):
                self.errors.append(f"plugin: not found: {p}")
                continue
            name = os.path.splitext(os.path.basename(p))[0]
            try:
                spec = importlib.util.spec_from_file_location(f"nv_plugin_{name}", p)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if not hasattr(mod, "run") or not callable(mod.run):
                    self.errors.append(f"plugin {name}: no callable run(ctx)")
                    continue
                self.plugins.append((name, mod))
            except Exception as e:
                self.errors.append(f"plugin {name}: load failed: {type(e).__name__}: {e}")
        return self

    def summary(self):
        return {"files": [n for n, _ in self.plugins], "loaded": len(self.plugins),
                "findings": self.produced, "errors": list(self.errors)}

    def run_all(self, ctx):
        """Run every plugin, collecting findings into the scan results."""
        for name, mod in self.plugins:
            label = getattr(mod, "NAME", name)
            try:
                out = mod.run(ctx)
                n = 0
                for item in (out or []):
                    if isinstance(item, (list, tuple)) and len(item) >= 3:
                        ctx.results['plugin_findings'].append(
                            (str(item[0]).upper(), str(item[1]), str(item[2])))
                        n += 1
                    elif isinstance(item, str):
                        ctx.results['plugin_findings'].append(("INFO", label, item))
                        n += 1
                self.produced += n
                ctx.results['plugin_runs'].append({"plugin": label, "findings": n, "ok": True})
                if n:
                    ctx.log(f"{label}: {n} finding(s)")
            except Exception as e:
                self.errors.append(f"plugin {name}: run failed: {type(e).__name__}: {e}")
                ctx.results['plugin_runs'].append({"plugin": label, "findings": 0,
                                                   "ok": False, "error": str(e)})
        return self


# ============================================================ plugin system end


# ============================================================ retrying transport
class RetryingTransport(httpx.AsyncBaseTransport):
    """Transparently retry transient failures (429/503/502/504 + connection
    errors) with exponential backoff + jitter, honouring ``Retry-After``.

    Wrapping the transport means *every* request the scan makes — discovery,
    audit, fuzzing — gets resilience without changing a single call site, which
    keeps the tool polite under rate-limiting instead of silently dropping data.
    """

    _RETRY_STATUS = {429, 502, 503, 504}

    def __init__(self, transport, max_retries=2, base=0.5, respect_retry_after=True):
        self._transport = transport
        self.max_retries = max(0, int(max_retries))
        self.base = float(base)
        self.respect_retry_after = respect_retry_after
        self.retries = 0          # total retried requests (scan-level metric)

    async def handle_async_request(self, request):
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self._transport.handle_async_request(request)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError,
                    httpx.ConnectTimeout, httpx.PoolTimeout) as e:
                last_exc = e
                if attempt >= self.max_retries:
                    raise
                await asyncio.sleep(self._delay(attempt, None))
                self.retries += 1
                continue
            if resp.status_code in self._RETRY_STATUS and attempt < self.max_retries:
                delay = self._delay(attempt, resp)
                try:
                    await resp.aclose()
                except Exception:
                    pass
                await asyncio.sleep(delay)
                self.retries += 1
                continue
            return resp
        if last_exc:
            raise last_exc
        raise httpx.TransportError("retry budget exhausted")

    def _delay(self, attempt, resp):
        if self.respect_retry_after and resp is not None:
            ra = resp.headers.get("retry-after")
            if ra:
                try:
                    return min(10.0, max(0.0, float(ra)))
                except Exception:
                    pass
        delay = self.base * (2 ** attempt)
        return min(8.0, delay) + random.uniform(0, delay / 2 or 0.1)


def parse_attack_list(s: str):
    s = s.lower().strip()
    if s in ("all", "full", "*"):
        return list(ALL_MODULE_NUMS)
    items = [x.strip().lower() for x in s.split(',') if x.strip()]
    res = set()
    unknown = []
    for it in items:
        if it.isdigit():
            m = int(it)
            if m in MODULE_BY_NUM:
                res.add(m)
            else:
                unknown.append(it)
            continue
        hit = False
        for name, idx, *_ in ATTACK_MODULES:
            if it == name or (name == "sub" and it in ("subdomains", "subdomain")) or (name == "paths" and it in ("admin", "dirs")):
                res.add(idx)
                hit = True
            elif name == "cloudstore" and it in ("cloud", "bucket", "buckets", "storage"):
                res.add(idx)
                hit = True
            elif name == "jsecret" and it in ("js", "jssecret"):
                res.add(idx)
                hit = True
            elif name == "gql" and it in ("graphql",):
                res.add(idx)
                hit = True
            elif name == "wayback" and it in ("history", "historical", "gau"):
                res.add(idx)
                hit = True
            elif name == "param" and it in ("params", "parameters", "arjun"):
                res.add(idx)
                hit = True
            elif name == "cvss" and it in ("cvss4", "cvss31", "scoring", "risk"):
                res.add(idx)
                hit = True
            elif name == "attack" and it in ("mitre", "attck", "attack-map", "tactics"):
                res.add(idx)
                hit = True
            elif name == "cveintel" and it in ("cve-intel", "kev", "cveinfo"):
                res.add(idx)
                hit = True
            elif name == "takeover" and it in ("takeover3", "takeover-v3", "dangling"):
                res.add(idx)
                hit = True
            elif name == "watch" and it in ("monitor", "drift", "change"):
                res.add(idx)
                hit = True
            elif name == "vulnverify" and it in ("vuln", "verify", "xss", "sqli", "traversal",
                                                 "vulnverify", "vuln-verify", "proof"):
                res.add(idx)
                hit = True
        if not hit:
            unknown.append(it)
    if unknown:
        console.print(f"[yellow]⚠ Unknown module name(s) ignored:[/] [bold]{', '.join(unknown)}[/]  "
                      f"[dim](see -l for the full list)[/]")
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
            return list(ALL_MODULE_NUMS)
        if not choice:
            return list(ALL_MODULE_NUMS)
        parsed = parse_attack_list(choice)
        if parsed:
            sel = ", ".join(str(i) for i in parsed)
            names = ", ".join(module_entry(i)[2] for i in parsed if module_entry(i))
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


def _norm_ports(v):
    """Normalise a port collection to a clean list of ints (dashboard-safe).

    Accepts ints, strings ("443", "443/tcp"), or dicts ({port, service} /
    {number, name}) and dedupes while preserving numeric order."""
    out = set()
    for p in (v or []):
        n = None
        if isinstance(p, dict):
            n = p.get("port", p.get("number"))
        elif p is not None and str(p) != "":
            n = str(p).split('/')[0].strip()
        if n is None:
            continue
        try:
            out.add(int(str(n).strip()))
        except Exception:
            continue
    return sorted(out)


def _norm_paths(v):
    """Normalise a path collection to a list of {'path','status','source'} dicts."""
    out, seen = [], set()
    for p in (v or []):
        if isinstance(p, dict):
            path = str(p.get("path") or p.get("url") or "").strip()
            if not path:
                continue
            rec = {"path": path}
            if p.get("status") is not None:
                rec["status"] = p.get("status")
            if p.get("flagged"):
                rec["flagged"] = True
            if p.get("source"):
                rec["source"] = p.get("source")
        else:
            if p is None:
                continue
            path = str(p).strip()
            if not path:
                continue
            rec = {"path": path}
        if path in seen:
            continue
        seen.add(path)
        out.append(rec)
    return out


def _wrap(text, width):
    """Wrap ``text`` to ``width`` characters (used by the reportlab PDF fallback)."""
    words, lines, cur = str(text).split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines or [""]


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
    def __init__(self, url, deep=False, timeout=10, concurrency=100, ports=None, wordlist=None, proxy=None):
        url = url.strip()
        self.proxy = (proxy or "").strip()
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
        self.attack_set = list(ALL_MODULE_NUMS)  # all modules
        # --- resilience: retry/backoff on transient throttling (429/503) ---
        # set BEFORE _build_transport so the retrying transport is used on the
        # very first client this constructor creates.
        self.max_retries = 2
        self.backoff_base = 0.5
        # --- WAF evasion (--evade): default off, wired from CLI in main() ---
        self.evade_level = "none"
        self.evade_rotate_every = 1
        # --- deep verification pass (--verify): default off ---
        self.deep_verify = False
        self._build_transport(concurrency)
        # --- authenticated / OOB scanning state (CLI flags wired in main) ---
        self.auth_cfg = {}     # --auth-* / --login-* / --role flags
        self.oob_cfg = {}      # --oob / --oob-server / --oob-wait flags
        self.roles = {}        # multi-role profiles (parsed during auth setup)
        self._auth_cmd = []    # "Name: value" strings for subprocess tools
        self.ruleset = None    # external --rules plugin set (wired in main)
        self.plugins = None    # external --plugin Python modules (wired in main)
        self.timeline_db = None  # SQLite timeline (--timeline; wired in main)

    def _build_transport(self, concurrency=None):
        """Create the shared httpx client + concurrency semaphore.

        Called from ``__init__`` and again at the start of every ``run()`` so
        continuous ``--watch`` runs get a transport bound to the *current* event
        loop (a client/semaphore created under a previous ``asyncio.run()`` is
        dead once that loop closes)."""
        concurrency = concurrency or self.concurrency
        # Build the low-level transport ourselves so it can be wrapped with the
        # retry/backoff layer (429/503 + connection errors). http2/proxy/verify
        # all keep working because the httpcore transport still handles them.
        limits = httpx.Limits(max_connections=max(concurrency, 100),
                              max_keepalive_connections=40,
                              keepalive_expiry=30.0)
        self._retry_transport = None
        try:
            base_transport = httpx.AsyncHTTPTransport(
                verify=False,               # recon: expired/self-signed certs still interesting
                http2=True,
                limits=limits,
                proxy=self.proxy or None,   # Burp/Caido intercepting proxy (--proxy)
                retries=0,                  # we handle retries ourselves
            )
            # WAF-evasion layer (--evade) sits closest to the wire: it rewrites
            # each request to a coherent browser profile before it is sent.
            self._evasion_transport = None
            level = getattr(self, "evade_level", "none") or "none"
            if level != "none" and level in _EVASION_LEVELS:
                self._evasion_transport = EvasionTransport(
                    base_transport, level=level,
                    rotate_every=getattr(self, "evade_rotate_every", 1))
                transport = self._evasion_transport
            else:
                transport = base_transport
            if getattr(self, "max_retries", 0):
                self._retry_transport = RetryingTransport(
                    transport,
                    max_retries=self.max_retries,
                    base=getattr(self, "backoff_base", 0.5))
                transport = self._retry_transport
        except Exception:
            transport = None
            limits = httpx.Limits(max_connections=max(concurrency, 100),
                                  max_keepalive_connections=40,
                                  keepalive_expiry=30.0)
        kw = dict(
            follow_redirects=True,
            timeout=self.timeout,
            verify=False,
            limits=limits,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                   f"(KHTML, like Gecko) Chrome/124.0 Safari/537.36 NULLVEIL-Recon/{__version__}"}
        )
        if transport is not None:
            kw["transport"] = transport
        else:
            # fallback: plain client (no custom transport)
            kw["http2"] = True
            kw["proxy"] = self.proxy or None
        self.client = httpx.AsyncClient(**kw)
        self.sem = None
        try:
            self.sem = asyncio.Semaphore(concurrency)
        except RuntimeError:
            # Python 3.9 requires a running event loop to construct a Semaphore
            # (3.10+ binds lazily). Defer creation to the first run() inside a loop.
            self._sem_concurrency = concurrency

    def _ensure_sem(self):
        """Bind the concurrency semaphore to the current event loop if needed.

        On Python 3.9 ``asyncio.Semaphore()`` cannot be constructed without a
        running loop, so it is created lazily here — called from ``run()`` where
        a loop is guaranteed."""
        if self.sem is None:
            self.sem = asyncio.Semaphore(
                getattr(self, "_sem_concurrency", self.concurrency))

    # ---------------------------------------------------------- run
    async def run(self):
        # Fresh transport every run so continuous --watch runs get a client +
        # semaphore bound to the current event loop (the previous one is dead).
        old_client = getattr(self, "client", None)
        if old_client is not None:
            try:
                await old_client.aclose()
            except Exception:
                pass
        try:
            self._build_transport()
        except Exception:
            pass
        self._ensure_sem()
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
                       if (module_entry(i) or ("",))[0] not in done]
            skipped = len(self.attack_set) - len(missing)
            # keep the already-done selection so the final report shows the full picture
            self._resume_done = [i for i in self.attack_set
                                 if (module_entry(i) or ("",))[0] in done]
            self.attack_set = missing
            resume_note = (f"Resumed from scan [bold cyan]{entry.get('id')}[/] "
                           f"({entry.get('when', '')[:16]}) — {skipped} module(s) already done, "
                           f"{len(missing)} remaining.")
        print_banner()
        if resume_note:
            console.print(f"      {resume_note}")
        module_names = ", ".join((module_entry(i) or ("",))[0]
                                 for i in self.attack_set if module_entry(i)) if self.attack_set else "none"
        console.print(f"      [dim]Target:[/] [bold magenta]{self.domain}[/]   "
                      f"[dim]Mode:[/] [bold {'red' if self.deep else 'green'}]"
                      f"{'DEEP' if self.deep else 'NORMAL'}[/]   "
                      f"[dim]Started:[/] [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")
        console.print(f"      [dim]Attacks:[/] [bold cyan]{module_names}[/]  "
                      f"[dim]({len(self.attack_set)}/{MAX_MODULE} modules)[/]\n")
        if self.wordlist_error:
            console.print(f"      [bold yellow]⚠ {self.wordlist_error}[/]\n")
        # ---------- authenticated scanning: inject session & run login FIRST,
        # so every module (httpx + katana/ffuf/nuclei subprocesses) shares it ----
        if self.auth_cfg:
            try:
                await self._auth_setup()
            except Exception as e:
                self.results['errors'].append(f"auth setup failed: {type(e).__name__} — {e}")

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
            (":satellite: Katana Crawler (API)", self.katana_crawl, 28),
            (":mag: LinkFinder JS Endpoints", self.linkfinder_scan, 29),
            (":bomb: FFUF API Fuzzing", self.ffuf_fuzz, 30),
            (":key: Authenticated API Scan", self.auth_scan, 31),
            (":satellite: SSRF & Internal Pivot", self.ssrf_probe, 32),
            (":crystal_ball: Smart Context Fuzz", self.smart_fuzz, 33),
            (":briefcase: Burp / Caido Traffic Bridge", self.burp_bridge, 34),
            (":wrench: AI Patch & Remediation Generator", self.patch_generator, 35),
            (":safety_pin: Read-Only PoC Verification", self.poc_generator, 36),
            (":bell: Multi-Channel Webhook Notifications", self.webhook_notify, 37),
            (":bar_chart: Executive Report Exporter", self.executive_report, 39),
            (":closed_lock_with_key: JS Secret & Source-Map Miner", self.js_secret_miner, 40),
            (":hourglass_flowing_sand: Historical URL Miner", self.wayback_miner, 41),
            (":question: Hidden Parameter Miner", self.param_miner, 42),
            (":crystal_ball: GraphQL Deep Audit", self.graphql_audit, 43),
            (":cloud: Cloud Storage Enumeration", self.cloud_storage_enum, 44),
            (":straight_ruler: CVSS 4.0 / CWE Risk Scoring", self.cvss_score_findings, 45),
            (":crossed_swords: MITRE ATT&CK Mapping", self.attack_mapping, 46),
            (":memo: CVE Intelligence Enricher", self.cve_intel_enrich, 47),
            (":anchor: Subdomain Takeover v3", self.takeover_v3, 48),
            (":eyes: Continuous Change Monitor", self.change_monitor, 49),
            (":shield: Read-Only Vulnerability Verification", self.vuln_verify, 50),
        ]
        # Filter by attack set and create coroutines only for selected
        # Modules that READ other modules' results must run sequentially AFTER the
        # concurrent scan finishes (indices: 19 crit, 23 comp, 24 graph, 25 correlate,
        # 29 linkfinder [reads katana js_files], 30 ffuf [reads api_pool],
        # 31 auth [diffs discovered endpoints], 32 ssrf [needs api_pool],
        # 33 smartfuzz [needs katana/linkfinder JS + api context]).
        DEFERRED = {19, 23, 24, 25, 29, 30, 31, 32, 33, 35, 36, 37, 39, 40, 41, 42, 43, 44,
                    45, 46, 47, 48, 49, 50}
        # Reporting/aggregation modules (35 patch, 36 poc, 37 notify, 39 exec, 45 cvss,
        # 46 attack, 47 cveintel, 49 watch) must run LAST so they see the findings
        # produced by the discovery pass (incl. the Tier-1 modules 40-44). Sort the
        # deferred pass by execution rank. 50 vulnverify runs in the deferred pass
        # (it needs the API pool) but BEFORE the reporting modules.
        _LATE = {35, 36, 37, 39, 45, 46, 47, 49}
        modules = []
        deferred = []
        for name, fn, idx in all_modules:
            if idx in self.attack_set:
                (deferred if idx in DEFERRED else modules).append((name, fn(), idx))
        deferred.sort(key=lambda t: (t[2] in _LATE, t[2]))

        scan_start = datetime.now()
        progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=28, complete_style="green", finished_style="bold green"),
            TextColumn("{task.fields[status]}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )

        self._completed = []

        # ---- strict per-module execution timeout (heavy crawl/fuzz get 300s) ----
        HEAVY = {16, 20, 27, 28, 29, 30, 31, 32, 33, 40, 41, 42, 44}   # crawl / ML / subprocess / fuzz / network-heavy discovery
        def _module_timeout(idx):
            heavy = float(getattr(self, "module_timeout_heavy", 300.0) or 300.0)
            normal = float(getattr(self, "module_timeout", 180.0) or 180.0)
            return heavy if idx in HEAVY else normal

        async def _with_timeout(name, coro, idx):
            t = _module_timeout(idx)
            try:
                return await asyncio.wait_for(coro, timeout=t)
            except asyncio.TimeoutError:
                self.results['errors'].append(
                    f"{name}: exceeded {int(t)}s timeout — module aborted (partial results kept)")
                raise

        async def runner(name, coro, tid, idx):
            try:
                result = await _with_timeout(name, coro, idx)
                progress.update(tid, completed=1, status="[bold green]✓ done[/]")
                self._completed.append((module_entry(idx) or ("",))[0])   # canonical name
                return result
            except asyncio.TimeoutError:
                progress.update(tid, completed=1, status="[bold yellow]⏱ timeout[/]")
                return None
            except asyncio.CancelledError:
                raise
            except Exception:
                progress.update(tid, completed=1, status="[bold red]✗ fail[/]")
                raise

        try:
            with progress:
                tids = [progress.add_task(name, total=1, status="[dim]scanning…[/]") for name, _, _ in modules]
                results = await asyncio.gather(
                    *[runner(modules[i][0], modules[i][1], tids[i], modules[i][2])
                      for i in range(len(modules))],
                    return_exceptions=True,
                )
        except (KeyboardInterrupt, asyncio.CancelledError):
            # Ctrl+C — keep partial results so `--resume` can finish the job
            self.scan_duration = (datetime.now() - scan_start).total_seconds()
            try:
                await self.client.aclose()
            except Exception:
                pass
            hid = self._history_save()
            console.print("\n[yellow]⏸  Scan interrupted[/]")
            if hid:
                console.print(f"[dim]Partial results saved to history:[/] [cyan]{hid}[/]")
                console.print(f"[dim]Continue:[/] nullveil {self.domain} --resume")
            raise

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
                        await _with_timeout(name, coro, idx)
                        prog2.update(tid, completed=1, status="[bold green]✓ done[/]")
                        self._completed.append((module_entry(idx) or ("",))[0])
                    except asyncio.TimeoutError:
                        prog2.update(tid, completed=1, status="[bold yellow]⏱ timeout[/]")
                    except Exception as e:
                        prog2.update(tid, completed=1, status="[bold red]✗ fail[/]")
                        self.results['errors'].append(f"{name} crashed: {e!r}")

        self.scan_duration = (datetime.now() - scan_start).total_seconds()

        # --- deep-accuracy pass (--verify): re-check findings, drop non-reproducers ---
        if getattr(self, "deep_verify", False):
            try:
                await self._verify_findings_pass()
            except Exception as e:
                self.results['errors'].append(f"verify: {e!r}")

        # --- external Python plugins (--plugin): run over the finished results ---
        if getattr(self, "plugins", None) is not None:
            try:
                ctx = PluginContext(self)
                ctx.report = self.export_dict()
                self.plugins.run_all(ctx)
            except Exception as e:
                self.results['errors'].append(f"plugins: {e!r}")

        try:
            await self.client.aclose()
        except Exception:
            pass
        report = self.export_dict()

        # --- Change detection vs the previous scan of this target ----------
        try:
            self._compute_diff(report)
        except Exception as e:
            self.results['errors'].append(f"diff: {e!r}")

        hid = self._history_save(report)
        if hid and not getattr(self, "quiet", False):
            console.print(f"[dim]Scan saved to history:[/] [cyan]{hid}[/]  "
                          f"[dim](list: nullveil <target> --history)[/]")

        # --- timeline DB (--timeline): append this scan for trend queries ---
        tdb = getattr(self, "timeline_db", None)
        if tdb is not None and getattr(tdb, "enabled", False):
            sid = tdb.record(report, recon=self)
            if sid:
                # the report was serialised before the row existed, so refresh
                # the embedded stats + record this scan's own id in place.
                st = tdb.stats()
                st = dict(st) if isinstance(st, dict) else {"enabled": True}
                st["indexed_scan_id"] = sid
                report["timeline"] = st
                if not getattr(self, "quiet", False):
                    console.print(f"[dim]Timeline:[/] scan #{sid} indexed "
                                  f"[dim]({tdb.path})[/]")

        # --- ATT&CK Navigator layer export (module 46) ---------------------
        layer_path = str(getattr(self, "attack_layer_path", "") or "")
        layer = (self.results.get('attack_map', {}) or {}).get('layer')
        if layer_path and layer:
            try:
                with open(layer_path, "w", encoding="utf-8") as fh:
                    json.dump(layer, fh, indent=2)
                if not getattr(self, "quiet", False):
                    console.print(f"[dim]ATT&CK Navigator layer written:[/] [cyan]{layer_path}[/]")
            except Exception as e:
                self.results['errors'].append(f"attack-layer export: {e!r}")

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
            findings.append(("MEDIUM", "No SPF record — domain spoofing possible for phishing [Configuration Gap]"))
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
            findings.append(("LOW", f"DKIM not detected on {len(dkim_selectors)} common selectors "
                                       f"(NOT_PROVEN — custom selector possible) [Configuration Gap]"))

        # ---------- DMARC ----------
        dmarc_record = next((t for t in dmarc_txt if t.lower().startswith('v=dmarc1')), None)
        self.results['dmarc'] = dmarc_record or ""
        if dmarc_record:
            policy_m = re.search(r'(?:^|;)\s*p\s*=\s*(\w+)', dmarc_record)
            policy = policy_m.group(1).lower() if policy_m else "none"
            self.results['dmarc_policy'] = policy
            if policy == "none":
                findings.append(("MEDIUM", "DMARC policy is 'p=none' — monitoring only, spoofing not blocked [Configuration Gap]"))
            elif policy == "quarantine":
                findings.append(("LOW", "DMARC policy 'p=quarantine' — consider 'p=reject' for full protection [Configuration Gap]"))
            else:
                findings.append(("INFO", "DMARC policy 'p=reject' — strongest anti-spoofing policy [OK]"))
            if not re.search(r'rua\s*=', dmarc_record):
                findings.append(("LOW", "DMARC has no 'rua=' aggregate report address — you won't see abuse reports [Configuration Gap]"))
            sp_m = re.search(r'(?:^|;)\s*sp\s*=\s*(\w+)', dmarc_record)
            if sp_m and sp_m.group(1).lower() == "none":
                findings.append(("MEDIUM", "DMARC subdomain policy 'sp=none' — subdomains are unprotected [Configuration Gap]"))
        else:
            findings.append(("MEDIUM", "No DMARC record — domain can be spoofed for phishing [Configuration Gap]"))

        # ---------- MTA-STS ----------
        mtasts_record = next((t for t in mtasts_txt if 'v=STSv1' in t), None)
        self.results['mta_sts'] = mtasts_record or ""
        if not mtasts_record:
            findings.append(("LOW", "No MTA-STS — SMTP TLS downgrade attacks possible [Configuration Gap]"))

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

        # ---------- per-endpoint checks (collect CORS for grouping) ----------
        cors_groups = {}
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

            # --- CORS misconfig (collect for grouping) ---
            acao = r.headers.get('access-control-allow-origin', '')
            acac = r.headers.get('access-control-allow-credentials', '').lower()
            if acao:
                if acao == ORIGIN and acac == 'true':
                    row['cors'] = "REFLECTED+CRED"
                    key = ("REFLECTED+CRED", True)
                    cors_groups.setdefault(key, []).append(path)
                elif acao == ORIGIN:
                    row['cors'] = "REFLECTED"
                    key = ("REFLECTED", row['auth'] == "none")
                    cors_groups.setdefault(key, []).append(path)
                elif acao == "*":
                    row['cors'] = "*"
                    if acac == 'true':
                        key = ("STAR+CRED", True)
                        cors_groups.setdefault(key, []).append(path)
                    else:
                        key = ("STAR", row['auth'] == "none")
                        cors_groups.setdefault(key, []).append(path)
                elif acac == 'true':
                    row['cors'] = "CRED"
                    key = ("CRED", row['auth'] == "none")
                    cors_groups.setdefault(key, []).append(path)

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

        # ---------- group CORS findings ----------
        for (cors_type, sensitive), paths in cors_groups.items():
            paths_list = sorted(set(paths))
            if not paths_list:
                continue
            if cors_type == "REFLECTED+CRED":
                sev = "CRITICAL"
                findings.append((sev, "CORS",
                                 f"Origin reflected WITH credentials (ACAO mirrors request Origin, Access-Control-Allow-Credentials: true). Affected endpoints: {', '.join(paths_list)} — cross-origin read with user cookies possible."))
            elif cors_type == "REFLECTED":
                sev = "HIGH" if sensitive else "MEDIUM"
                findings.append((sev, "CORS",
                                 f"Foreign origin reflected in Access-Control-Allow-Origin. Affected endpoints: {', '.join(paths_list)} — cross-origin reads allowed."))
            elif cors_type == "STAR+CRED":
                sev = "HIGH"
                findings.append((sev, "CORS",
                                 f"ACAO: '*' with Access-Control-Allow-Credentials: true (invalid per spec, often misconfigured). Affected endpoints: {', '.join(paths_list)} — review for cross-origin access with credentials."))
            elif cors_type == "STAR":
                sev = "INFO" if not sensitive else "LOW"
                findings.append((sev, "CORS",
                                 f"ACAO: '*' allows any origin. Affected endpoints: {', '.join(paths_list)} — public API if intended."))
            elif cors_type == "CRED":
                sev = "MEDIUM" if sensitive else "LOW"
                findings.append((sev, "CORS",
                                 f"Access-Control-Allow-Credentials: true with specific origin. Affected endpoints: {', '.join(paths_list)} — ensure origin allowlist is strict."))

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

    def _active_cve_rules(self):
        """Built-in CVE rules + any external rules loaded via --rules."""
        rules = list(self.CVE_RULES)
        rs = getattr(self, "ruleset", None)
        if rs is not None:
            rules += list(rs.cve)
        return rules

    def _active_misconfig_probes(self):
        """Built-in misconfig probes + any external probes loaded via --rules."""
        probes = list(self.MISCONFIG_PROBES)
        rs = getattr(self, "ruleset", None)
        if rs is not None:
            probes += list(rs.misconfig)
        return probes

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
            for prod, rule_major, mode, boundary, cve, sev, title in self._active_cve_rules():
                if prod != product:
                    continue
                if rule_major is not None and parts[0] != rule_major:
                    continue
                c = _cmp(parts, boundary)
                hit = {"eq": c == 0, "lt": c < 0, "le": c <= 0,
                       "gt": c > 0, "ge": c >= 0}.get(mode, c < 0)
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
        all_probes = [(p, rx, sev, pid, title)
                      for p, rx, sev, pid, title in self._active_misconfig_probes() if p and pid]
        if not self.deep:
            # quick scans probe only the first few *built-in* checks, but every
            # user-supplied external rule is always kept (never silently dropped).
            builtins_n = len([1 for p, rx, sev, pid, title in self.MISCONFIG_PROBES if p and pid])
            probes = all_probes[:min(7, builtins_n)] + all_probes[builtins_n:]
        else:
            probes = all_probes

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
            import warnings as _warnings
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with _warnings.catch_warnings():
                    # probing TLS 1.0/1.1 deliberately → don't spam DeprecationWarnings
                    _warnings.simplefilter("ignore", DeprecationWarning)
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
        unknown = [r for r in exec_res if r.get("vendor_known") is False and not r.get("same_origin")]
        first_party_exec = [r for r in exec_res if r.get("same_origin")]
        if exec_res and no_sri:
            third_party_no_sri = [r for r in no_sri if not r.get("same_origin")]
            if third_party_no_sri:
                sev = "HIGH" if unknown else "MEDIUM"
                findings.append((sev, "No Subresource Integrity",
                                 f"{len(third_party_no_sri)} third-party executable resources lack SRI — "
                                 f"add integrity + crossorigin where appropriate, pin trusted resources, and review dependencies (not fixable by WAF/CDN alone)"))
            elif first_party_exec and no_sri:
                findings.append(("INFO", "No Subresource Integrity (first-party)",
                                 f"{len(no_sri)} first-party executable resources lack SRI — consider adding integrity where using versioned/CDN-hosted assets"))
        for r in unknown[:8]:
            findings.append(("MEDIUM", "Unknown external script source",
                             f"{r['kind']} loaded from unrecognized host: {r['url'][:100]} (classification: THIRD-PARTY/UNKNOWN)"))
        for r in first_party_exec[:5]:
            # Don't flag same-origin app chunks as third-party
            pass
        if ext_form_actions:
            for scheme, u in ext_form_actions[:6]:
                sev = "CRITICAL" if scheme == "http" else "MEDIUM"
                findings.append((sev, "Form submits to third party",
                                 f"form action → {u[:100]} (submitted data leaves this origin)"))
        scripts3p = [r for r in resources if r["kind"] == "script" and not r.get("same_origin")]
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
            "third_party_exec": len([r for r in exec_res if not r.get("same_origin")]),
            "first_party_exec": len(first_party_exec),
            "sri_missing": len([r for r in no_sri if not r.get("same_origin")]),
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
        "upload": 76, "backup": 92, "bak": 88, "grafana": 80, "gitlab": 80,
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
        2375: 96, 2376: 90, 5672: 72, 9092: 72, 27017: 94, 5984: 82, 15672: 76,
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
        otx_ok = False
        otx_attempts = 0
        for indicator, itype in ([(self.domain, "domain")] + [(ip, "IPv4") for ip in ips[:3]]):
            if not otx_ok and otx_attempts >= 2:
                break           # OTX unreachable — don't hammer more slow timeouts
            otx_attempts += 1
            try:
                async with self.sem:
                    r = await self.client.get(
                        f"https://otx.alienvault.com/api/v1/indicators/{itype}/{indicator}/general",
                        timeout=15.0, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    otx_ok = True
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
        ran = {(module_entry(i) or ("",))[0] for i in self.attack_set if module_entry(i)}
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

        MULTI_TLD = {"co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "com.au", "net.au",
                     "org.au", "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.ar",
                     "co.in", "co.nz", "co.za", "com.sg", "com.hk", "com.tw", "co.kr",
                     "com.cn", "com.tr", "com.pl", "com.ua", "com.vn", "co.id"}

        def apex(host):
            parts = str(host).lower().rstrip('.').split('.')
            if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLD:
                return ".".join(parts[-3:])
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
        for h in getattr(self, "_auth_cmd", []):
            cmd += ["-H", h]
        if self.proxy:
            cmd += ["-proxy", self.proxy]   # Burp/Caido capture (module 34)
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

    # ---------------------------------------------------------- Katana Crawler
    async def katana_crawl(self):
        """Run ProjectDiscovery katana and harvest API endpoints + JS files."""
        import shutil as _shutil
        exe = _shutil.which("katana") or _shutil.which("katana.exe")
        if not exe:
            self.results['katana'] = {
                "available": False, "endpoints": [], "js_files": [], "urls": [],
                "note": "katana binary not found — install: "
                        "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            }
            self.results['errors'].append(
                "katana: binary missing — install from projectdiscovery.io, then re-run -a katana")
            return

        depth = 5 if self.deep else 3
        cmd = [exe, "-u", self.base_url, "-jsonl", "-d", str(depth),
               "-jc", "-silent", "-timeout", str(max(self.timeout, 8)),
               "-c", str(min(self.concurrency, 25)),
               "-ef", "png,jpg,jpeg,gif,svg,css,ico,woff,woff2,mp4,pdf"]
        for h in getattr(self, "_auth_cmd", []):
            cmd += ["-H", h]
        if self.proxy:
            cmd += ["-proxy", self.proxy]   # Burp/Caido capture (module 34)
        version = ""
        wall_limit = 600 if self.deep else 300
        try:
            try:
                vproc = await asyncio.create_subprocess_exec(
                    exe, "-version", stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT)
                vout, _ = await asyncio.wait_for(vproc.communicate(), timeout=15)
                m = re.search(r'v?(\d+\.\d+\.\d+)', vout.decode('utf-8', 'replace'))
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
                stdout_lines = []
                self.results['errors'].append(f"katana: stopped after {wall_limit}s wall-time cap")
        except Exception as e:
            self.results['errors'].append(f"katana: execution failed: {type(e).__name__} — {e}")
            self.results['katana'] = {"available": False, "endpoints": [], "js_files": [],
                                      "urls": [], "note": f"execution failed: {type(e).__name__}"}
            return

        urls, js_files, endpoints = set(), set(), set()
        for line in stdout_lines:
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            req = j.get("request", {}) or {}
            u = str(req.get("endpoint") or req.get("url") or "")
            if not u:
                continue
            path = urlparse(u).path
            q = urlparse(u).query
            urls.add(u)
            if re.search(r'\.m?js(\?|$)', path, re.I):
                js_files.add(u)
            if re.search(r'(?i)/(api|rest|graphql|v\d|auth|oauth|json|rpc|soap|wsdl)[/\w\-.$]*', path):
                endpoints.add(f"{path}" + (f"?{q}" if q else ""))
            if self.deep:
                endpoints.add(path)

        self.results['katana'] = {
            "available": True, "binary": exe, "version": version, "depth": depth,
            "urls_crawled": len(urls),
            "js_files": sorted(js_files)[:200],
            "endpoints": sorted(endpoints)[:2000],
            "urls": sorted(urls)[:1000],
        }
        for u in sorted(urls)[:800]:
            self.results['api_pool'].append({"path": urlparse(u).path or "/", "source": "katana"})
        for ep in sorted(endpoints)[:800]:
            self.results['api_pool'].append({"path": ep, "source": "katana"})

    # ---------------------------------------------------------- LinkFinder JS
    async def linkfinder_scan(self):
        """Extract hidden API endpoints from JS bundles (LinkFinder engine).

        Uses the LinkFinder regex natively (no dependency) + runs the
        ``linkfinder`` CLI too when it is installed.
        """
        import shutil as _shutil
        js_urls = set()
        kat = self.results.get('katana', {}) or {}
        for u in (kat.get('js_files') or []):
            js_urls.add(u)
        # JS bundles seen in Burp/Caido HAR captures
        for u in ((self.results.get('burp', {}) or {}).get('js_files') or []):
            if isinstance(u, str) and u.startswith(('http://', 'https://')):
                js_urls.add(u)
        try:
            async with self.sem:
                r = await self.client.get(self.scalar_results.get('final_url', self.base_url + "/"))
            html = r.text[:500_000]
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                js_urls.add(urljoin(str(r.url), m.group(1)))
        except Exception:
            pass

        js_urls = {u for u in js_urls if re.search(r'\.m?js(\?|$)', urlparse(u).path, re.I)} or js_urls
        js_limit = 25 if self.deep else 12
        js_urls = sorted(js_urls)[:js_limit]

        # LinkFinder's core regex (from the original gerbenjaviering/linkfinder)
        LINKFINDER_RE = re.compile(
            r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')""")
        found = {}

        async def analyze(u):
            try:
                async with self.sem:
                    r = await self.client.get(u)
                if r.status_code != 200:
                    return
                body = r.text[:2_000_000]
                for m in LINKFINDER_RE.finditer(body):
                    ep = (m.group(1) or '').strip()
                    if ep and len(ep) >= 3:
                        found.setdefault(ep, u)
                for m in re.finditer(
                        r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post))\(\s*["\'`]([^"\'`]{3,200})["\'`]', body):
                    v = m.group(1)
                    if v.startswith('/') or '://' in v:
                        found.setdefault(v, u)
            except Exception:
                pass

        await asyncio.gather(*[analyze(u) for u in js_urls])

        lf_exe = _shutil.which("linkfinder")
        ext_count = 0
        if lf_exe and js_urls:
            for u in js_urls[:6]:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        lf_exe, "-i", u, "-o", "json",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    out, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
                    data = json.loads(out.decode('utf-8', 'replace') or '[]')
                    for ep in (data if isinstance(data, list) else []):
                        if isinstance(ep, str) and len(ep) >= 3:
                            found.setdefault(ep, f"linkfinder:{u}")
                            ext_count += 1
                except Exception:
                    continue

        clean = {}
        for ep, src in found.items():
            ep = ep.strip()
            if re.search(r'\.(png|jpg|jpeg|gif|svg|css|woff2?|ico|mp4|pdf)(\?|$)', ep, re.I):
                continue
            if ep.startswith('//') and '://' not in ep[2:20]:
                continue
            # MIME-type / content-negotiation noise (application/json, text/html …)
            if re.match(r'(?i)^(application|audio|font|image|message|model|multipart|text|video)/',
                        ep):
                continue
            # pure file-extension or language tags ("*.js", "en-US", "v1.2.3")
            if re.fullmatch(r'[\w.*-]+', ep) and ('/' not in ep):
                continue
            clean[ep] = src

        endpoints = sorted(clean.keys())
        self.results['linkfinder'] = {
            "available": True, "js_analyzed": len(js_urls), "external_cli": bool(lf_exe),
            "ext_found": ext_count, "count": len(endpoints),
            "endpoints": endpoints[:1500],
            "sources": {ep: clean[ep] for ep in endpoints[:300]},
        }
        for ep in endpoints[:800]:
            self.results['api_pool'].append({"path": ep, "source": "linkfinder"})

    # ==================================================== JS Secret & Source-Map Miner (40)
    JS_SECRET_RULES = [
        ("AWS Access Key",       r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",                             "CRITICAL"),
        ("Google API Key",       r"\bAIza[0-9A-Za-z_\-]{35}\b",                              "HIGH"),
        ("Google OAuth Client",  r"\b[0-9]{12}-[0-9a-z_]{32}\.apps\.googleusercontent\.com",  "MEDIUM"),
        ("Firebase URL",         r"\bhttps://[a-z0-9\-]+\.firebaseio\.com",                  "MEDIUM"),
        ("Stripe Secret Key",    r"\bsk_live_[0-9a-zA-Z]{24,}\b",                            "CRITICAL"),
        ("Stripe Publishable",   r"\bpk_(live|test)_[0-9a-zA-Z]{24,}\b",                     "LOW"),
        ("SendGrid API Key",     r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",          "CRITICAL"),
        ("Twilio Account SID",   r"\bAC[0-9a-fA-F]{32}\b",                                   "MEDIUM"),
        ("Slack Token",          r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",                       "HIGH"),
        ("Slack Webhook",        r"https://hooks\.slack\.com/services/[A-Za-z0-9/+_]{40,}",  "HIGH"),
        ("GitHub Token",         r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",                          "CRITICAL"),
        ("GitLab Token",         r"\bglpat-[A-Za-z0-9_\-]{20,}\b",                           "CRITICAL"),
        ("Private Key Block",    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "CRITICAL"),
        ("JWT",                  r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "MEDIUM"),
        ("Mapbox Token",         r"\bpk\.[A-Za-z0-9_\-]{60,}\b",                             "LOW"),
        ("Mailgun Key",          r"\bkey-[0-9a-zA-Z]{32}\b",                                 "HIGH"),
        ("Heroku API Key",       r"(?i)heroku[^0-9a-f]{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "HIGH"),
        ("Square Token",         r"\bsq0atp-[0-9A-Za-z_\-]{22}\b",                           "HIGH"),
        ("OpenAI Key",           r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",           "CRITICAL"),
        ("Generic Bearer",       r"(?i)authorization['\"]?\s*[:=]\s*['\"]Bearer\s+[A-Za-z0-9_\-\.]{20,}", "MEDIUM"),
        ("Generic API Key",      r"(?i)(api[_-]?key|apikey|api[_-]?secret|access[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "MEDIUM"),
        ("Basic Auth in URL",    r"https?://[^/\s:@'\"]+:[^/\s:@'\"]+@[^/\s'\"]+",           "HIGH"),
    ]
    JS_SINK_RULES = [
        ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML",  "MEDIUM"),
        ("innerHTML assignment",    r"\.innerHTML\s*=",          "LOW"),
        ("document.write",          r"document\.write\s*\(",     "LOW"),
        ("eval()",                  r"\beval\s*\(",              "MEDIUM"),
        ("new Function()",          r"new\s+Function\s*\(",      "MEDIUM"),
        ("postMessage *",           r"postMessage\s*\([^,]+,\s*['\"]\*['\"]", "MEDIUM"),
        ("localStorage token",      r"localStorage\.(setItem|getItem)\s*\(\s*['\"][^'\"]*(token|jwt|auth|secret)", "LOW"),
        ("hardcoded internal host", r"https?://(?:localhost|127\.0\.0\.1|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", "LOW"),
    ]

    async def js_secret_miner(self):
        """Module 40 — deep JavaScript secret & source-map miner (read-only).

        Walks every JS bundle referenced by the page, discovered crawlers and HAR
        captures, then additionally *de-obfuscates* it by following ``//# sourceMappingURL``
        source maps (``.map`` → ``sourcesContent``). Scans all recovered text for
        API keys / tokens / private keys and dangerous DOM sinks. Sends only GET,
        never mutates anything. Secrets are **masked** in the report."""
        js_urls = set()
        for u in (self.results.get('js_files') or []):
            if isinstance(u, str):
                js_urls.add(u)
        for u in ((self.results.get('katana', {}) or {}).get('js_files') or []):
            js_urls.add(u)
        for u in ((self.results.get('burp', {}) or {}).get('js_files') or []):
            if isinstance(u, str) and u.startswith(('http://', 'https://')):
                js_urls.add(u)
        for u in ((self.results.get('crawl', {}) or {}).get('js_files') or []):
            js_urls.add(u)
        # page-inline <script src> (in case content/api modules did not capture)
        try:
            async with self.sem:
                r = await self.client.get(self.scalar_results.get('final_url', self.base_url + "/"))
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text[:500_000], re.I):
                js_urls.add(urljoin(str(r.url), m.group(1)))
        except Exception:
            pass
        js_urls = {u for u in js_urls if u.startswith(('http://', 'https://'))}
        js_urls = {u for u in js_urls if re.search(r'\.m?js(\?|$)', urlparse(u).path, re.I)} or js_urls
        limit = 60 if self.deep else 30
        js_urls = sorted(js_urls)[:limit]

        secrets, sinks, endpoints = [], [], set()
        maps_found, chunks_found = [], set()
        secret_seen, sink_seen = set(), set()
        ep_re = re.compile(r"""["'](/[A-Za-z0-9_\-./]{3,}(?:\?[^"']*)?|https?://[^"'\s]+)["']""")
        chunk_re = re.compile(r"""["']((?:/|\.\./)?[A-Za-z0-9_\-./]*?[\w-]{1,}\.[0-9a-f]{6,20}\.js)["']""")

        def scan_text(text, src, inline=False):
            # secrets
            for name, rx, sev in self.JS_SECRET_RULES:
                for m in re.finditer(rx, text):
                    raw = m.group(0)
                    key = (name, src.split('?')[0], raw[:24])
                    if key in secret_seen:
                        continue
                    secret_seen.add(key)
                    masked = (raw[:6] + "…" + raw[-4:]) if len(raw) > 14 else raw[:4] + "…"
                    secrets.append({"severity": sev, "type": name, "source": src,
                                    "masked": masked, "length": len(raw),
                                    "context": re.sub(r"\s+", " ", text[max(0, m.start() - 30):m.end() + 30])[:160]})
            # dangerous sinks
            for name, rx, sev in self.JS_SINK_RULES:
                for _ in re.finditer(rx, text):
                    key = (name, src.split('?')[0])
                    if key in sink_seen:
                        continue
                    sink_seen.add(key)
                    sinks.append({"severity": sev, "type": name, "source": src})
            # endpoints (source-map / chunk recovery)
            for m in ep_re.finditer(text):
                u = m.group(1)
                if u.startswith('http') and self.domain not in u:
                    continue
                if re.search(r'\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|map)(\?|$)', u, re.I):
                    continue
                endpoints.add(u)
            for m in chunk_re.finditer(text):
                c = m.group(1)
                if c.endswith('.map') or len(c) > 200:
                    continue
                chunks_found.add(c)

        async def fetch(u):
            try:
                async with self.sem:
                    r = await self.client.get(u)
                if r.status_code != 200:
                    return
                body = r.text[:3_000_000]
                scan_text(body, u)
                # follow source map → recover original (unminified) sources
                for m in re.finditer(r'//[#@]\s*sourceMappingURL=([^\s\'"]+)', body):
                    smu = m.group(1).strip()
                    if smu.startswith('data:'):
                        continue
                    smu = urljoin(u, smu)
                    if not smu.startswith(('http://', 'https://')):
                        continue
                    maps_found.append(smu)
                    try:
                        async with self.sem:
                            mr = await self.client.get(smu)
                        if mr.status_code != 200:
                            continue
                        data = mr.json()
                        for sname, content in zip(data.get('sources') or [],
                                                 data.get('sourcesContent') or []):
                            if isinstance(content, str):
                                scan_text(content, f"{smu}::{sname}", inline=True)
                    except Exception:
                        continue
            except Exception:
                pass

        await asyncio.gather(*[fetch(u) for u in js_urls])

        # severity ordering + findings
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        secrets.sort(key=lambda s: rank.get(s["severity"], 5))
        sinks.sort(key=lambda s: rank.get(s["severity"], 5))
        findings = []
        for s in secrets:
            findings.append({"severity": s["severity"],
                             "check": f"JS secret — {s['type']}",
                             "detail": f"{s['masked']} ({s['length']} chars) in {s['source']}",
                             "evidence": s.get("context", "")})
        for s in sinks:
            findings.append({"severity": s["severity"], "check": f"JS sink — {s['type']}",
                             "detail": s["source"], "evidence": ""})

        endpoints = sorted(endpoints)
        self.results['js_secret'] = {
            "available": True, "js_analyzed": len(js_urls),
            "source_maps": maps_found[:200], "map_count": len(maps_found),
            "chunks": sorted(chunks_found)[:400], "chunk_count": len(chunks_found),
            "secret_count": len(secrets), "secrets": secrets[:200],
            "sink_count": len(sinks), "sinks": sinks[:200],
            "endpoints": endpoints[:1000], "endpoint_count": len(endpoints),
            "findings": findings[:400],
            "policy": "Read-only GET only — secrets are masked; no values are used to authenticate.",
        }
        for ep in endpoints[:600]:
            self.results['api_pool'].append({"path": ep, "source": "jssecret"})

    # ==================================================== Historical URL Miner (41)
    async def wayback_miner(self):
        """Module 41 — historical URL mining (Wayback / CommonCrawl / OTX).

        Read-only: queries public historical-index APIs for URLs that *used* to
        exist on the target. Forgotten endpoints, old query parameters, backup
        files and config paths often remain reachable — a very common real-world
        finding. No traffic is sent to the target itself beyond the passive index
        lookups."""
        import json as _json
        urls = set()
        sources_used = []

        async def _get(url, tag):
            try:
                async with self.sem:
                    r = await self.client.get(url, timeout=20)
                if r.status_code == 200 and r.text:
                    sources_used.append(tag)
                return r.text
            except Exception:
                return ""

        # --- Wayback CDX API (URL list for the domain + subdomains) ---
        cdx = ("https://web.archive.org/cdx/search/cdx?"
               f"url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey&limit=8000")
        txt = await _get(cdx, "wayback")

        def _add(u):
            try:
                u = u.strip()
                if not u:
                    return
                p = urlparse(u)
                if self.domain not in (p.netloc or ''):
                    return
                urls.add((p.path or '/') + (f"?{p.query}" if p.query else ''))
            except Exception:
                pass

        for line in (txt or "").splitlines():
            _add(line)

        # --- CommonCrawl index (latest crawl, via the collinfo-less index server) ---
        if self.deep:
            cc_idx = ("https://index.commoncrawl.org/CC-MAIN-2024-33-index?"
                      f"url=*.{self.domain}/*&output=json&limit=3000")
            cct = await _get(cc_idx, "commoncrawl")
            for line in (cct or "").splitlines():
                try:
                    _add(_json.loads(line).get("url", ""))
                except Exception:
                    pass

        # --- AlienVault OTX URL list (already used by intel but here as a URL source) ---
        otx = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=500"
        otxt = await _get(otx, "otx")
        try:
            for entry in (_json.loads(otxt) or {}).get("url_list", []):
                _add(entry.get("url", ""))
        except Exception:
            pass

        urls = sorted(urls)
        # classify interesting historical URLs
        interesting_res = re.compile(
            r'(?i)(\.env|\.git|\.svn|\.bak|\.old|\.zip|\.tar|\.gz|\.sql|\.log|'
            r'backup|config|admin|debug|test|staging|dev|internal|api|graphql|'
            r'swagger|actuator|phpinfo|\.json|\.ya?ml|token|secret|password|key)')
        params = set()
        for u in urls:
            q = urlparse(u).query
            for pair in q.split('&'):
                if '=' in pair:
                    k = pair.split('=', 1)[0].strip()
                    if k and len(k) < 40:
                        params.add(k)
        interesting = [u for u in urls if interesting_res.search(u)][:400]
        findings = []
        for u in interesting[:300]:
            sev = "MEDIUM" if re.search(r'(?i)(\.env|\.git|backup|\.sql|\.bak|config|token|secret|password)', u) else "LOW"
            findings.append({"severity": sev, "check": "Historical URL",
                             "detail": u, "evidence": "from " + ", ".join(sorted(set(sources_used)))})
        self.results['wayback'] = {
            "available": bool(sources_used), "sources": sorted(set(sources_used)),
            "url_count": len(urls), "urls": urls[:1500],
            "interesting_count": len(interesting), "interesting": interesting,
            "param_count": len(params), "params": sorted(params)[:300],
            "findings": findings,
            "note": ("Forgotten/older endpoints can still be live — re-test before reporting as fixed."
                     if urls else "No historical URLs returned (index unavailable or domain unseen)."),
        }
        for ep in urls[:600]:
            self.results['api_pool'].append({"path": urlparse(ep).path or '/', "source": "wayback"})
        for p in sorted(params):
            self.results['api_pool'].append({"path": p, "source": "wayback:param"})

    # ==================================================== Hidden Parameter Miner (42)
    # Curated param names favouring real-world reflections / auth-ish behaviour.
    PARAM_WORDLIST = [
        "id", "user", "username", "userid", "user_id", "account", "uid", "pid", "gid",
        "page", "p", "view", "file", "filename", "path", "dir", "folder", "url", "uri",
        "link", "src", "source", "redirect", "redirect_uri", "next", "return", "returnurl",
        "callback", "continue", "dest", "destination", "target", "ref", "referer",
        "q", "query", "search", "s", "keyword", "term", "filter", "sort", "order", "orderby",
        "limit", "offset", "start", "end", "from", "to", "count", "size", "num", "n",
        "format", "type", "mode", "action", "method", "cmd", "command", "op", "operation",
        "token", "key", "apikey", "api_key", "secret", "auth", "access_token", "session",
        "sid", "csrf", "nonce", "signature", "sig", "hash", "code", "state",
        "email", "mail", "phone", "name", "firstname", "lastname", "fullname", "title",
        "role", "group", "perm", "permission", "scope", "admin", "is_admin", "debug",
        "test", "lang", "locale", "country", "region", "timezone", "currency",
        "json", "api", "callback_fn", "jsonp", "output", "template", "theme", "layout",
        "version", "v", "ts", "time", "date", "day", "month", "year",
    ]

    async def param_miner(self):
        """Module 42 — hidden GET/POST parameter discovery (Arjun-style, read-only).

        For each candidate parameter the module issues a benign GET with a unique
        marker value and compares the response (status, length, reflection count,
        headers). A parameter that *changes* the response, or reflects the marker,
        is reported as a discovered parameter. **Only the marker is ever sent** —
        no SQLi/XSS/command payloads, no writes. Rate-limited by the shared
        semaphore."""
        base = self.scalar_results.get('final_url') or (self.base_url + "/")
        # build the small set of test URLs: the base + a few discovered endpoints
        cand_urls = [base]
        for ep in (self.results.get('api_pool') or [])[: (12 if self.deep else 5)]:
            p = ep.get('path') if isinstance(ep, dict) else ep
            if isinstance(p, str) and p.startswith('/') and '?' not in p and len(p) < 80:
                cand_urls.append(self.base_url.rstrip('/') + p)
        cand_urls = list(dict.fromkeys(cand_urls))[: (8 if self.deep else 4)]

        marker = "nv" + hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8]
        found_params, findings = {}, []

        async def baseline(u, post=False):
            try:
                if post:
                    async with self.sem:
                        r = await self.client.post(u, data={"nvbase": marker})
                else:
                    async with self.sem:
                        r = await self.client.get(u)
                return {"status": r.status_code, "len": len(r.content),
                        "text": r.text[:200_000], "headers": dict(r.headers)}
            except Exception:
                return None

        async def probe(u, base_sig, pname, post=False):
            try:
                if post:
                    async with self.sem:
                        r = await self.client.post(u, data={pname: marker})
                else:
                    sep = '&' if '?' in u else '?'
                    async with self.sem:
                        r = await self.client.get(f"{u}{sep}{pname}={marker}")
                if r.status_code != base_sig["status"]:
                    return ("status", r.status_code, base_sig["status"])
                reflected = marker in r.text
                dlen = abs(len(r.content) - base_sig["len"])
                # ignore tiny jitter, require a meaningful delta or a reflection
                if reflected:
                    return ("reflected", dlen, None)
                if dlen >= max(25, int(base_sig["len"] * 0.02)):
                    return ("length", dlen, base_sig["len"])
                return None
            except Exception:
                return None

        # Control probe: an obviously-unknown parameter. If it *also* reflects or
        # shifts the response, the endpoint reflects any input (e.g. echoes the
        # whole query string) and reflection alone is not evidence — suppress it.
        control_names = ["zzq" + hashlib.md5(b"nvctl").hexdigest()[:8],
                         "nvunknown" + hashlib.md5(b"nvctl2").hexdigest()[:6]]

        for u in cand_urls:
            b = await baseline(u)
            if not b or b["status"] >= 500:
                continue
            ctrl = None
            for cn in control_names:
                c = await probe(u, b, cn)
                if c:
                    ctrl = c
                    break
            ctrl_reflects = bool(ctrl and ctrl[0] == "reflected")
            ctrl_len = abs(int(ctrl[1])) if (ctrl and ctrl[0] == "length" and str(ctrl[1]).isdigit()) else 0
            names = self.PARAM_WORDLIST if self.deep else self.PARAM_WORDLIST[:40]
            sem_probe = asyncio.Semaphore(8)

            def _keep(hit):
                """Drop a hit that merely matches how the control (unknown) param behaved."""
                if not hit:
                    return None
                kind, val, ref = hit
                if kind == "reflected":
                    if ctrl_reflects:
                        return None          # endpoint echoes anything — not evidence
                    return hit
                if kind == "length":
                    d = abs(int(val)) if str(val).isdigit() else 0
                    if ctrl_len and d <= ctrl_len * 1.5:
                        return None          # same order as control jitter
                    return hit
                if kind == "status":
                    return hit
                return None

            async def one(pname):
                async with sem_probe:
                    return pname, _keep(await probe(u, b, pname))
            for chunk in [names[i:i + 40] for i in range(0, len(names), 40)]:
                for pname, hit in await asyncio.gather(*[one(n) for n in chunk]):
                    if hit:
                        kind, val, ref = hit
                        found_params.setdefault(pname, {"name": pname, "url": u,
                                                        "type": kind, "evidence": str(val)})
            # POST pass (deep only, narrow set) — uses its own POST baseline and
            # control, so a plain GET→POST method difference is never reported.
            if self.deep:
                pb = await baseline(u, post=True)
                if pb and pb["status"] < 500:
                    pctrl = None
                    for cn in control_names:
                        c = await probe(u, pb, cn, post=True)
                        if c:
                            pctrl = c
                            break
                    pctrl_reflects = bool(pctrl and pctrl[0] == "reflected")
                    pctrl_len = abs(int(pctrl[1])) if (pctrl and pctrl[0] == "length"
                                                       and str(pctrl[1]).isdigit()) else 0

                    def _keep_post(hit):
                        if not hit:
                            return None
                        kind, val, ref = hit
                        if kind == "reflected":
                            return None if pctrl_reflects else hit
                        if kind == "length":
                            d = abs(int(val)) if str(val).isdigit() else 0
                            if pctrl_len and d <= pctrl_len * 1.5:
                                return None
                            return hit
                        if kind == "status":
                            return hit
                        return None

                    async def one_post(pname):
                        async with sem_probe:
                            return pname, _keep_post(await probe(u, pb, pname, post=True))
                    for pname, hit in await asyncio.gather(*[one_post(n) for n in names[:25]]):
                        if hit:
                            kind, val, ref = hit
                            found_params.setdefault(f"POST:{pname}",
                                                    {"name": pname, "url": u, "type": f"POST/{kind}",
                                                     "evidence": str(val)})

        for p in found_params.values():
            sev = "HIGH" if p["type"] == "reflected" else "LOW"
            findings.append({"severity": sev, "check": f"Hidden parameter ({p['type']})",
                             "detail": f"{p['name']} on {p['url']}",
                             "evidence": f"marker reflected/Δ={p['evidence']}"})
        findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f["severity"], 3))
        self.results['param'] = {
            "available": True, "urls_tested": len(cand_urls),
            "count": len(found_params), "params": sorted(found_params.values(),
                                                         key=lambda x: x["name"])[:200],
            "findings": findings[:200],
            "policy": "Only benign unique-marker values are sent — no SQLi/XSS/command payloads, no writes.",
        }
        for p in found_params.values():
            self.results['api_pool'].append({"path": p["name"], "source": "param"})

    # ==================================================== GraphQL Deep Audit (43)
    async def graphql_audit(self):
        """Module 43 — GraphQL introspection & misconfiguration audit (read-only).

        Locates common GraphQL endpoints, attempts a standard **introspection**
        query (report-only — introspection exposed is itself the finding), checks
        whether the server leaks **field suggestions** for typo'd queries, and
        verifies depth-limit / batching protections exist. Sends only read
        (query) operations — never mutations."""
        candidates = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                      "/v2/graphql", "/gql", "/query", "/api/gql", "/graphql/console"]
        for ep in (self.results.get('api_pool') or []):
            p = ep.get('path') if isinstance(ep, dict) else ep
            if isinstance(p, str) and re.search(r'(?i)graphql|/gql\b', p):
                candidates.append(p)
        candidates = list(dict.fromkeys(candidates))[: (16 if self.deep else 9)]

        INTROSPECT = ('{"query":"query{__schema{queryType{name} mutationType{name}'
                      'types{name kind fields{name}}}}"}')
        endpoints, findings = [], []

        async def check(path):
            url = self.base_url.rstrip('/') + path
            try:
                async with self.sem:
                    r = await self.client.post(url, content=INTROSPECT,
                                               headers={"Content-Type": "application/json"})
                if r.status_code >= 500:
                    return
                ct = r.headers.get('content-type', '')
                body = r.text[:400_000]
                if 'json' not in ct.lower() and '__schema' not in body:
                    return
                rec = {"endpoint": url, "status": r.status_code,
                       "introspection": False, "field_suggestions": False,
                       "depth_limited": None, "batching": None, "issues": []}
                # 1) introspection enabled?
                try:
                    data = r.json()
                    sch = ((data or {}).get("data") or {}).get("__schema")
                    if sch:
                        rec["introspection"] = True
                        types = [t.get("name") for t in (sch.get("types") or [])
                                 if t.get("name") and not str(t.get("name")).startswith("__")]
                        rec["type_count"] = len(types)
                        rec["types"] = types[:60]
                        if sch.get("mutationType"):
                            rec["issues"].append("mutations exposed")
                        findings.append({"severity": "MEDIUM",
                                         "check": "GraphQL introspection enabled",
                                         "detail": f"{url} exposes full schema ({len(types)} types)",
                                         "evidence": "An attacker can enumerate all types/fields."})
                except Exception:
                    pass
                # 2) field-suggestion leakage (typo probe)
                try:
                    async with self.sem:
                        sr = await self.client.post(
                            url, content='{"query":"query{__typenameX}"}',
                            headers={"Content-Type": "application/json"})
                    sb = sr.text[:50_000]
                    if re.search(r'(?i)(did you mean|suggest|__typename)', sb) and sr.status_code < 500:
                        rec["field_suggestions"] = True
                        findings.append({"severity": "LOW",
                                         "check": "GraphQL field suggestions leaked",
                                         "detail": f"{url} returns 'did you mean' suggestions",
                                         "evidence": "Enables field/type enumeration without introspection."})
                except Exception:
                    pass
                # 3) depth-limit probe (deeply nested query — benign, no aliases explosion)
                try:
                    deep_q = "query{" + "a{" * 12 + "__typename" + "}" * 12 + "}"
                    async with self.sem:
                        dr = await self.client.post(
                            url, content=json.dumps({"query": deep_q}),
                            headers={"Content-Type": "application/json"})
                    rec["depth_limited"] = dr.status_code >= 400 or bool(
                        re.search(r'(?i)(depth|complexity|too deep|max)', dr.text[:20_000]))
                    if not rec["depth_limited"] and dr.status_code < 400:
                        rec["issues"].append("no depth limit observed")
                        findings.append({"severity": "LOW",
                                         "check": "GraphQL depth limit not enforced",
                                         "detail": f"{url} accepted a 12-level nested query",
                                         "evidence": "Deep queries can be used for DoS."})
                except Exception:
                    pass
                # 4) batching (alias-based) — benign two-alias probe
                try:
                    batch = ('{"query":"query{a:__typename b:__typename}"}')
                    async with self.sem:
                        br = await self.client.post(url, content=batch,
                                                    headers={"Content-Type": "application/json"})
                    rec["batching"] = br.status_code < 400
                except Exception:
                    pass
                endpoints.append(rec)
            except Exception:
                pass

        await asyncio.gather(*[check(p) for p in candidates])
        self.results['graphql'] = {
            "available": bool(endpoints), "endpoints": endpoints,
            "count": len(endpoints),
            "introspection_open": [e["endpoint"] for e in endpoints if e.get("introspection")],
            "findings": findings,
            "policy": "Query (read) operations only — no mutations, no writes, no data exfiltration.",
        }

    # ==================================================== Cloud Storage Enumeration (44)
    async def cloud_storage_enum(self):
        """Module 44 — cloud storage (S3/Azure/GCP) exposure check (read-only).

        Derives likely bucket names from the target domain and probes each
        provider with **HEAD/GET only**: does the bucket exist, is the listing
        public, is it world-writable (checked via a HEAD to a random key + the
        ``x-amz-*`` response headers — no upload). Never writes, uploads or
        deletes anything."""
        import hashlib as _h
        dom_root = self.domain.split(':')[0]
        base = re.sub(r'[^a-z0-9]+', '-', dom_root.lower()).strip('-')
        parts = re.sub(r'[^a-z0-9]+', '-', dom_root.lower()).split('-')
        cands = {base, f"{base}-backup", f"{base}-backups", f"{base}-dev", f"{base}-staging",
                 f"{base}-prod", f"{base}-assets", f"{base}-static", f"{base}-media",
                 f"{base}-uploads", f"{base}-data", f"{base}-files", f"{base}-cdn",
                 f"{base}-logs", f"{base}-test", f"{base}-public", f"{base}-private"}
        if len(parts) > 1:
            cands.add(parts[0])
            cands.add('-'.join(parts[:2]))
        cands = sorted(c for c in cands if 3 <= len(c) <= 63)
        if not self.deep:
            cands = cands[:14]

        rnd_key = "nv" + _h.md5(dom_root.encode()).hexdigest()[:10] + ".txt"
        findings, buckets = [], []

        async def s3(name):
            url = f"https://{name}.s3.amazonaws.com/"
            try:
                async with self.sem:
                    r = await self.client.get(url, follow_redirects=False)
                if r.status_code not in (200, 403) or 'ListBucketResult' not in r.text[:4000] \
                        and r.status_code != 200 and r.status_code != 403:
                    return
                listing = r.status_code == 200 and '<ListBucketResult' in r.text
                rec = {"provider": "aws-s3", "bucket": name, "url": url,
                       "status": r.status_code, "public_listing": listing}
                if listing:
                    findings.append({"severity": "HIGH", "check": "Public S3 bucket listing",
                                     "detail": f"{url} lists objects publicly",
                                     "evidence": "Anyone can enumerate the bucket contents."})
                buckets.append(rec)
            except Exception:
                pass

        async def azure(name):
            url = f"https://{name}.blob.core.windows.net/?comp=list"
            try:
                async with self.sem:
                    r = await self.client.get(url, follow_redirects=False)
                if r.status_code == 200 and '<EnumerationResults' in r.text:
                    buckets.append({"provider": "azure-blob", "bucket": name, "url": url,
                                    "status": r.status_code, "public_listing": True})
                    findings.append({"severity": "HIGH", "check": "Public Azure container listing",
                                     "detail": f"{url} lists containers publicly",
                                     "evidence": "Anyone can enumerate blob containers."})
                elif r.status_code == 404:
                    return
                elif r.status_code in (403, 400):
                    buckets.append({"provider": "azure-blob", "bucket": name, "url": url,
                                    "status": r.status_code, "public_listing": False})
            except Exception:
                pass

        async def gcp(name):
            url = f"https://storage.googleapis.com/storage/v1/b/{name}"
            try:
                async with self.sem:
                    r = await self.client.get(url, follow_redirects=False)
                if r.status_code == 200:
                    buckets.append({"provider": "gcp-storage", "bucket": name, "url": url,
                                    "status": 200, "public_listing": True})
                    findings.append({"severity": "MEDIUM", "check": "Public GCP bucket metadata",
                                     "detail": f"{url} is publicly readable",
                                     "evidence": "Bucket metadata is world-readable."})
                elif r.status_code in (401, 403):
                    buckets.append({"provider": "gcp-storage", "bucket": name, "url": url,
                                    "status": r.status_code, "public_listing": False})
            except Exception:
                pass

        tasks = []
        for c in cands:
            tasks += [s3(c), azure(c), gcp(c)]
        await asyncio.gather(*tasks)

        # world-writable probe (HEAD only — never uploads)
        for b in list(buckets):
            if b["provider"] != "aws-s3":
                continue
            try:
                url = f"https://{b['bucket']}.s3.amazonaws.com/{rnd_key}"
                async with self.sem:
                    r = await self.client.request("HEAD", url)
                if r.status_code in (200, 204):
                    b["writable_probe"] = True
                    findings.append({"severity": "CRITICAL",
                                     "check": "S3 bucket appears world-writable",
                                     "detail": f"{b['bucket']} returned {r.status_code} for an unknown key",
                                     "evidence": "HEAD on a non-existent key succeeded — investigate ACL immediately."})
            except Exception:
                pass

        self.results['cloud'] = {
            "available": True, "candidates_tested": len(cands),
            "buckets": buckets, "count": len(buckets),
            "findings": findings,
            "policy": "HEAD/GET only — no uploads, no writes, no deletions.",
        }

    # ==================================================== CVSS 4.0 / CWE Risk Scoring (45)
    # Heuristic CVSS vectors keyed by finding "category". Each entry carries the
    # four CVSS 4.0 base metric groups (AV/AC/AT/PR/UI + VC/VI/VA + SC/SI/SA) in a
    # compact form. Scores are computed from the official CVSS 4.0 lookup table's
    # macro-vector approximation, plus a legacy CVSS 3.1 base score for tooling
    # that still speaks 3.1. This is a *documented heuristic* — not an authoritative
    # NVD score — and is labelled as such everywhere it is shown.
    CVSS_PROFILES = {
        # category key: (cvss4 macro-vector, cvss31 vector, cwe, cwe_name)
        "rce":          ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-94", "Improper Control of Generation of Code ('Code Injection')"),
        "sqli":         ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
        "deserialization": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-502", "Deserialization of Untrusted Data"),
        "ssrf":         ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", "CWE-918", "Server-Side Request Forgery (SSRF)"),
        "secrets":      ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "CWE-798", "Use of Hard-coded Credentials"),
        "info_disclosure": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "path_traversal": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
        "auth_bypass": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-287", "Improper Authentication"),
        "default_creds": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-1392", "Use of Default Credentials"),
        "xss":          ("AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "csrf":         ("AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-352", "Cross-Site Request Forgery (CSRF)"),
        "cors":         ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", "CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "open_redirect": ("AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", "CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "takeover":     ("AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-350", "Reliance on Reverse DNS Resolution for a Security-Critical Action"),
        "weak_crypto":  ("AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
        "tls_legacy":   ("AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-326", "Inadequate Encryption Strength"),
        "security_headers": ("AV:N/AC:H/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-693", "Protection Mechanism Failure"),
        "info_leak":    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "misconfig":    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "CWE-16", "Configuration"),
        "dos":          ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "CWE-400", "Uncontrolled Resource Consumption"),
        "supply_chain": ("AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-1104", "Use of Unmaintained Third Party Components"),
        "email_spoof":  ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "CWE-290", "Authentication Bypass by Spoofing"),
        "graphql":      ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "cloud_bucket": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-732", "Incorrect Permission Assignment for Critical Resource"),
        "generic":      ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", "CWE-noinfo", "Insufficient Information"),
    }

    # --- CVSS 4.0 macro-vector score table (official CVSS v4.0 spec, Appendix A) ---
    # Keys: (AV, AC, AT, PR, UI) equivalence classes → {VC/VI/VA + SC/SI/SA macro: score}
    # Simplified but faithful: we use the published "CVSS-B" macro scores.
    _CVSS4_BASE = {
        # AV:N/AC:L/AT:N/PR:N/UI:N  (the common network, no-auth, no-interaction class)
        "AV:N/AC:L/AT:N/PR:N/UI:N": {"H": 9.3, "M": 8.2, "L": 6.9, "N": 0.0},
        # AV:N/AC:L/AT:N/PR:N/UI:P  (network, no-auth, passive UI)
        "AV:N/AC:L/AT:N/PR:N/UI:P": {"H": 8.7, "M": 7.6, "L": 6.2, "N": 0.0},
        # AV:N/AC:L/AT:N/PR:N/UI:A  (network, no-auth, active UI)
        "AV:N/AC:L/AT:N/PR:N/UI:A": {"H": 8.6, "M": 7.1, "L": 5.1, "N": 0.0},
        # AV:N/AC:L/AT:N/PR:L/UI:N  (network, low priv, no interaction)
        "AV:N/AC:L/AT:N/PR:L/UI:N": {"H": 8.7, "M": 7.9, "L": 6.9, "N": 0.0},
        # AV:N/AC:L/AT:N/PR:L/UI:P
        "AV:N/AC:L/AT:N/PR:L/UI:P": {"H": 8.1, "M": 7.3, "L": 6.4, "N": 0.0},
        # AV:N/AC:L/AT:P/PR:N/UI:N  (network, no-auth, no interaction, attack requires conditions)
        "AV:N/AC:L/AT:P/PR:N/UI:N": {"H": 8.2, "M": 7.0, "L": 5.9, "N": 0.0},
        # AV:N/AC:H/AT:N/PR:N/UI:N  (network, high complexity)
        "AV:N/AC:H/AT:N/PR:N/UI:N": {"H": 8.3, "M": 7.1, "L": 5.9, "N": 0.0},
        # AV:N/AC:H/AT:P/PR:N/UI:N
        "AV:N/AC:H/AT:P/PR:N/UI:N": {"H": 7.4, "M": 6.3, "L": 5.1, "N": 0.0},
        # AV:N/AC:H/AT:N/PR:N/UI:P
        "AV:N/AC:H/AT:N/PR:N/UI:P": {"H": 7.7, "M": 6.6, "L": 5.3, "N": 0.0},
        # AV:N/AC:L/AT:N/PR:L/UI:A
        "AV:N/AC:L/AT:N/PR:L/UI:A": {"H": 7.1, "M": 6.4, "L": 4.8, "N": 0.0},
    }

    def _cvss4_score(self, macro):
        """Approximate a CVSS 4.0 base score from a macro-vector string."""
        try:
            parts = dict(p.split(':') for p in macro.split('/') if ':' in p)
        except Exception:
            parts = {}
        av = parts.get('AV', 'N'); ac = parts.get('AC', 'L')
        at = parts.get('AT', 'N'); pr = parts.get('PR', 'N'); ui = parts.get('UI', 'N')
        key = f"AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
        impact = 0
        for m in ('VC', 'VI', 'VA', 'SC', 'SI', 'SA'):
            v = parts.get(m, 'N')
            impact = max(impact, {'H': 3, 'L': 1, 'N': 0}.get(v, 0))
        # choose the exploitable class nearest to the requested one
        row = self._CVSS4_BASE.get(key) or next(
            (self._CVSS4_BASE[k] for k in self._CVSS4_BASE
             if k.startswith(f"AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/")), None)
        if not row:
            row = self._CVSS4_BASE["AV:N/AC:L/AT:N/PR:N/UI:N"]
        mag = 'H' if impact >= 3 else 'M' if impact == 2 else 'L' if impact == 1 else 'N'
        return round(row[mag], 1)

    def _cvss31_score(self, vector):
        """Compute the CVSS 3.1 base score from a full 3.1 vector string."""
        try:
            p = dict(x.split(':') for x in vector.replace("CVSS:3.1/", "").split('/') if ':' in x)
        except Exception:
            return 0.0
        av = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}.get(p.get('AV', 'N'), 0.85)
        ac = {'L': 0.77, 'H': 0.44}.get(p.get('AC', 'L'), 0.77)
        prm = p.get('PR', 'N'); scope_changed = p.get('S', 'U') == 'C'
        pr = {'N': 0.85, 'L': 0.62 if scope_changed else 0.61,
              'H': 0.27 if scope_changed else 0.27}.get(prm, 0.85)
        ui = {'N': 0.85, 'R': 0.62}.get(p.get('UI', 'N'), 0.85)
        v = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        iss = 1 - ((1 - v.get(p.get('C', 'N'), 0)) * (1 - v.get(p.get('I', 'N'), 0))
                   * (1 - v.get(p.get('A', 'N'), 0)))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = min((1.08 if scope_changed else 1.0) * (impact + expl), 10.0)
        return round(math.ceil(raw * 10) / 10, 1)

    def _cvss_category(self, check, detail):
        """Best-effort classification of a finding into a CVSS_PROFILES category."""
        c = f"{check} {detail}".lower()
        rules = [
            ("deserialization", r"deseriali[sz]|drupageddon|session.*deserial"),
            ("sqli", r"\bsqli\b|sql injection|sql-inject"),
            ("rce", r"\brce\b|remote code|code execution|command injection|ghostcat|log4shell|shellshock"),
            ("path_traversal", r"path traversal|directory traversal|\.\./|lfi|file inclusion"),
            ("ssrf", r"\bssrf\b|server-side request"),
            ("default_creds", r"default (credential|password)|admin:admin|weak password"),
            ("auth_bypass", r"auth bypass|authentication bypass|improper auth|jwt|token.*forg|accesstoken|auth.*weak"),
            ("takeover", r"takeover|dangling|unclaimed"),
            ("secrets", r"secret|api[_ -]?key|token|credential|password|private key|aws access"),
            ("cors", r"\bcors\b|access-control-allow-origin"),
            ("open_redirect", r"open redirect|redirect_uri|unvalidated redirect"),
            ("xss", r"\bxss\b|cross-site scripting|script injection|reflected.*input"),
            ("csrf", r"\bcsrf\b|cross-site request"),
            ("graphql", r"graphql|introspection"),
            ("cloud_bucket", r"bucket|s3|blob|gcs|storage"),
            ("weak_crypto", r"weak cipher|weak (cert|signature)|short (rsa|ec) key|rc4|md5|sha-?1"),
            ("tls_legacy", r"tls 1\.[01]|legacy tls|ssl ?v?[23]|expired cert|self-signed"),
            ("dos", r"\bdos\b|denial of service|depth limit|batch"),
            ("email_spoof", r"spf|dmarc|dkim|spoof|mta-sts|bimi"),
            ("supply_chain", r"supply chain|sri|third[- ]party|cdn|vendor"),
            ("security_headers", r"header|csp|hsts|x-frame|missing security"),
            ("info_disclosure", r"exposed \.(git|env|svn)|phpinfo|heapdump|actuator|server-status|web\.config|h2 console|directory listing|misconfig"),
            ("info_leak", r"info(rmation)? (leak|disclos)|verbose|version|banner"),
            ("misconfig", r"misconfig|configuration"),
        ]
        for cat, rx in rules:
            if re.search(rx, c):
                return cat
        return "generic"

    async def cvss_score_findings(self):
        """Module 45 — CVSS 4.0 / 3.1 + CWE risk scoring.

        Re-scores every finding collected across the whole scan with a
        documented CVSS 4.0 macro-vector (plus a legacy 3.1 base score) and a
        CWE weakness ID, producing an industry-standard priority register.
        Scores are a **reviewed heuristic** — clearly labelled — not an
        authoritative NVD assessment."""
        live = self._collect_findings()
        if not live:
            live = self._collect_findings_from_report(self.export_dict())
        entries, seen = [], set()
        for sev, check, detail, src in live:
            key = (check, detail[:80])
            if key in seen:
                continue
            seen.add(key)
            cat = self._cvss_category(check, detail)
            macro, vec31, cwe, cwe_name = self.CVSS_PROFILES.get(
                cat, self.CVSS_PROFILES["generic"])
            s4 = self._cvss4_score(macro)
            s31 = self._cvss31_score(vec31)
            # combined risk = max of the two standards, kept honest vs the base sev
            score = max(s4, s31)
            band = ("CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0
                    else "MEDIUM" if score >= 4.0 else "LOW")
            # the source severity stays authoritative-ish; flag large deltas
            delta = None
            base_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            band_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if base_rank.get(sev, 0) != band_rank.get(band, 0):
                delta = f"{sev}→{band}"
            entries.append({
                "severity": band, "source_severity": sev, "check": check,
                "source": src, "detail": detail[:200],
                "cvss4_vector": f"CVSS:4.0/{macro}",
                "cvss4_score": s4, "cvss31_vector": vec31, "cvss31_score": s31,
                "score": score, "category": cat,
                "cwe": cwe, "cwe_name": cwe_name, "rebanded": delta,
            })
        entries.sort(key=lambda e: -e["score"])
        dist = {b: len([e for e in entries if e["severity"] == b])
                for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        top = entries[:25]
        findings = [{"severity": e["severity"],
                     "check": f"[CVSS {e['score']}] {e['check']} ({e['cwe']})",
                     "detail": f"{e['cvss4_vector']} · {e['detail'][:120]}",
                     "evidence": f"CVSS4 {e['cvss4_score']} / CVSS3.1 {e['cvss31_score']} — {e['cwe_name']}"}
                    for e in top if e["severity"] in ("CRITICAL", "HIGH")]
        mean = round(sum(e["score"] for e in entries) / len(entries), 2) if entries else 0.0
        self.results['cvss'] = {
            "available": True, "count": len(entries),
            "mean_score": mean,
            "distribution": dist,
            "top": top,
            "register": entries[:400],
            "findings": findings,
            "method": ("Heuristic CVSS 4.0 macro-vector + CVSS 3.1 base score + CWE mapping. "
                       "Not an authoritative NVD assessment — use for prioritisation only."),
        }

    # ==================================================== MITRE ATT&CK Mapping (46)
    # Finding category → ATT&CK technique(s). Read-only mapping for defensive use.
    ATTACK_MAP = {
        "secrets":        [("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access")],
        "info_disclosure": [("T1592", "Gather Victim Host Information", "Reconnaissance"),
                            ("T1087", "Account Discovery", "Discovery")],
        "info_leak":      [("T1592.004", "Gather Victim Host Information: Client Configurations", "Reconnaissance")],
        "path_traversal": [("T1083", "File and Directory Discovery", "Discovery")],
        "sqli":           [("T1190", "Exploit Public-Facing Application", "Initial Access")],
        "rce":            [("T1190", "Exploit Public-Facing Application", "Initial Access"),
                           ("T1059", "Command and Scripting Interpreter", "Execution")],
        "deserialization": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
        "xss":            [("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution"),
                           ("T1185", "Browser Session Hijacking", "Collection")],
        "csrf":           [("T1204.001", "User Execution: Malicious Link", "Execution")],
        "ssrf":           [("T1190", "Exploit Public-Facing Application", "Initial Access"),
                           ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access")],
        "auth_bypass":    [("T1078", "Valid Accounts", "Defense Evasion")],
        "default_creds":  [("T1078.001", "Valid Accounts: Default Accounts", "Defense Evasion")],
        "takeover":       [("T1584.001", "Compromise Infrastructure: Domains", "Resource Development"),
                           ("T1583.001", "Acquire Infrastructure: Domains", "Resource Development")],
        "cors":           [("T1185", "Browser Session Hijacking", "Collection")],
        "open_redirect":  [("T1204.001", "User Execution: Malicious Link", "Execution")],
        "graphql":        [("T1592", "Gather Victim Host Information", "Reconnaissance")],
        "cloud_bucket":   [("T1530", "Data from Cloud Storage", "Collection")],
        "weak_crypto":    [("T1600", "Weaken Encryption", "Defense Evasion")],
        "tls_legacy":     [("T1040", "Network Sniffing", "Credential Access"),
                           ("T1557", "Adversary-in-the-Middle", "Collection")],
        "dos":            [("T1499", "Endpoint Denial of Service", "Impact")],
        "email_spoof":    [("T1566.002", "Phishing: Spearphishing Link", "Initial Access")],
        "supply_chain":   [("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access")],
        "security_headers": [("T1185", "Browser Session Hijacking", "Collection")],
        "misconfig":      [("T1592", "Gather Victim Host Information", "Reconnaissance")],
        "generic":        [("T1595", "Active Scanning", "Reconnaissance")],
    }

    async def attack_mapping(self):
        """Module 46 — map every finding to MITRE ATT&CK Enterprise.

        Produces a tactic/technique coverage view (SOC/blue-team value) and an
        ATT&CK Navigator layer JSON that can be imported into the official
        Navigator. Pure mapping over already-collected evidence — no new traffic."""
        # reuse the CVSS categorisation if module 45 ran, else classify here
        reg = (self.results.get('cvss', {}) or {}).get('register')
        if reg:
            rows = [(e["source_severity"], e["check"], e["detail"], e["source"],
                     e["category"], e["score"]) for e in reg]
        else:
            rows = []
            for sev, check, detail, src in self._collect_findings():
                cat = self._cvss_category(check, detail)
                rows.append((sev, check, detail, src, cat, 0.0))

        techniques, tactics, findings = {}, {}, []
        seen = set()
        for sev, check, detail, src, cat, score in rows:
            for tid, tname, tactic in self.ATTACK_MAP.get(cat, self.ATTACK_MAP["generic"]):
                key = (tid, check[:60])
                if key in seen:
                    continue
                seen.add(key)
                t = techniques.setdefault(tid, {
                    "id": tid, "name": tname, "tactic": tactic,
                    "count": 0, "examples": [], "max_severity": "INFO"})
                t["count"] += 1
                if len(t["examples"]) < 5:
                    t["examples"].append({"check": check, "severity": sev,
                                          "detail": detail[:150]})
                rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if rank.get(sev, 0) > rank.get(t["max_severity"], 0):
                    t["max_severity"] = sev
                tactics.setdefault(tactic, []).append(tid)
                if sev in ("CRITICAL", "HIGH"):
                    findings.append({"severity": sev,
                                     "check": f"ATT&CK {tid} — {tname}",
                                     "detail": f"{tactic} · {check[:110]}",
                                     "evidence": f"{detail[:150]}"})
        for tactic in tactics:
            tactics[tactic] = sorted(set(tactics[tactic]))
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: sev_rank.get(f["severity"], 5))
        _rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        tlist = sorted(techniques.values(),
                       key=lambda x: (-_rank.get(x["max_severity"], 0), x["id"]))

        # ATT&CK Navigator layer (schema 4.5) — offline, importable
        layer = {
            "name": f"NULLVEIL — {self.domain}",
            "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": ("Findings observed during a read-only NULLVEIL recon scan, "
                            "mapped to ATT&CK techniques."),
            "techniques": [{
                "techniqueID": t["id"],
                "score": t["count"],
                "color": {"CRITICAL": "#d32f2f", "HIGH": "#f57c00",
                          "MEDIUM": "#fbc02d", "LOW": "#388e3c"}.get(t["max_severity"], "#888888"),
                "comment": f"{t['count']} finding(s); max severity {t['max_severity']}",
                "enabled": True,
            } for t in tlist],
            "gradient": {"colors": ["#ffffff", "#d32f2f"], "minValue": 0,
                         "maxValue": max([t["count"] for t in tlist] + [1])},
            "legendItems": [{"label": "Observed technique", "color": "#d32f2f"}],
        }
        self.results['attack_map'] = {
            "available": True, "technique_count": len(tlist),
            "tactic_count": len(tactics), "techniques": tlist, "tactics": tactics,
            "layer": layer,
            "findings": findings[:200],
            "note": ("Read-only mapping for defensive coverage. No techniques are executed. "
                     "Import the layer into MITRE ATT&CK Navigator (JSON)."),
        }

    # ==================================================== CVE Intelligence Enricher (47)
    # Curated offline intel for the CVEs in CVE_RULES: CVSS + CWE + KEV + exploit.
    # This is the *offline fallback* — when --cve-live is enabled, the module also
    # queries NVD 2.0 + FIRST EPSS and merges the live values over these defaults.
    CVE_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".nullveil", "cve_cache")
    CVE_CACHE_TTL = 7 * 24 * 3600  # live CVE data is stable; refresh weekly
    CVE_INTEL = {
        "CVE-2021-41773": {"cvss": 9.8, "cwe": "CWE-22", "kev": True, "exploit": True,
                           "epss": 0.97, "desc": "Apache 2.4.49 path traversal/RCE — actively exploited."},
        "CVE-2021-42013": {"cvss": 9.8, "cwe": "CWE-22", "kev": True, "exploit": True,
                           "epss": 0.97, "desc": "Apache 2.4.50 incomplete fix for 41773 — RCE."},
        "CVE-2021-40438": {"cvss": 9.0, "cwe": "CWE-918", "kev": False, "exploit": True,
                           "epss": 0.90, "desc": "Apache mod_proxy SSRF."},
        "CVE-2021-23017": {"cvss": 7.7, "cwe": "CWE-193", "kev": False, "exploit": False,
                           "epss": 0.55, "desc": "nginx resolver off-by-one (DNS poisoning)."},
        "CVE-2020-11022": {"cvss": 6.1, "cwe": "CWE-79", "kev": False, "exploit": True,
                           "epss": 0.60, "desc": "jQuery htmlPrefilter XSS."},
        "CVE-2019-11358": {"cvss": 6.1, "cwe": "CWE-1321", "kev": False, "exploit": True,
                           "epss": 0.65, "desc": "jQuery prototype pollution."},
        "CVE-2015-9251": {"cvss": 6.1, "cwe": "CWE-79", "kev": False, "exploit": True,
                          "epss": 0.62, "desc": "jQuery cross-domain AJAX XSS."},
        "CVE-2021-41182": {"cvss": 6.1, "cwe": "CWE-79", "kev": False, "exploit": True,
                           "epss": 0.50, "desc": "jQuery UI XSS."},
        "CVE-2019-8331": {"cvss": 6.1, "cwe": "CWE-79", "kev": False, "exploit": True,
                          "epss": 0.58, "desc": "Bootstrap tooltip/popover XSS."},
        "CVE-2020-1938": {"cvss": 9.8, "cwe": "CWE-276", "kev": False, "exploit": True,
                          "epss": 0.94, "desc": "Tomcat Ghostcat AJP file read/RCE."},
        "CVE-2014-3704": {"cvss": 9.8, "cwe": "CWE-89", "kev": False, "exploit": True,
                          "epss": 0.93, "desc": "Drupal 7 'Drupageddon' SQLi."},
        "CVE-2018-7600": {"cvss": 9.8, "cwe": "CWE-94", "kev": True, "exploit": True,
                          "epss": 0.97, "desc": "Drupalgeddon2 RCE — actively exploited."},
        "CVE-2022-21661": {"cvss": 5.3, "cwe": "CWE-89", "kev": False, "exploit": True,
                           "epss": 0.40, "desc": "WordPress WP_Query SQLi."},
        "CVE-2015-8562": {"cvss": 9.8, "cwe": "CWE-502", "kev": False, "exploit": True,
                          "epss": 0.88, "desc": "Joomla session deserialization RCE."},
        "CVE-2021-44228": {"cvss": 10.0, "cwe": "CWE-502", "kev": True, "exploit": True,
                           "epss": 0.97, "desc": "Log4Shell JNDI RCE — actively exploited."},
        "CVE-2021-34473": {"cvss": 9.8, "cwe": "CWE-918", "kev": True, "exploit": True,
                           "epss": 0.97, "desc": "ProxyShell (Exchange) RCE."},
        "CVE-2017-5638": {"cvss": 10.0, "cwe": "CWE-20", "kev": True, "exploit": True,
                          "epss": 0.97, "desc": "Struts2 Jakarta Multipart RCE."},
        "CVE-2022-22965": {"cvss": 9.8, "cwe": "CWE-94", "kev": True, "exploit": True,
                           "epss": 0.97, "desc": "Spring4Shell RCE."},
        "CVE-2021-3129": {"cvss": 9.8, "cwe": "CWE-502", "kev": True, "exploit": True,
                          "epss": 0.96, "desc": "Laravel Ignition RCE."},
        "CVE-2021-26855": {"cvss": 9.8, "cwe": "CWE-918", "kev": True, "exploit": True,
                           "epss": 0.97, "desc": "ProxyLogon (Exchange) SSRF/RCE."},
    }

    async def cve_intel_enrich(self):
        """Module 47 — enrich fingerprinted versions' CVEs with intel.

        Merges **offline curated intel** (always available) with **live NVD 2.0 +
        FIRST EPSS** data when ``--cve-live`` is enabled. Live lookups are
        disk-cached (``~/.nullveil/cve_cache/``, weekly TTL) and degrade silently
        to the offline values when the network or the upstream API is unavailable.
        CVSS/CWE/KEV/EPSS are then ranked into real-world patch priorities
        (KEV > high-EPSS > CVSS). No active checks against the target."""
        versions = self.results.get('versions', []) or []
        cve_hits = self.results.get('cve_findings', []) or []
        intel_rows, findings, seen = [], [], set()
        # compound CVE regex over all evidence (versions + findings)
        blob = " ".join(str(v) for v in versions) + " " + \
               " ".join(str(f) for f in cve_hits)
        cve_ids = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', blob)))

        live = bool(getattr(self, "cve_live", False)) and bool(cve_ids)
        live_data = {}
        if live:
            try:
                live_data = await self._cve_live_fetch(cve_ids)
            except Exception as e:
                self.results['errors'].append(f"cveintel: live fetch failed: {e!r}")

        for cid in cve_ids:
            if cid in seen:
                continue
            seen.add(cid)
            info = self.CVE_INTEL.get(cid, {})
            lv = live_data.get(cid, {}) if isinstance(live_data, dict) else {}
            # live values win when present; otherwise fall back to offline intel
            cvss = lv.get("cvss") or info.get("cvss", 0.0)
            cwe = lv.get("cwe") or info.get("cwe", "CWE-noinfo")
            epss = lv.get("epss") if lv.get("epss") is not None else info.get("epss", 0.0)
            kev = bool(lv.get("kev")) or bool(info.get("kev"))
            exploit = (bool(lv.get("exploit_available"))
                       or bool(info.get("exploit"))
                       or bool(lv.get("kev")))
            desc = lv.get("desc") or info.get(
                "desc", "No intel available — verify against NVD.")
            source = lv.get("source") or ("offline curated" if cid in self.CVE_INTEL
                                          else "unknown")
            row = {
                "cve": cid, "cvss": cvss, "cwe": cwe, "kev": kev,
                "exploit_available": exploit, "epss": epss, "desc": desc,
                "known": cid in self.CVE_INTEL, "source": source,
            }
            sev = ("CRITICAL" if row["kev"] else
                   "CRITICAL" if row["cvss"] >= 9.0 else
                   "HIGH" if row["cvss"] >= 7.0 or row["exploit_available"] else
                   "MEDIUM" if row["cvss"] >= 4.0 else "LOW")
            row["severity"] = sev
            row["priority"] = ("P1 — patch now" if row["kev"] else
                               "P2 — urgent" if sev == "CRITICAL" else
                               "P3 — scheduled" if sev == "HIGH" else "P4 — routine")
            intel_rows.append(row)
            if sev in ("CRITICAL", "HIGH"):
                tags = " · ".join(t for t in (
                    "CISA KEV" if row["kev"] else "",
                    f"EPSS {row['epss']:.0%}" if row["epss"] else "",
                    "exploit public" if row["exploit_available"] else "") if t)
                findings.append({
                    "severity": sev,
                    "check": f"{cid} (CVSS {row['cvss']})",
                    "detail": f"{row['desc']} [{tags or 'no public exploit'}]",
                    "evidence": f"{row['cwe']} · {row['priority']}",
                })
        intel_rows.sort(key=lambda r: (-r["kev"], -r["epss"], -r["cvss"]))
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: sev_rank.get(f["severity"], 4))
        kev = [r["cve"] for r in intel_rows if r["kev"]]
        n_live = sum(1 for r in intel_rows if r.get("source", "").startswith("live"))
        note = (("Offline curated intel (CVSS/CWE/KEV/EPSS-style). "
                 "Always confirm against NVD + the vendor advisory before patching.")
                if not live else
                (f"Merged offline curated intel with LIVE NVD 2.0 + FIRST EPSS "
                 f"({n_live}/{len(intel_rows)} CVE(s) enriched live, disk-cached; "
                 f"rest fell back to offline values). Always confirm the vendor "
                 f"advisory before patching."))
        self.results['cve_intel'] = {
            "available": True, "count": len(intel_rows),
            "kev_count": len(kev), "kev": kev,
            "live": live, "live_enriched": n_live,
            "cvss_mean": round(sum(r["cvss"] for r in intel_rows) / len(intel_rows), 1)
                         if intel_rows else 0.0,
            "cves": intel_rows, "findings": findings,
            "note": note,
        }

    # ---------------------------------------------------------- Live CVE intel (NVD + EPSS)
    @classmethod
    def _cve_cache_path(cls, cve_id):
        return os.path.join(cls.CVE_CACHE_DIR, cve_id.replace('/', '_') + ".json")

    @classmethod
    def _cve_cache_read(cls, cve_id):
        """Return cached live intel for a CVE if fresh enough, else None."""
        try:
            p = cls._cve_cache_path(cve_id)
            if not os.path.isfile(p):
                return None
            if time.time() - os.path.getmtime(p) > cls.CVE_CACHE_TTL:
                return None
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None

    @classmethod
    def _cve_cache_write(cls, cve_id, data):
        try:
            os.makedirs(cls.CVE_CACHE_DIR, exist_ok=True)
            with open(cls._cve_cache_path(cve_id), "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
        except Exception:
            pass

    async def _cve_live_fetch(self, cve_ids, max_new=40):
        """Fetch live CVSS/CWE/KEV/EPSS for the given CVEs (cache-first).

        Sources (no API key required):
          * NVD 2.0 REST API  — CVSS v3.1/v3.0/v2 metrics + CWE weakness
          * FIRST EPSS API    — exploit-prediction score (``epss``/``percentile``)
          * CISA KEV catalog  — known-exploited flag (one download, cached)

        Returns ``{cve_id: {cvss, cwe, epss, kev, exploit_available, desc, source}}``.
        Only CVEs missing from the fresh cache cause network traffic, capped at
        ``max_new`` per scan to stay polite to the public APIs."""
        out, to_fetch = {}, []
        for cid in cve_ids:
            cached = self._cve_cache_read(cid)
            if cached:
                out[cid] = cached
            else:
                to_fetch.append(cid)
        if not to_fetch:
            return out
        to_fetch = to_fetch[:max_new]

        # --- CISA KEV catalog (one request, cached as a set) ---
        kev_set = await self._kev_set()

        # --- NVD 2.0 (per CVE; the API has no bulk-by-id GET) ---
        async def _nvd(cid):
            try:
                async with self.sem:
                    r = await self.client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": cid}, timeout=15.0,
                        headers={"User-Agent": "NULLVEIL-Recon"})
                if r.status_code != 200:
                    return {}
                v = (r.json().get("vulnerabilities") or [{}])[0].get("cve", {})
                metrics = v.get("metrics", {}) or {}
                score, vector = 0.0, ""
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(key) or []
                    if arr:
                        cd = arr[0].get("cvssData", {}) or {}
                        score = float(cd.get("baseScore") or 0.0)
                        vector = cd.get("vectorString", "")
                        break
                cwe = "CWE-noinfo"
                for w in (v.get("weaknesses") or []):
                    for d in (w.get("description") or []):
                        val = d.get("value", "")
                        if val.startswith("CWE-"):
                            cwe = val
                            break
                    if cwe != "CWE-noinfo":
                        break
                desc = ""
                for d in (v.get("descriptions") or []):
                    if d.get("lang") == "en":
                        desc = re.sub(r"\s+", " ", d.get("value", "")).strip()
                        break
                return {"cvss": round(score, 1), "vector": vector, "cwe": cwe,
                        "desc": desc[:400]}
            except Exception:
                return {}

        # --- EPSS (bulk query: one request for all CVEs) ---
        epss_map = {}
        try:
            async with self.sem:
                er = await self.client.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": ",".join(to_fetch)}, timeout=15.0,
                    headers={"User-Agent": "NULLVEIL-Recon"})
            if er.status_code == 200:
                for item in (er.json().get("data") or []):
                    try:
                        epss_map[item["cve"]] = {
                            "epss": float(item.get("epss") or 0.0),
                            "percentile": float(item.get("percentile") or 0.0)}
                    except Exception:
                        continue
        except Exception:
            pass

        nvd = await asyncio.gather(*[_nvd(c) for c in to_fetch])
        for cid, nv in zip(to_fetch, nvd):
            e = epss_map.get(cid, {})
            row = {
                "cvss": nv.get("cvss", 0.0),
                "cwe": nv.get("cwe", "CWE-noinfo"),
                "epss": e.get("epss", 0.0),
                "epss_percentile": e.get("percentile", 0.0),
                "kev": cid in kev_set,
                "exploit_available": bool(cid in kev_set or e.get("epss", 0) >= 0.5),
                "desc": nv.get("desc", ""),
                "source": "live:nvd+epss" if (nv or e) else "unknown",
            }
            out[cid] = row
            # cache only rows that actually carry data (avoid caching total misses)
            if nv or e or row["kev"]:
                self._cve_cache_write(cid, row)
        return out

    @classmethod
    async def _kev_set(cls):
        """Download + cache the CISA KEV catalog → set of CVE ids."""
        cache = os.path.join(cls.CVE_CACHE_DIR, "_kev_catalog.json")
        try:
            if os.path.isfile(cache) and time.time() - os.path.getmtime(cache) < cls.CVE_CACHE_TTL:
                with open(cache, encoding="utf-8") as fh:
                    return set(json.load(fh))
        except Exception:
            pass
        ids = set()
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
                r = await c.get(
                    "https://www.cisa.gov/sites/default/files/feeds/"
                    "known_exploited_vulnerabilities.json",
                    headers={"User-Agent": "NULLVEIL-Recon"})
            if r.status_code == 200:
                for v in (r.json().get("vulnerabilities") or []):
                    cid = v.get("cveID")
                    if cid:
                        ids.add(cid)
                try:
                    os.makedirs(cls.CVE_CACHE_DIR, exist_ok=True)
                    with open(cache, "w", encoding="utf-8") as fh:
                        json.dump(sorted(ids), fh)
                except Exception:
                    pass
        except Exception:
            pass
        return ids

    # ==================================================== Subdomain Takeover v3 (48)
    # Extended provider fingerprint list — (service, cname_suffixes, http_signature_regex)
    TAKEOVER_V3 = [
        ("AWS S3",              ["s3.amazonaws.com", "s3-website"], r"(?i)nosuchbucket|the specified bucket does not exist"),
        ("AWS CloudFront",      ["cloudfront.net"],                  r"(?i)bad request|generated by cloudfront"),
        ("AWS Elastic Beanstalk", ["elasticbeanstalk.com"],          r"(?i)404 not found|no application"),
        ("Heroku",              ["herokuapp.com", "herokussl.com", "herokudns.com"], r"(?i)no such app|herokucdn\.com/error-no-such-app"),
        ("GitHub Pages",        ["github.io", "githubusercontent.com"], r"(?i)there isn't a github pages site here"),
        ("GitLab Pages",        ["gitlab.io"],                       r"(?i)404|the page you're looking for could not be found"),
        ("Netlify",             ["netlify.app", "netlify.com"],      r"(?i)not found - request id|page not found"),
        ("Vercel",              ["vercel.app", "now.sh"],            r"(?i)404: not_found|deployment not found"),
        ("Azure App Service",   ["azurewebsites.net"],               r"(?i)404 - web app not found|this web app has been stopped"),
        ("Azure Cloud Service", ["cloudapp.net", "cloudapp.azure.com"], r"(?i)404 - web app not found"),
        ("Azure Blob",          ["blob.core.windows.net"],           r"(?i)resource not found|blob not found"),
        ("Azure Traffic Manager", ["trafficmanager.net"],            r"(?i)not found|traffic manager"),
        ("Azure Front Door",    ["azurefd.net"],                     r"(?i)not found|front door"),
        ("Azure Static Web",    ["azurestaticapps.net"],             r"(?i)not found|404"),
        ("Shopify",             ["shopify.com", "myshopify.com"],    r"(?i)sorry, this shop is currently unavailable"),
        ("Tumblr",              ["tumblr.com"],                      r"(?i)there's nothing here|whatever you were looking for doesn't exist"),
        ("WordPress.com",       ["wordpress.com"],                   r"(?i)doesn't exist|do you want to register"),
        ("Pantheon",            ["pantheonsite.io"],                 r"(?i)the gods are wise|404"),
        ("Zendesk",             ["zendesk.com"],                     r"(?i)help center closed"),
        ("Freshdesk",           ["freshdesk.com"],                   r"(?i)there is no helpdesk here|account not found"),
        ("Desk.com",            ["desk.com"],                        r"(?i)please try again later|not found"),
        ("Help Scout",          ["helpscoutdocs.com"],               r"(?i)no settings were found"),
        ("Intercom",            ["custom.intercom.help"],            r"(?i)this page is reserved"),
        ("Uservoice",           ["uservoice.com"],                    r"(?i)this uservoice subdomain is available"),
        ("Teamwork",            ["teamwork.com"],                    r"(?i)not found|create a new site"),
        ("Tilda",               ["tilda.ws", "tildacdn.com"],        r"(?i)please renew your subscription|tilda"),
        ("Read the Docs",       ["readthedocs.io"],                  r"(?i)404|the page you're looking for"),
        ("Surge.sh",            ["surge.sh"],                        r"(?i)project not found"),
        ("Bitbucket",           ["bitbucket.io"],                    r"(?i)repository not found"),
        ("Fastly",              ["fastly.net"],                      r"(?i)fastly error: unknown domain"),
        ("Ghost",               ["ghost.io"],                        r"(?i)404|domain is not configured"),
        ("Webflow",             ["webflow.io"],                      r"(?i)404|this site is not published"),
        ("Strikingly",          ["strikingly.com", "strikinglydns.com"], r"(?i)page not found|this site is not currently available"),
        ("Cargo",               ["cargocollective.com"],             r"(?i)404|not found"),
        ("Agile CRM",           ["agilecrm.com"],                    r"(?i)not found|this account"),
        ("Aha",                 ["aha.io"],                          r"(?i)not found|this aha account"),
        ("Statuspage",          ["statuspage.io"],                   r"(?i)not found|this page"),
        ("Smugmug",             ["smugmug.com"],                     r"(?i)not found|this page"),
        ("Smartling",           ["smartling.com"],                   r"(?i)not found"),
        ("Pingdom",             ["pingdom.com"],                     r"(?i)this public report does not exist"),
        ("Tictail",             ["tictail.com"],                     r"(?i)not found|shop is not available"),
        ("Campaign Monitor",    ["createsend.com"],                  r"(?i)not found|this page"),
        ("Acquia",              ["acquia-sites.com"],                r"(?i)not found"),
        ("Proposify",           ["proposify.com"],                   r"(?i)not found"),
        ("Simplebooklet",       ["simplebooklet.com"],               r"(?i)not found"),
        ("Sitemap.io",          ["sitemap.io"],                      r"(?i)not found"),
        ("Getresponse",         ["getresponse.com"],                 r"(?i)not found"),
        ("Mailchimp",           ["mailchimp.com"],                   r"(?i)not found"),
        ("Wix",                 ["wixsite.com"],                     r"(?i)not found|this site"),
        ("Squarespace",         ["squarespace.com"],                 r"(?i)not found|this site"),
        ("Launchrock",          ["launchrock.com"],                  r"(?i)not found"),
        ("Unbounce",            ["unbounce.com"],                    r"(?i)not found"),
        ("Ngrok",               ["ngrok.io", "ngrok-free.app"],      r"(?i)endpoint (is offline|not found)|tunnel .* not found"),
        ("Fly.io",              ["fly.dev"],                          r"(?i)404|application not found"),
        ("Render",              ["onrender.com"],                    r"(?i)not found|service not found"),
        ("Railway",             ["up.railway.app"],                  r"(?i)404|application not found"),
        ("Kinsta",              ["kinsta.cloud"],                    r"(?i)not found"),
        ("WP Engine",           ["wpengine.com", "wpenginepowered.com"], r"(?i)not found"),
        ("Contentful",          ["contentful.com"],                  r"(?i)not found|space not found"),
        ("Prismic",             ["prismic.io"],                      r"(?i)not found"),
        ("Firebase",            ["web.app", "firebaseapp.com"],      r"(?i)site not found|firebase app not found"),
        ("Google Sites",        ["sites.google.com"],                r"(?i)not found"),
        ("Blogger",             ["blogspot.com"],                    r"(?i)not found|blog has been removed"),
        ("Medium",              ["medium.com"],                      r"(?i)not found|out of nothing"),
        ("Hatena",              ["hatenablog.com"],                  r"(?i)not found"),
        ("Sendgrid",            ["sendgrid.net"],                    r"(?i)not found"),
        ("Tave",                ["tave.com"],                        r"(?i)not found"),
        ("Vend",                ["vendhq.com"],                      r"(?i)not found"),
        ("Volusion",            ["volusion.com"],                    r"(?i)not found"),
        ("Kajabi",              ["kajabi.com"],                      r"(?i)not found"),
        ("Bigcartel",           ["bigcartel.com"],                   r"(?i)not found"),
        ("Copper",              ["copper.com"],                      r"(?i)not found"),
        ("Canny",               ["canny.io"],                        r"(?i)not found|company not found"),
    ]

    async def takeover_v3(self):
        """Module 48 — standalone subdomain-takeover engine (v3 fingerprints).

        For each known subdomain, resolves the CNAME chain, matches it against
        70+ provider fingerprints and fetches the host to look for the provider's
        'unclaimed resource' signature. Reports dangling-CNAME candidates as
        HIGH-risk. **Read-only** — nothing is registered, claimed or modified."""
        hosts = set()
        for h in (self.results.get('subdomains') or []):
            h = str(h).strip().lower()
            if h:
                hosts.add(h)
        for h in (self.scalar_results.get('subdomains') or []):
            if h:
                hosts.add(str(h).strip().lower())
        root = self.domain.split(':')[0]
        hosts.add(root)
        hosts = sorted(hosts)[: (80 if self.deep else 40)]

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = min(self.timeout, 8)

        async def get_chain(host):
            chain = []
            cur = host
            for _ in range(6):
                try:
                    ans = await resolver.resolve(cur, 'CNAME')
                    tgt = str(ans[0].target).rstrip('.').lower()
                    chain.append(tgt)
                    cur = tgt
                except Exception:
                    break
            return chain

        risks, findings, checked = [], [], 0

        async def check(host):
            nonlocal checked
            chain = await get_chain(host)
            if not chain:
                return
            checked += 1
            cname = chain[-1]
            for service, suffixes, sig in self.TAKEOVER_V3:
                if not any(cname == s or cname.endswith('.' + s) or s in cname
                           for s in suffixes):
                    continue
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
                base = {"host": host, "cname_chain": chain, "service": service}
                if m:
                    risks.append({**base, "status": "LIKELY TAKEOVER",
                                  "signature": m.group(0)[:60], "severity": "HIGH"})
                    findings.append({
                        "severity": "HIGH",
                        "check": f"Subdomain takeover ({service})",
                        "detail": f"{host} → {cname} serves unclaimed-resource signature "
                                  f"'{m.group(0)[:50]}'",
                        "evidence": f"CNAME chain: {' → '.join(chain)}",
                    })
                elif not body:
                    risks.append({**base, "status": "DANGLING (unreachable)", "severity": "MEDIUM"})
                    findings.append({
                        "severity": "MEDIUM",
                        "check": f"Dangling CNAME ({service})",
                        "detail": f"{host} → {cname} is unreachable — verify the cloud "
                                  f"resource still exists",
                        "evidence": f"CNAME chain: {' → '.join(chain)}",
                    })
                else:
                    findings.append({
                        "severity": "INFO",
                        "check": f"Takeover check — {service}",
                        "detail": f"{host} → {cname} — no takeover signature (likely claimed)",
                        "evidence": f"CNAME chain: {' → '.join(chain)}",
                    })
                return

        await asyncio.gather(*[check(h) for h in hosts])
        sev_rank = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        findings.sort(key=lambda f: sev_rank.get(f["severity"], 3))
        self.results['takeover_v3'] = {
            "available": True, "hosts_checked": checked,
            "risk_count": len(risks), "risks": risks,
            "cname_hosts": checked,
            "findings": findings[:300],
            "providers": len(self.TAKEOVER_V3),
            "policy": "Read-only CNAME/HTTP inspection — no registration, claiming or modification.",
        }

    # ==================================================== Continuous Change Monitor (49)
    async def change_monitor(self):
        """Module 49 — continuous change monitor / watch baseline.

        Compares the current scan against the newest stored baseline for the
        same target and reports added/removed assets plus a risk delta. Designed
        for ``--watch`` (repeat runs every ``--interval`` seconds) and CI drift
        gates. Reuses the diff engine when available; otherwise computes a
        standalone snapshot comparison."""
        current = self.export_dict()
        prev = None
        for e in self._history_list():
            if e.get("domain", "").lower() == self.domain.lower():
                prev = e
                break
        cur = self._asset_sets(current)
        if not prev:
            self.results['watch'] = {
                "available": True, "baseline": False,
                "note": "No prior baseline for this target — this scan establishes the baseline.",
                "snapshot": {k: len(v) for k, v in cur.items()},
                "assets": {k: sorted(v)[:200] for k, v in cur.items()},
                "findings": [],
            }
            return
        old = self._asset_sets(prev.get("report", {}))
        added = {k: sorted(cur[k] - old[k]) for k in cur}
        removed = {k: sorted(old[k] - cur[k]) for k in old}
        # risk delta: weighted comparison of the two scans' finding summaries.
        # (module 49 runs before the post-scan diff engine, so we cannot rely on
        #  self.results['diff'] here — compute an honest delta from the summaries.)
        def _risk(report_like):
            sm = ((report_like or {}).get("report", report_like) or {}).get("summary", {}) or {}
            return (int(sm.get("cve_issues", 0) or 0) * 6
                    + int(sm.get("secrets", 0) or 0) * 8
                    + int(sm.get("takeover_risks", 0) or 0) * 10
                    + int(sm.get("tls_issues", 0) or 0) * 3
                    + int(sm.get("audit_issues", 0) or 0) * 2
                    + int(sm.get("admin_api_findings", 0) or 0) * 4)
        prev_score = _risk(prev)
        cur_score = _risk(current)
        delta = cur_score - prev_score
        SEV = {"ports": "HIGH", "api_endpoints": "HIGH", "subdomains": "MEDIUM",
              "paths": "MEDIUM", "users": "LOW", "cookies": "LOW", "js_files": "LOW",
              "tech_stack": "INFO"}
        findings = []
        for k, items in added.items():
            if not items:
                continue
            findings.append({
                "severity": SEV.get(k, "INFO"),
                "check": f"watch: new {k.rstrip('s')}",
                "detail": f"{len(items)} new {k}: {', '.join(items[:6])}" + (" …" if len(items) > 6 else ""),
                "evidence": f"baseline {prev.get('when', '')[:19]}",
            })
        for k, items in removed.items():
            if not items:
                continue
            findings.append({
                "severity": "INFO",
                "check": f"watch: removed {k.rstrip('s')}",
                "detail": f"{len(items)} {k} disappeared: {', '.join(items[:6])}" + (" …" if len(items) > 6 else ""),
                "evidence": f"baseline {prev.get('when', '')[:19]}",
            })
        total_added = sum(len(v) for v in added.values())
        verdict = ("REGRESSION" if delta > 0 else "IMPROVEMENT" if delta < 0
                   else "CHANGED" if total_added else "STABLE")
        self.results['watch'] = {
            "available": True, "baseline": True,
            "baseline_id": prev.get("id"), "baseline_when": prev.get("when"),
            "added": added, "removed": removed,
            "added_total": total_added,
            "removed_total": sum(len(v) for v in removed.values()),
            "risk_delta": delta, "prev_risk": prev_score, "cur_risk": cur_score,
            "verdict": verdict,
            "snapshot": {k: len(v) for k, v in cur.items()},
            "findings": findings,
        }

    # ---------------------------------------------------------- FFUF Fuzzing
    async def ffuf_fuzz(self):
        """Run ffuf content/API fuzzing (curated API wordlist + discovered paths)."""
        import shutil as _shutil
        exe = _shutil.which("ffuf") or _shutil.which("ffuf.exe")
        if not exe:
            self.results['ffuf'] = {
                "available": False, "findings": [],
                "note": "ffuf binary not found — install: go install github.com/ffuf/ffuf/v2@latest "
                        "(or: apt install ffuf)",
            }
            self.results['errors'].append(
                "ffuf: binary missing — install from github.com/ffuf/ffuf, then re-run -a ffuf")
            return

        # wordlist = curated API list + every discovered API path (base dirs too)
        # + user-supplied --ffuf-wordlist (if any)
        words = set(FFUF_API_WORDLIST)
        custom_wl = str(getattr(self, "ffuf_wordlist", "") or "")
        if custom_wl and os.path.isfile(custom_wl):
            try:
                with open(custom_wl, 'r', encoding='utf-8', errors='ignore') as fh:
                    words.update(
                        ln.strip() for ln in fh
                        if ln.strip() and not ln.startswith('#') and ' ' not in ln.strip())
            except Exception as _e:
                self.results['errors'].append(f"ffuf: could not read custom wordlist {custom_wl}: {_e}")
        elif custom_wl:
            self.results['errors'].append(f"ffuf: custom wordlist not found: {custom_wl}")
        for e in self.results.get('api_pool', []):
            p = str(e.get('path', '')).split('?')[0].strip('/')
            if p and 0 < len(p) < 60 and ' ' not in p:
                words.add(p)
            parts = [x for x in str(e.get('path', '')).strip('/').split('/') if x]
            for i in range(1, min(len(parts), 4)):
                words.add('/'.join(parts[:i]))
        words = sorted(w for w in words if w and not w.startswith('http'))
        wl_file = out_file = None
        try:
            fd, wl_file = tempfile.mkstemp(prefix="nullveil_ffuf_", suffix=".txt")
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                fh.write("\n".join(words))
            ofd, out_file = tempfile.mkstemp(prefix="nullveil_ffuf_", suffix=".json")
            os.close(ofd)

            url = self.base_url.rstrip('/') + "/FUZZ"
            cmd = [exe, "-u", url, "-w", wl_file,
                   "-mc", "200,201,202,204,207,301,302,307,401,403,405,500,501,502,503",
                   "-t", str(min(self.concurrency, 200)),
                   "-timeout", str(max(self.timeout, 8)),
                   "-of", "json", "-o", out_file, "-s",
                   "-H", f"User-Agent: Mozilla/5.0 NULLVEIL-Recon/{__version__}"]
            for h in getattr(self, "_auth_cmd", []):
                cmd += ["-H", h]
            if self.proxy:
                cmd += ["-x", self.proxy]   # Burp/Caido capture (module 34)
            if self.deep:
                cmd += ["-recursion", "-recursion-depth", "2"]
            wall_limit = 600 if self.deep else 300
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try:
                await asyncio.wait_for(proc.communicate(), timeout=wall_limit)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                self.results['errors'].append(f"ffuf: stopped after {wall_limit}s wall-time cap")

            try:
                with open(out_file, encoding='utf-8') as fh:
                    data = json.load(fh)
            except Exception:
                data = {}
        except Exception as e:
            self.results['errors'].append(f"ffuf: execution failed: {type(e).__name__} — {e}")
            self.results['ffuf'] = {"available": False, "findings": [],
                                    "note": f"execution failed: {type(e).__name__}"}
            return
        finally:
            for f in (wl_file, out_file):
                if f:
                    try:
                        os.unlink(f)
                    except Exception:
                        pass

        findings = []
        for r in (data.get('results') or []):
            findings.append({
                "url": r.get('url', ''), "status": r.get('status', 0),
                "size": r.get('length', 0), "words": r.get('words', 0),
                "content_type": r.get('content-type', ''),
                "redirectlocation": r.get('redirectlocation', ''),
            })
        self.results['ffuf'] = {
            "available": True, "binary": exe, "fuzz_url": url,
            "wordlist_size": len(words), "count": len(findings),
            "findings": findings[:500],
        }
        for f in findings[:500]:
            self.results['api_pool'].append(
                {"path": urlparse(f['url']).path or '/', "source": f"ffuf:{f['status']}"})

    # ======================================================== Burp / Caido Bridge (34)
    async def burp_bridge(self):
        """Burp Suite / Caido traffic-capture bridge.

        Two-way integration with intercepting proxies:
          • ``--har FILE`` (repeatable) — import HAR captures exported from
            Burp (Proxy > HTTP history > Save items > HAR) or Caido (Traffic >
            Export HAR): every request/response is parsed for endpoints,
            parameters, cookies, auth material, JS bundles & secrets, then fed
            into the unified API pool so ffuf/auth/smartfuzz analyze them too.
          • ``--proxy URL`` — the whole scan (shared httpx client + katana /
            ffuf / nuclei subprocesses) is routed through your local proxy, so
            NULLVEIL's traffic lands in Burp/Caido for manual follow-up; this
            module verifies the proxy is actually reachable and reports status.
        """
        proxy = str(getattr(self, "proxy", "") or "")
        har_files = list(getattr(self, "har_files", []) or [])
        info = {
            "proxy": proxy, "proxy_ok": False, "proxy_note": "",
            "har_files": [], "har_entries": 0,
            "endpoints": [], "params": [], "cookies": [], "auth_headers": [],
            "js_files": [], "secrets": [], "findings": [],
        }

        # ---------- 1) Proxy reachability (Burp :8080 / Caido :8080 typical) ----------
        if proxy:
            try:
                p = urlparse(proxy if "://" in proxy else f"http://{proxy}")
                host, port = p.hostname or "127.0.0.1", p.port or (443 if p.scheme == "https" else 8080)
                # Burp & Caido both speak plain HTTP proxying on the listener port
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=4)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                info["proxy_ok"] = True
                info["proxy_note"] = f"capture active — every request (httpx + katana/ffuf/nuclei) is routed via {host}:{port}"
                self.results['proxy_findings'].append(
                    ("INFO", "proxy-active", f"All scan traffic routed through {host}:{port} — inspect it live in Burp/Caido"))
            except Exception as e:
                info["proxy_note"] = f"proxy {proxy} unreachable ({type(e).__name__}) — scan continues WITHOUT capture"
                self.results['errors'].append(
                    f"proxy: {proxy} unreachable ({type(e).__name__} — {e}) — traffic not captured; "
                    f"start Burp/Caido listener or drop --proxy")

        # ---------- 2) HAR import (Burp / Caido / browser export) ----------
        endpoints, params, cookies, auth_headers, js_files = set(), set(), set(), set(), set()
        secrets = []
        seen_entries = 0

        def _walk_query(qs):
            """queryString list or dict-of-lists -> param names."""
            if isinstance(qs, list):
                for q in qs:
                    if isinstance(q, dict) and q.get("name"):
                        params.add(str(q["name"])[:80])
                    elif isinstance(q, str) and q:
                        params.add(q[:80])
            elif isinstance(qs, dict):
                for k in qs:
                    params.add(str(k)[:80])

        for hf in har_files:
            if not os.path.isfile(hf):
                self.results['errors'].append(f"har: file not found: {hf}")
                continue
            try:
                with open(hf, encoding='utf-8', errors='ignore') as fh:
                    har = json.load(fh)
            except Exception as e:
                self.results['errors'].append(f"har: could not parse {hf}: {type(e).__name__} — {e}")
                continue
            entries = ((har or {}).get('log') or {}).get('entries') or []
            info["har_files"].append({"file": hf, "entries": len(entries)})
            seen_entries += len(entries)

            for ent in entries:
                req = ent.get('request') or {}
                resp = ent.get('response') or {}
                url = str(req.get('url') or '')
                if not url:
                    continue
                method = str(req.get('method') or 'GET').upper()
                pu = urlparse(url)
                # keep only target (and its subdomains) traffic
                host = (pu.hostname or '').lower()
                if host and host != self.domain and not host.endswith('.' + self.domain):
                    continue
                path = (pu.path or '/') + (f"?{pu.query}" if pu.query else '')
                endpoints.add(f"{method} {path}")
                _walk_query(req.get('queryString'))
                # POST/PUT body params (form or JSON keys)
                pd = req.get('postData') or {}
                if isinstance(pd, dict):
                    _walk_query(pd.get('params'))
                    if str(pd.get('mimeType', '')).startswith('application/json') and pd.get('text'):
                        try:
                            body = json.loads(str(pd['text'])[:200_000])
                            if isinstance(body, dict):
                                for k in body:
                                    params.add(str(k)[:80])
                        except Exception:
                            pass
                # request headers — auth material names (values never stored) + cookie names
                for h in (req.get('headers') or []):
                    hn = str((h or {}).get('name') or '')
                    if re.search(r'(?i)^(authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|api-key)$', hn):
                        auth_headers.add(f"{method} {pu.path or '/'} → {hn}")
                    elif hn.lower() == 'cookie':
                        for pair in str((h or {}).get('value') or '').split(';'):
                            cn = pair.split('=', 1)[0].strip()
                            if cn:
                                cookies.add(cn[:80])
                # request cookies (HAR native field)
                for c in (req.get('cookies') or []):
                    cn = str((c or {}).get('name') or '')
                    if cn:
                        cookies.add(cn[:80])
                # response cookies
                for c in (resp.get('cookies') or []):
                    cn = str((c or {}).get('name') or '')
                    if cn:
                        cookies.add(cn[:80])
                # JS bundles directly requested
                if pu.path and re.search(r'\.m?js(\?|$)', pu.path, re.I):
                    js_files.add(url)
                # secrets in response bodies
                rtext = str(((resp.get('content') or {}).get('text') or ''))[:500_000]
                if rtext:
                    # JS bundles referenced by captured HTML/JS (script src=)
                    for sm in re.finditer(r'''<script[^>]+src\s*=\s*["']([^"']+?\.m?js(?:\?[^"']*)?)["']''', rtext, re.I):
                        js_files.add(urljoin(url, sm.group(1)))
                    for label, pat in SECRET_PATTERNS:
                        m = re.search(pat, rtext)
                        if m:
                            val = m.group(0)
                            masked = val[:6] + "…" + val[-3:] if len(val) > 12 else val[:2] + "…"
                            secrets.append(f"{label} (HAR {method} {pu.path or '/'}): {masked}")

        info["har_entries"] = seen_entries
        info["endpoints"] = sorted(endpoints)[:3000]
        info["params"] = sorted(params)[:1500]
        info["cookies"] = sorted(cookies)[:200]
        info["auth_headers"] = sorted(auth_headers)[:300]
        info["js_files"] = sorted(js_files)[:500]
        info["secrets"] = secrets[:100]

        # feed unified API pool → ffuf / auth / smartfuzz pick these up
        for ep in sorted(endpoints)[:1500]:
            path_only = ep.split(' ', 1)[1] if ' ' in ep else ep
            self.results['api_pool'].append({"path": path_only, "source": "har"})

        if secrets:
            self.results['proxy_findings'].append(
                ("HIGH", "har-secrets", f"{len(secrets)} secret(s) visible in captured HAR responses"))
        if cookies:
            self.results['proxy_findings'].append(
                ("INFO", "har-cookies", f"{len(cookies)} cookie(s) seen in capture: {', '.join(sorted(cookies)[:8])}"))
        if auth_headers:
            self.results['proxy_findings'].append(
                ("INFO", "har-auth", f"{len(auth_headers)} authenticated request(s) captured — replayable in Repeater / Caido"))

        self.results['burp'] = info
        if not proxy and not har_files:
            self.results['burp']["proxy_note"] = (
                "no --proxy / --har given — run with --proxy http://127.0.0.1:8080 (Burp) "
                "to capture traffic, or --har capture.har to import an existing capture")

    # ======================================================== Authenticated Scan (31)
    @staticmethod
    def _parse_header_specs(specs):
        """['Name: Value', ...] -> {'Name': 'Value'} (first ':' splits)."""
        out = {}
        for s in specs or []:
            s = str(s)
            if ":" in s:
                name, val = s.split(":", 1)
                if name.strip():
                    out[name.strip()] = val.strip()
        return out

    async def _auth_setup(self):
        """Inject session headers/cookies + run the automated login engine ONCE
        at scan start, so every module (shared httpx client + katana/ffuf/nuclei
        subprocesses) operates inside the same authenticated session."""
        cfg = getattr(self, "auth_cfg", {}) or {}
        hdrs = self._parse_header_specs(cfg.get("headers"))
        for c in (cfg.get("cookies") or []):
            c = str(c)
            if "=" in c:
                k, v = c.split("=", 1)
                if k.strip():
                    self.client.cookies.set(k.strip(), v.strip())
        if cfg.get("token"):
            hdrs["Authorization"] = f"Bearer {cfg['token']}"
        if cfg.get("api_key"):
            hdrs[str(cfg.get("api_key_header") or "X-API-Key")] = str(cfg["api_key"])
        # static session material applies BEFORE login (some logins need it)
        for k, v in hdrs.items():
            self.client.headers[k] = v

        login_summary = None
        lu = str(cfg.get("login_url") or "")
        user = str(cfg.get("login_user") or "")
        pw = str(cfg.get("login_pass") or "")
        if lu and user:
            uf = str(cfg.get("user_field") or "username")
            pf = str(cfg.get("pass_field") or "password")
            tpl = str(cfg.get("body") or "")
            try:
                payload = {uf: user, pf: pw}
                for kv in (cfg.get("extra") or []):
                    if "=" in str(kv):
                        a, b = str(kv).split("=", 1)
                        if a.strip():
                            payload[a.strip()] = b.strip()
                if tpl:
                    body = (tpl.replace("{user}", user).replace("{pass}", pw)
                               .replace("{password}", pw))
                    json.loads(body)                      # validate the template
                    as_json = True
                else:
                    body = json.dumps(payload)
                    as_json = not cfg.get("form")
                url = (lu if lu.startswith("http")
                       else self.base_url.rstrip("/") + "/" + lu.lstrip("/"))
                if as_json:
                    resp = await self.client.post(
                        url, content=body.encode("utf-8"),
                        headers={"Content-Type": "application/json"})
                else:
                    resp = await self.client.post(url, data=payload)
                captured = []
                token_val = None
                try:
                    jd = resp.json()
                except Exception:
                    jd = None
                if isinstance(jd, dict):
                    probes = ([str(cfg["token_path"])] if cfg.get("token_path") else []) + [
                        "access_token", "token", "jwt", "id_token", "data.access_token",
                        "data.token", "result.access_token", "result.token",
                        "auth.token", "session.token"]
                    for pth in probes:
                        cur = jd
                        try:
                            for part in pth.split("."):
                                cur = cur[part]
                        except Exception:
                            continue
                        if isinstance(cur, str) and 8 < len(cur) < 8192:
                            token_val = cur
                            captured.append(f"bearer token (json path: {pth})")
                            break
                if token_val:
                    hdrs["Authorization"] = f"Bearer {token_val}"
                rh = (resp.headers.get("authorization")
                      or resp.headers.get("x-auth-token") or "")
                if rh and not token_val:
                    hdrs["Authorization"] = rh
                    captured.append("auth response header")
                try:
                    n_ck = len(self.client.cookies.jar)
                except Exception:
                    n_ck = 0
                if n_ck:
                    captured.append(f"{n_ck} session cookie(s)")
                login_summary = {"url": url, "status": resp.status_code,
                                 "captured": captured or ["none"]}
                if resp.status_code >= 400:
                    self.results['errors'].append(
                        f"auth: login returned HTTP {resp.status_code} at {url}")
            except Exception as e:
                login_summary = {"url": lu, "status": 0,
                                 "error": f"{type(e).__name__} — {e}"}
                self.results['errors'].append(
                    f"auth: automated login failed: {login_summary['error']}")

        # final headers on the shared client + header list for subprocess tools
        for k, v in hdrs.items():
            self.client.headers[k] = v
        self._auth_cmd = [f"{k}: {v}" for k, v in hdrs.items()]
        try:
            ck = "; ".join(f"{c.name}={c.value}" for c in self.client.cookies.jar)
            if ck and not any(x.lower().startswith("cookie:") for x in self._auth_cmd):
                self._auth_cmd.append(f"Cookie: {ck}")
        except Exception:
            pass

        # ---- multi-role profiles:
        #   --role 'admin=Authorization: Bearer eyJ...'   -> header override
        #   --role 'user=Cookie: sid=abc'                 -> cookie set
        #   --role 'member=session=xyz'                   -> cookie shorthand
        #   --role 'qa=abc123def456'                      -> bare token -> Bearer
        roles = {}
        for r in (cfg.get("roles") or []):
            if "=" not in str(r):
                continue
            name, spec = str(r).split("=", 1)
            name, spec = name.strip(), spec.strip()
            if not name or not spec:
                continue
            rh_, rc = {}, {}
            m = re.match(r"^([\w-]{1,60})\s*:\s*(.+)$", spec, re.S)
            if m and m.group(1).lower() == "cookie":
                for part in m.group(2).split(";"):
                    if "=" in part:
                        a, b = part.split("=", 1)
                        if a.strip():
                            rc[a.strip()] = b.strip()
            elif m:
                rh_[m.group(1)] = m.group(2).strip()
            elif "=" in spec:
                a, b = spec.split("=", 1)
                if a.strip():
                    rc[a.strip()] = b.strip()
            else:
                rh_["Authorization"] = f"Bearer {spec}"
            roles[name] = {"headers": rh_, "cookies": rc}
        self.roles = roles

        try:
            ck_names = sorted({c.name for c in self.client.cookies.jar})
        except Exception:
            ck_names = []
        self.results['auth_setup'] = {
            "active": bool(hdrs or ck_names or roles),
            "headers": sorted(hdrs.keys()),
            "cookies": ck_names,
            "roles": sorted(roles.keys()),
            "login": login_summary,
        }
        if self.results['auth_setup']["active"]:
            console.print(f"      [bold green]✓ Auth active[/] — "
                          f"headers: {', '.join(sorted(hdrs)) or '-'}  ·  "
                          f"cookies: {', '.join(ck_names) or '-'}  ·  "
                          f"roles: {', '.join(sorted(roles)) or '-'}")

    async def auth_scan(self):
        """Probe every discovered endpoint WITH & WITHOUT the session to expose
        auth-gated APIs, then repeat per --role profile to find role-hidden ones."""
        auth_info = self.results.get('auth_setup') or {}
        eps, seen = [], set()
        for e in (self.results.get('api_pool') or []):
            p = str((e or {}).get('path', '')).split('#')[0]
            if p and p not in seen:
                seen.add(p)
                eps.append(p)
        for p in (self.results.get('api_endpoints') or []):
            path = str(p.get('path', '') if isinstance(p, dict) else p).split('#')[0]
            if path and path not in seen:
                seen.add(path)
                eps.append(path)
        for p in (self.results.get('api_endpoints_found') or []):
            path = str(p).split('#')[0]
            if path and path not in seen:
                seen.add(path)
                eps.append(path)
        limit = 60 if self.deep else 30
        eps = [e for e in eps if e.startswith('/') or str(e).startswith('http')][:limit]

        if not auth_info.get("active"):
            self.results['authscan'] = {
                "available": False, "endpoints_probed": 0, "auth_gated": 0,
                "status_changed": 0, "session_verified": False, "findings": [],
                "roles": [], "role_matrix": {}, "role_gated": [],
                "note": "No session configured — pass --auth-token / --auth-header / "
                        "--auth-cookie, or --login-url + --login-user + --login-pass "
                        "for the automated login engine (then: -a auth)",
            }
            return
        if not eps:
            admin_audit = await self._auth_admin_audit([], None)
            self.results['authscan'] = {
                "available": True, "endpoints_probed": 0, "auth_gated": 0,
                "status_changed": 0, "session_verified": False, "findings": [],
                "roles": sorted(self.roles), "role_matrix": {}, "role_gated": [],
                "note": "Session active but no discovered endpoints to diff — add "
                        "discovery modules: -a api,katana,linkfinder,ffuf,auth",
                "admin_audit": admin_audit,
            }
            return

        def _abs(p):
            p = str(p)
            return (p if p.startswith('http')
                    else self.base_url.rstrip('/') + (p if p.startswith('/') else '/' + p))

        bare = httpx.AsyncClient(follow_redirects=True, timeout=self.timeout, verify=False,
                                 headers={"User-Agent": self.client.headers.get(
                                     "User-Agent", f"NULLVEIL-Recon/{__version__}")})
        diffs, role_matrix, gated = [], {}, []

        async def _probe(cli, path, headers=None, cookies=None):
            try:
                async with self.sem:
                    r = await cli.get(_abs(path), headers=headers or {}, cookies=cookies)
                return r.status_code, len(r.content)
            except Exception:
                return None, None

        try:
            for p in eps:
                ns, nl = await _probe(bare, p)
                as_, al_ = await _probe(self.client, p)
                if ns is None and as_ is None:
                    continue
                auth_gated = (ns in (401, 403, 404)
                              and as_ in (200, 201, 202, 204, 301, 302))
                diffs.append({"path": p, "status_noauth": ns, "status_auth": as_,
                              "size_noauth": nl, "size_auth": al_,
                              "auth_gated": auth_gated})
                if auth_gated:
                    self.results['api_pool'].append({"path": p, "source": "auth:gated"})
                if self.roles:
                    codes = {}
                    for rname, rcfg in self.roles.items():
                        rs, _ = await _probe(self.client, p,
                                             headers=rcfg.get("headers") or {},
                                             cookies=(rcfg.get("cookies") or None))
                        codes[rname] = rs
                    role_matrix[p] = codes
                    live = {k: v for k, v in codes.items() if v is not None}
                    if len(live) >= 2 and 200 in live.values():
                        allowed = sorted(k for k, v in live.items() if v == 200)
                        hidden = [{"role": k, "status": v}
                                  for k, v in sorted(live.items()) if v != 200]
                        if hidden:
                            gated.append({"path": p, "visible_to": allowed,
                                          "hidden_from": hidden})
        finally:
            try:
                await bare.aclose()
            except Exception:
                pass

        changed = [d for d in diffs if d["status_noauth"] != d["status_auth"]]
        gated_paths = [d for d in diffs if d["auth_gated"]]
        for g in gated[:100]:
            self.results['api_pool'].append({"path": g["path"], "source": "auth:role-hidden"})

        # ---- backend / admin API audit with the injected session ----------
        admin_audit = await self._auth_admin_audit(eps, bare)

        self.results['authscan'] = {
            "available": True, "endpoints_probed": len(eps),
            "auth_gated": len(gated_paths), "status_changed": len(changed),
            "session_verified": bool(gated_paths or changed),
            "findings": changed[:200], "roles": sorted(self.roles.keys()),
            "role_matrix": role_matrix, "role_gated": gated[:100],
            "admin_audit": admin_audit,
        }

    # ------------------------------------------------- Backend / admin API audit
    ADMIN_BACKEND_PATHS = [
        "/admin", "/admin/", "/admin/api", "/api/admin", "/api/v1/admin",
        "/api/v2/admin", "/api/internal", "/internal", "/internal/api",
        "/api/private", "/private", "/api/manage", "/manage", "/management",
        "/api/console", "/console", "/api/backoffice", "/backoffice",
        "/api/staff", "/staff", "/api/superuser", "/superadmin",
        "/api/debug", "/debug", "/api/config", "/api/settings",
        "/api/users", "/api/v1/users", "/api/accounts", "/api/roles",
        "/api/permissions", "/api/metrics", "/api/health", "/api/status",
        "/api/export", "/api/import", "/api/logs", "/api/audit",
        "/api/tokens", "/api/keys", "/api/webhooks", "/api/jobs",
        "/api/queue", "/api/tasks", "/api/system", "/api/tenant",
    ]
    ADMIN_CTYPE_OK = re.compile(r'(?i)(json|xml|plain|javascript)')
    ADMIN_BODY_SIG = re.compile(
        r'(?i)("?(role|is_admin|is_superuser|permissions|scope|privilege|'
        r'access_token|refresh_token|api_key|secret|password_hash|ssn|credit_card)"?\s*:|'
        r'<role>|<permissions>|admin|superuser)')

    async def _auth_admin_audit(self, eps, bare):
        """With the authenticated session, probe admin/backend endpoints and flag
        those reachable *only* with the session (privilege surface) plus
        authenticated data-exposure signals (sensitive keys, verbose errors)."""
        found, findings = [], []
        # a no-auth client is needed for the "session-only" comparison
        own_bare = False
        if bare is None:
            bare = httpx.AsyncClient(follow_redirects=True, timeout=self.timeout, verify=False,
                                     headers={"User-Agent": self.client.headers.get(
                                         "User-Agent", f"NULLVEIL-Recon/{__version__}")})
            own_bare = True
        try:
            return await self._auth_admin_audit_run(eps, bare, found, findings)
        finally:
            if own_bare:
                try:
                    await bare.aclose()
                except Exception:
                    pass

    async def _auth_admin_audit_run(self, eps, bare, found, findings):
        # candidate admin paths + any discovered path that looks privileged
        candidates, seen = [], set()
        for p in self.ADMIN_BACKEND_PATHS:
            if p not in seen:
                seen.add(p)
                candidates.append(p)
        for p in eps:
            lp = str(p).lower()
            if any(k in lp for k in ('admin', 'internal', 'backoffice', 'manage',
                                     'superuser', 'staff', 'debug', 'private')):
                if p not in seen:
                    seen.add(p)
                    candidates.append(p)
        candidates = candidates[:(80 if self.deep else 40)]

        def _abs(p):
            p = str(p)
            return (p if p.startswith('http')
                    else self.base_url.rstrip('/') + (p if p.startswith('/') else '/' + p))

        for p in candidates:
            try:
                async with self.sem:
                    authed = await self.client.get(_abs(p))
                    bare_r = await bare.get(_abs(p))
            except Exception:
                continue
            if authed.status_code not in (200, 201, 202, 204, 207, 300, 301, 302, 401, 403):
                continue
            ctype = (authed.headers.get('content-type') or '').lower()
            body = (authed.text or '')[:60_000]
            sensitive = bool(re.search(
                r'(?i)"?(password_hash|api_key|secret|ssn|credit_card|access_token|'
                r'private_key|refresh_token)"?\s*:', body))
            verbose = bool(re.search(
                r'(?i)(traceback|stack trace|sqlstate|syntax error|at\s+\w+\.\w+\('
                r'|exception in thread|django\.|org\.springframework)', body))
            data_sig = bool(self.ADMIN_BODY_SIG.search(body)) and bool(self.ADMIN_CTYPE_OK.search(ctype))
            session_only = (bare_r.status_code in (401, 403, 404)
                            and authed.status_code in (200, 201, 202, 204))
            reachable = authed.status_code in (200, 201, 202, 204)
            if not (session_only or (reachable and (sensitive or verbose))):
                continue

            sev = "HIGH" if (session_only and reachable) else "MEDIUM"
            detail_parts = []
            if session_only:
                detail_parts.append(f"reachable only WITH session (no-auth→{bare_r.status_code}, auth→{authed.status_code})")
            if sensitive:
                sev = "CRITICAL"
                detail_parts.append("sensitive fields (password_hash/api_key/secret/token) in authenticated response")
            if verbose:
                detail_parts.append("verbose error / stack trace leaked")
            if data_sig and not detail_parts:
                detail_parts.append("administration-like data structure exposed to this session")
            rec = {
                "path": p, "status": authed.status_code,
                "noauth_status": bare_r.status_code, "session_only": session_only,
                "sensitive_keys": sensitive, "verbose_error": verbose, "size": len(authed.content),
            }
            found.append(rec)
            findings.append((sev, "admin-api", f"{p}: " + "; ".join(detail_parts)))
            if reachable:
                self.results['api_pool'].append({"path": p, "source": "auth:admin"})

        result = {
            "probed": len(candidates), "reachable": len(found),
            "session_only": len([f for f in found if f["session_only"]]),
            "sensitive": len([f for f in found if f["sensitive_keys"]]),
            "endpoints": found[:150],
            "findings": findings[:150],
        }
        # surface admin findings as report-wide findings too
        self.results.setdefault('admin_findings', []).extend(findings)
        return result

    # ======================================================== Finding helpers
    def _collect_findings(self):
        """Flatten every finding across all modules into one normalised list.

        Returns ``[(severity, check, detail, source_module), ...]`` sorted by
        severity (CRITICAL first). Used by the patch / PoC / notify / executive
        modules so they all reason over the same evidence set."""
        F = []
        r = self.results

        def add(sev, chk, det, src):
            det = str(det or "")
            # keep to a single line and a sane length for every consumer
            det = re.sub(r"\s+", " ", det).strip()[:400]
            F.append((str(sev or "INFO").upper(), str(chk or ""), det, src))

        # generic (sev, check, detail) triples used across modules
        # (email_findings uses (sev, message) 2-tuples, so handle both shapes)
        for key, src in (("email_findings", "email"), ("api_audit_findings", "audit"),
                         ("ext_findings", "ext"), ("tls_findings", "tls"),
                         ("admin_findings", "auth"), ("proxy_findings", "burp"),
                         ("vuln_verify_findings", "vulnverify"),
                         ("plugin_findings", "plugin"),
                         ("diff_findings", "diff")):
            for t in (r.get(key) or []):
                if isinstance(t, (list, tuple)) and len(t) >= 3:
                    add(t[0], t[1], t[2], src)
                elif isinstance(t, (list, tuple)) and len(t) == 2:
                    add(t[0], src, t[1], src)
        # dict-grouped findings {severity, check/id, detail}
        for key, src in (("nuclei", "nuclei"), ("supply", "supply"), ("anomaly", "anomaly"),
                         ("intel", "intel"), ("breach", "breach"), ("correlation", "correlate"),
                         ("compliance", "comp"), ("js_secret", "jssecret"),
                         ("wayback", "wayback"), ("param", "param"),
                         ("graphql", "gql"), ("cloud", "cloud"),
                         ("cvss", "cvss"), ("attack_map", "attack"),
                         ("cve_intel", "cveintel"), ("takeover_v3", "takeover"),
                         ("watch", "watch")):
            blob = r.get(key) or {}
            for f in (blob.get("findings") or []) if isinstance(blob, dict) else []:
                if isinstance(f, dict):
                    chk = f.get("id") or f.get("check") or f.get("title") or src
                    det = f.get("detail") or f.get("message") or f.get("desc") or ""
                    add(f.get("severity"), chk, det, src)
                elif isinstance(f, (list, tuple)) and len(f) >= 3:
                    add(f[0], f[1], f[2], src)
                elif isinstance(f, (list, tuple)) and len(f) == 2:
                    add(f[0], src, f[1], src)
        # cve / ffuf / katana style
        for f in (r.get("cve_findings") or []):
            if isinstance(f, (list, tuple)) and len(f) >= 3:
                add(f[0], f[1], f[2], "cve")
        for x in ((r.get("ffuf") or {}).get("findings") or []):
            if isinstance(x, dict):
                st = str(x.get("status", ""))
                if st in ("200", "401", "403", "500"):
                    sev = "HIGH" if st == "200" else "INFO"
                    add(sev, "ffuf-path", f"{st} {x.get('url', '')} (size {x.get('size', '?')})", "ffuf")
        for x in ((r.get("katana") or {}).get("endpoints") or [])[:0]:
            pass
        for s, c, d in (r.get("graph", {}) or {}).get("chains", [])[:0]:
            pass
        F.sort(key=lambda t: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                              "LOW": 3, "INFO": 4}.get(t[0], 5))
        return F

    async def _verify_findings_pass(self):
        """Deep-accuracy pass (--verify).

        Re-verifies the *reproducible-URL* class of findings with a second,
        independent request issued from a fresh connection. A finding is kept
        only when the second probe agrees with the first; findings that do not
        reproduce are moved to ``results['verify_dropped']`` instead of being
        silently deleted, so nothing is ever hidden from the operator.

        Read-only: it only re-issues the same GET/HEAD the module already made.
        """
        candidates = []
        # 1) flagged paths / exposed resources (the highest false-positive class).
        #    Entries are dicts like {"path": "/.git/config", "status": 200, "flagged": true}.
        for entry in list(self.results.get('paths', [])):
            if not isinstance(entry, dict):
                continue
            path = entry.get("path") or ""
            if not path:
                continue
            url = path if path.startswith("http") else urljoin(self.base_url + "/", path.lstrip("/"))
            label = f"{path} (status {entry.get('status')}{', flagged' if entry.get('flagged') else ''})"
            candidates.append(("paths", url, label))
        # 2) plausible .git/.env/config exposures flagged by the audit
        for sev, chk, det in list(self.results.get('api_audit_findings', [])):
            if re.search(r"(?i)(\.git|\.env|config|backup|swagger|exposed)", f"{chk} {det}"):
                m = re.search(r"(https?://[^\s'\"<>)]+)", det)
                base = m.group(1) if m else ""
                if not base:
                    pm = re.search(r"(/[A-Za-z0-9._\-/]{2,})", det)
                    if pm:
                        base = urljoin(self.base_url + "/", pm.group(1).lstrip('/'))
                if base:
                    candidates.append(("audit", base, f"{chk}: {det}"))

        # de-dupe candidate URLs and cap the work
        seen = set()
        uniq = []
        for kind, url, det in candidates:
            if url in seen:
                continue
            seen.add(url)
            uniq.append((kind, url, det))
        cap = 200 if self.deep else 80
        uniq = uniq[:cap]
        if not uniq:
            self.results['verify_stats'] = {"tested": 0, "kept": 0, "dropped": 0}
            return

        async def _confirm(url):
            # a finding "reproduces" when a fresh GET still returns a
            # non-404 status (the truthy signal the module keyed on).
            try:
                async with self.sem:
                    r = await self.client.get(url, timeout=min(self.timeout, 12))
                return r.status_code not in (404, 410)
            except Exception:
                return None   # unknown — do NOT drop on a network hiccup

        results = await asyncio.gather(*[_confirm(u) for _, u, _ in uniq])
        kept = dropped = unknown = 0
        drop_urls = set()
        for (kind, url, det), ok in zip(uniq, results):
            if ok is None:
                unknown += 1
            elif ok:
                kept += 1
            else:
                dropped += 1
                drop_urls.add(url)
                self.results['verify_dropped'].append(f"[{kind}] {url} — did not reproduce on re-probe")

        # Drop non-reproducing *path* findings from the report — but only when the
        # probe actually reached the host (kept + dropped > 0). If every probe was
        # inconclusive the target is probably down, so we keep everything.
        if kept + dropped > 0 and drop_urls:
            before = len(self.results.get('paths', []))
            def _keep(p):
                if not isinstance(p, dict):
                    return True
                path = p.get("path") or ""
                url = path if str(path).startswith("http") else urljoin(self.base_url + "/", str(path).lstrip("/"))
                return url not in drop_urls
            self.results['paths'] = [p for p in self.results.get('paths', []) if _keep(p)]
            dropped_paths = before - len(self.results['paths'])
        else:
            dropped_paths = 0

        self.results['verify_stats'] = {"tested": len(uniq), "kept": kept,
                                        "dropped": dropped, "unknown": unknown,
                                        "paths_removed": dropped_paths}
        if not getattr(self, "quiet", False):
            console.print(f"[dim]Verify pass:[/] {kept} confirmed · {dropped} dropped · "
                          f"{unknown} inconclusive [dim](of {len(uniq)}"
                          + (f", {dropped_paths} path(s) removed" if dropped_paths else "") + ")[/]")

    def _dedupe_findings(self, findings):
        """Smart deduplication — collapse redundant/near-identical findings.

        * exact (severity, check, normalised detail) duplicates removed
        * repeated INFO findings with the same check collapsed to one entry
          with a ``(×N)`` count
        * detail normalised (paths/numbers masked) so ``/a/1`` & ``/a/2`` dedupe
        """
        if getattr(self, "no_dedupe", False):
            return findings
        def norm(d):
            d = re.sub(r"\b\d{1,5}\b", "N", d.lower())
            d = re.sub(r"(https?://[^\s)]+)", lambda m: m.group(1).split('?')[0], d)
            d = re.sub(r"\s+", " ", d).strip()
            return d[:200]

        seen = {}
        order = []
        norm_findings = []
        for f in findings:
            # accept both 4-tuples (sev, check, detail, source) and 3-tuples
            if isinstance(f, (list, tuple)) and len(f) >= 4:
                norm_findings.append((f[0], f[1], f[2], f[3]))
            elif isinstance(f, (list, tuple)) and len(f) == 3:
                norm_findings.append((f[0], f[1], f[2], ""))
        for sev, chk, det, src in norm_findings:
            key = (sev, chk.lower().strip(), norm(det))
            if key in seen:
                seen[key][1] += 1
                continue
            seen[key] = [list((sev, chk, det, src)), 1]
            order.append(key)
        out = []
        removed = 0
        for key in order:
            (sev, chk, det, src), count = seen[key]
            if count > 1:
                removed += count - 1
                out.append((sev, chk, f"{det}  (×{count})", src))
            else:
                out.append((sev, chk, det, src))
        if getattr(self, "results", None) is not None:
            self.results['dedupe_stats'] = {"before": len(norm_findings),
                                            "after": len(out), "removed": removed}
        return out

    # ======================================================== AI Patch / Remediation (35)
    PATCH_RULES = [
        # (matcher regex against check/detail, title, remediation markdown)
        (r"(?i)(hsts|strict-transport|missing security header|security header)",
         "Enforce HTTP security headers at the edge",
         "Add the header at your reverse proxy so every route inherits it:\n\n"
         "```nginx\n# nginx — security headers\nadd_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n"
         "add_header X-Content-Type-Options \"nosniff\" always;\n"
         "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
         "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
         "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'self'\" always;\n```\n\n"
         "Cloudflare: **SSL/TLS → Edge Certificates → HSTS** + **Rules → Transform Rules** to inject headers."),
        (r"(?i)(csp|content-security-polic|xss)",
         "Deploy a Content-Security-Policy",
         "Start in report-only, then enforce:\n\n"
         "```\nContent-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report\n```\n"
         "Once reports are clean, drop `-Report-Only` and tighten `script-src` (avoid `unsafe-inline`)."),
        (r"(?i)(cors|access-control-allow-origin)",
         "Restrict CORS to trusted origins",
         "```nginx\n# allow-list instead of reflecting arbitrary Origin\nlocation /api/ {\n"
         "  if ($http_origin ~* \"^https://(app|admin)\\.example\\.com$\") { add_header Access-Control-Allow-Origin $http_origin always; }\n"
         "  add_header Access-Control-Allow-Credentials \"true\" always;\n  add_header Vary \"Origin\" always;\n}\n```\n"
         "Never combine `Access-Control-Allow-Origin: *` with credentials."),
        (r"(?i)(verbose error|stack trace|traceback|debug|info disclosure|phpinfo|actuator)",
         "Disable debug/verbose error output in production",
         "* App: run with `DEBUG=false`, disable framework debug toolbars, set a generic 500 page.\n"
         "* nginx: `fastcgi_intercept_errors on;` + a custom `error_page 500 502 503 504 /500.html;`\n"
         "* Spring: `management.endpoints.web.exposure.include=health` (hide `env`, `heapdump`, `beans`).\n"
         "* PHP: `display_errors=Off`, `expose_php=Off`, remove `phpinfo()`."),
        (r"(?i)(dmarc|spf|dkim|email security|mail auth|mta-sts|bimi|mx\b)",
         "Publish complete email authentication (SPF / DKIM / DMARC)",
         "Publish the DNS records (replace the domain/selector with your own):\n\n"
         "```\n; SPF — authorize only your real senders (keep under 10 DNS lookups)\nyourdomain.com.        TXT  \"v=spf1 mx include:_spf.google.com ~all\"\n\n"
         "; DMARC — start at p=none to collect reports, then move to quarantine/reject\n_dmarc.yourdomain.com.  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1; pct=100\"\n\n"
         "; DKIM — public key published by your mail provider at <selector>._domainkey\ndefault._domainkey.yourdomain.com.  TXT  \"v=DKIM1; k=rsa; p=MIGfMA0GCSq...\"\n\n"
         "; MTA-STS / TLS-RPT (optional but recommended)\n_mta-sts.yourdomain.com.  TXT  \"v=STSv1; id=20260101T000000\"\n_smtp._tls.yourdomain.com. TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com\"\n```\n"
         "* Run with `p=none` + `rua` for a week, read the aggregate reports, then tighten to `p=quarantine` → `p=reject`.\n"
         "* Add `include:` only for providers that actually send mail; one bad `include` can blow the 10-lookup SPF limit."),
        (r"(?i)(secret|api[_ -]?key|token|credential|leak|\.env|private key)",
         "Rotate leaked secrets and remove them from artefacts",
         "1. **Rotate now** — treat any credential exposed to an unauthenticated client as compromised.\n"
         "2. Move secrets to a secret manager (Vault / AWS Secrets Manager / SSM), never in JS or repos.\n"
         "3. Purge from source history (`git filter-repo`) and invalidate old tokens.\n"
         "4. Add a pre-commit secret scanner + CI secret detection."),
        (r"(?i)(swagger|openapi|api doc|postman)",
         "Restrict public API documentation & schema",
         "```nginx\nlocation ~* ^/(swagger|openapi|api-docs) {\n  allow 10.0.0.0/8;\n  deny all;\n}\n```\n"
         "Keep the spec internal (build-time artefact), not served to the public internet."),
        (r"(?i)(admin|backoffice|management|internal api|session-only)",
         "Lock down admin/backend surfaces",
         "* Enforce authn+authz **server-side** on every admin route (not just hidden UI).\n"
         "```nginx\nlocation ^~ /admin/ { allow 10.0.0.0/8; deny all; }\n```\n"
         "* Add MFA + IP allow-listing, and log all admin access.\n"
         "* Cloudflare: **WAF → Custom rules** — block `/admin*` unless from a trusted ASN/IP."),
        (r"(?i)(ssrf|metadata|169\.254|internal pivot|bypass)",
         "Harden against SSRF / internal pivot",
         "* egress allow-list only — block RFC1918 + `169.254.169.254` at the network layer.\n"
         "* Never trust `X-Forwarded-For` / `X-Original-URL` from clients; strip them at the proxy.\n"
         "```nginx\nproxy_set_header X-Forwarded-For $remote_addr;  # not $proxy_add_x_forwarded_for for untrusted edges\n```\n"
         "* IMDSv2 only on AWS; validate all user-supplied URLs against an allow-list."),
        (r"(?i)(tls|ssl|cipher|weak|expired|self-signed|protocol)",
         "Modernise TLS configuration",
         "```nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\n"
         "ssl_prefer_server_ciphers off;\nssl_session_tickets off;\n```\n"
         "* Renew/automate certs (ACME). Cloudflare: **SSL/TLS → Minimum TLS 1.2**, enable **Always Use HTTPS**."),
        (r"(?i)(rate limit|brute|no throttl|429)",
         "Add rate-limiting / anti-automation",
         "```nginx\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\nlocation /api/ { limit_req zone=api burst=20 nodelay; }\n```\n"
         "* Cloudflare: **Security → WAF → Rate limiting rules** per path.\n* Add generic error messages + account lockout/CAPTCHA on auth."),
        (r"(?i)(waf|cdn|cloudflare)",
         "Front the edge with a WAF/CDN",
         "Put the origin behind Cloudflare/AWS WAF: enable managed + OWASP rule sets, "
         "bot management, and hide the origin IP. Lock the origin firewall to the WAF IP ranges only."),
        (r"(?i)(takeover|dangling|cname|subdomain)",
         "Prevent subdomain takeover",
         "Remove or claim every dangling DNS record; audit CNAMEs pointing at deprovisioned "
         "cloud resources (S3, Heroku, GitHub Pages, Azure). Automate a periodic takeover scan in CI."),
        (r"(?i)(cookie|session|jwt|auth)",
         "Harden session / cookie handling",
         "* Cookies: `Secure; HttpOnly; SameSite=Strict` (or `Lax`).\n"
         "* Sessions: short TTL, rotate on login/privilege change, server-side revocation.\n"
         "* JWTs: verify `alg`/`iss`/`aud`, reject `none`, keep secrets out of the token, use short expiry + refresh rotation."),
        (r"(?i)(directory listing|index of|autoindex|\.git|backup|exposed file)",
         "Disable directory listing & remove exposed artefacts",
         "```nginx\nautoindex off;\nlocation ~ /\\.(git|env|svn) { deny all; }\nlocation ~* \\.(bak|old|sql|zip|tar\\.gz)$ { deny all; }\n```\n"
         "* Remove backups/temp files from the web root; deploy from CI, not by hand."),
        (r"(?i)(pathtraversal|path traversal|directory traversal|\.\.)",
         "Normalise and validate paths server-side",
         "Reject input containing traversal sequences, resolve canonical paths, and never concatenate "
         "user input into filesystem paths. Serve user files via IDs mapped to a safe root."),
        (r"(?i)(clickjack|frame)",
         "Prevent clickjacking",
         "```nginx\nadd_header Content-Security-Policy \"frame-ancestors 'self'\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\n```"),
    ]

    def _remediation_for(self, sev, check, detail):
        """Return (title, markdown) remediation guidance for a finding."""
        hay = f"{check} {detail}"
        for pat, title, fix in self.PATCH_RULES:
            if re.search(pat, hay):
                return title, fix
        # severity-aware generic fallback
        if sev in ("CRITICAL", "HIGH"):
            return ("Harden the affected component",
                    "* Restrict access to the affected endpoint (auth/IP/allow-list).\n"
                    "* Remove the exposed data/behaviour or disable the feature until fixed.\n"
                    "* Re-test with the same read-only request after the change.")
        return ("Review and tighten configuration",
                "* Confirm whether the behaviour is intended; if not, restrict it.\n"
                "* Add compensating controls (WAF/rate-limit/headers) and re-test.")

    async def patch_generator(self):
        """Module 35 — AI-style (template + heuristic) patch & remediation generator.

        Read-only: it only *reads* findings collected by other modules and emits
        actionable, copy-paste fixes (nginx / Cloudflare WAF / code-level).
        No network traffic, no AI API key required."""
        findings = self._dedupe_findings(self._collect_findings())
        patches, seen = [], set()
        for sev, check, det, src in findings:
            key = (check.lower(), self._remediation_for(sev, check, det)[0])
            if key in seen:
                continue
            seen.add(key)
            title, fix = self._remediation_for(sev, check, det)
            patches.append({
                "severity": sev, "check": check, "source": src,
                "finding": det, "title": title, "remediation": fix,
                "priority": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3,
                             "LOW": 4, "INFO": 5}.get(sev, 5),
            })
        patches.sort(key=lambda p: p["priority"])
        self.results['patch'] = {
            "generated": len(patches), "patches": patches[:200],
            "categories": sorted({p["title"] for p in patches}),
            "note": "Template/heuristic remediation (offline) — adapt to your stack and re-test read-only.",
        }

    # ======================================================== Read-Only PoC (36)
    def _poc_commands_for(self, sev, check, detail):
        """Build strictly non-destructive verification commands for a finding."""
        base = self.base_url.rstrip('/')
        host = self.domain
        c = f"{check} {detail}".lower()
        cmds = []
        if re.search(r"(?i)header|hsts|csp|cors|security", c):
            cmds.append({"desc": "Inspect response headers (read-only)",
                         "cmd": f"curl -sSI {base}/ | grep -iE 'strict-transport|content-security|x-frame|access-control'"})
        if re.search(r"(?i)cors|access-control-allow-origin", c):
            # echo-probe: server only reflects the Origin header — no request is altered, nothing is written
            cmds.append({"desc": "Check whether CORS reflects an arbitrary Origin (read-only echo probe)",
                         "cmd": f"curl -sSI -H 'Origin: https://evil.example' {base}/ "
                                f"| grep -i 'access-control-allow-origin'"})
            cmds.append({"desc": "Confirm preflight behaviour (OPTIONS, no body)",
                         "cmd": f"curl -sS -o /dev/null -D - -X OPTIONS "
                                f"-H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' {base}/ "
                                f"| grep -iE 'access-control|HTTP/'"})
        if re.search(r"(?i)actuator|heapdump|spring", c):
            cmds.append({"desc": "HEAD the Spring actuator endpoints (presence only — no download)",
                         "cmd": f"for ep in heapdump env beans mappings; do "
                                f"curl -sSI {base}/actuator/$ep | head -1; done"})
        if re.search(r"(?i)\bport\b|open port|listening", c):
            m = re.search(r"(?:port[:\s#]*)(\d{1,5})", detail, re.I) or re.search(r"\b(\d{2,5})\b", detail)
            if m:
                cmds.append({"desc": f"Confirm TCP port {m.group(1)} is open (connect only)",
                             "cmd": f"curl -sS --connect-timeout 3 telnet://{host}:{m.group(1)} </dev/null || "
                                    f"nc -z -w3 {host} {m.group(1)} && echo open"})
        if re.search(r"(?i)path|admin|swagger|api|endpoint|directory|expos", c):
            m = re.search(r"(/[A-Za-z0-9_\-./?=&%]+)", detail)
            p = m.group(1) if m else "/"
            cmds.append({"desc": "HEAD the endpoint (no body, no side-effects)",
                         "cmd": f"curl -sSI {base}{p}"})
            cmds.append({"desc": "Fetch status only (GET, headers suppressed)",
                         "cmd": f"curl -sS -o /dev/null -w '%{{http_code}}\\n' {base}{p}"})
        if re.search(r"(?i)subdomain|dns|cname|takeover|mx|spf|dmarc", c):
            m = re.search(r"([A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+)", detail)
            sub = m.group(1) if m else host
            cmds.append({"desc": f"Resolve A/CNAME for {sub}",
                         "cmd": f"dig +short A {sub}; dig +short CNAME {sub}"})
            cmds.append({"desc": "Check SPF/DMARC posture",
                         "cmd": f"dig +short TXT {host} | grep -i spf; dig +short TXT _dmarc.{host}"})
        if re.search(r"(?i)tls|ssl|cipher|cert|expired", c):
            cmds.append({"desc": "Read the certificate & negotiated protocol (no handshake data sent)",
                         "cmd": f"echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null "
                                f"| openssl x509 -noout -subject -issuer -dates"})
        if re.search(r"(?i)robots|sitemap", c):
            cmds.append({"desc": "Fetch robots/sitemap policy",
                         "cmd": f"curl -sS {base}/robots.txt; curl -sS {base}/sitemap.xml | head -c 2000"})
        if not cmds:
            cmds.append({"desc": "Neutral connectivity + status probe",
                         "cmd": f"curl -sSI {base}/"})
        return cmds[:5]

    async def poc_generator(self):
        """Module 36 — read-only PoC verification generator.

        Emits benign, reproducible commands (curl/dig/openssl/nc) that *show a
        finding exists* without sending any exploit payload or mutating state."""
        findings = self._dedupe_findings(self._collect_findings())
        pocs = []
        for sev, check, det, src in findings:
            if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
                continue
            pocs.append({
                "severity": sev, "check": check, "source": src, "finding": det,
                "commands": self._poc_commands_for(sev, check, det),
            })
        self.results['poc'] = {
            "generated": len(pocs), "pocs": pocs[:200],
            "policy": "Read-only verification only — HEAD/GET/OPTIONS/dig/openssl; no payloads, no writes, no brute-force.",
        }

    # ======================================================== Webhook Notify (37)
    def _alert_severity_counts(self, report):
        """Count severities across the whole report (for alert severity)."""
        F = self._collect_findings_from_report(report)
        return {k: len([f for f in F if f[0] == k])
                for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    def _notification_payload(self, report):
        s = report.get("summary", {})
        diff = report.get("scan_diff", {}) or {}
        sev = self._alert_severity_counts(report)
        crit, high = sev["CRITICAL"], sev["HIGH"]
        if crit:
            head = f"🚨 *NULLVEIL CRITICAL ALERT* 🚨 — `{report.get('target', '')}`"
        elif high:
            head = f"⚠️ *NULLVEIL HIGH-RISK ALERT* — `{report.get('target', '')}`"
        else:
            head = f"🔔 *NULLVEIL Recon complete* — `{report.get('target', '')}`"
        lines = [
            head,
            f"version {report.get('version', '')} · mode {report.get('mode', '')} · {report.get('duration_s', 0)}s",
            "",
            f"• Severity: 🔴 {crit} critical · 🟠 {high} high · 🟡 {sev['MEDIUM']} medium · 🔵 {sev['LOW']} low",
            f"• Subdomains: {s.get('subdomains', 0)}  • Open ports: {s.get('open_ports', 0)}",
            f"• Secrets: {s.get('secrets', 0)}  • API endpoints: {s.get('api_endpoints', 0)}",
            f"• CVE issues: {s.get('cve_issues', 0)}  • Admin-API: {s.get('admin_api_findings', 0)}",
            f"• New since last scan: {s.get('diff_new_assets', 0)} (score {s.get('diff_score', 0)}/100)",
        ]
        if diff.get("available"):
            lines.append(f"• Change verdict: {diff.get('verdict', '')}")
        # surface the single most severe finding (redacted detail)
        F = self._collect_findings_from_report(report)
        if F and F[0][0] in ("CRITICAL", "HIGH"):
            lines += ["", f"Top risk — *{F[0][1]}*: {F[0][2][:180]}"]
        lines += ["", "_Counts only — no secret values included._"]
        return "\n".join(lines)

    @staticmethod
    def _md_escape(t):
        """Escape text for Telegram MarkdownV2."""
        return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", str(t))

    async def webhook_notify(self):
        """Module 37 — push an instant scan alert to Slack/Telegram/Discord/Teams.

        Fires as soon as the scan finishes (module runs at the end of the pipeline).
        Uses httpx (already a dependency). Graceful when nothing is configured or a
        channel rejects the message. Alert content is **counts + the target name
        only** — secret values are never included. A CRITICAL/HIGH finding changes
        the alert headline and Telegram parse mode is crash-safe (MarkdownV2)."""
        cfg = dict(getattr(self, "webhooks", {}) or {})
        targets = {k: v for k, v in cfg.items() if v}
        out = {"channels": sorted(targets.keys()), "sent": [], "failed": [],
               "note": "", "severity": {}}
        if not targets:
            out["note"] = ("no webhook configured — pass --webhook-slack / --webhook-telegram "
                           "(TOKEN:CHATID) / --webhook-discord / --webhook-teams")
            self.results['notify'] = out
            return

        report = self.export_dict()
        plain = self._notification_payload(report)
        out["severity"] = self._alert_severity_counts(report)

        async def _send(name, url, payload):
            try:
                async with self.sem:
                    r = await self.client.post(url, json=payload, timeout=10,
                                               follow_redirects=True)
                if 200 <= r.status_code < 300:
                    out["sent"].append({"channel": name, "status": r.status_code})
                else:
                    out["failed"].append({"channel": name, "status": r.status_code,
                                          "body": (r.text or "")[:200]})
            except Exception as e:
                out["failed"].append({"channel": name, "error": f"{type(e).__name__}: {e}"})

        for name, url in targets.items():
            if name == "slack":
                await _send(name, url, {"text": plain})
            elif name == "discord":
                await _send(name, url, {"content": plain[:1900]})
            elif name == "teams":
                await _send(name, url, {"text": plain})
            elif name == "telegram":
                # url format: TOKEN:CHATID  (chat id may be negative, e.g. -100123…)
                if ":" in url:
                    token, chat = url.split(":", 1)
                    api = f"https://api.telegram.org/bot{token}/sendMessage"
                    # MarkdownV2 needs escaping; fall back to plain text if it still fails
                    md = self._md_escape(plain)
                    ok = await self._tg_send(name, api, chat, md, out)
                    if not ok:
                        await self._tg_send(name, api, chat, plain, out, plain_mode=True)
                else:
                    out["failed"].append({"channel": name,
                                          "error": "expected TOKEN:CHATID"})
        self.results['notify'] = out

    async def _tg_send(self, name, api, chat, text, out, plain_mode=False):
        """Send one Telegram message; return True on success (and record result)."""
        payload = {"chat_id": chat, "text": text[:4000],
                   "disable_web_page_preview": True}
        if not plain_mode:
            payload["parse_mode"] = "MarkdownV2"
        try:
            async with self.sem:
                r = await self.client.post(api, json=payload, timeout=10,
                                           follow_redirects=True)
            if 200 <= r.status_code < 300:
                out["sent"].append({"channel": name, "status": r.status_code})
                return True
            # record only the final failure (avoid duplicate entries on retry)
            if plain_mode:
                out["failed"].append({"channel": name, "status": r.status_code,
                                      "body": (r.text or "")[:200]})
            return False
        except Exception as e:
            if plain_mode:
                out["failed"].append({"channel": name,
                                      "error": f"{type(e).__name__}: {e}"})
            return False

    # ======================================================== Executive report (39)
    def _collect_findings_from_report(self, report):
        """Rebuild ``[(sev, check, detail, source), ...]`` from an exported report
        dict (used when rendering the executive report/dashboard PDF from a saved
        history entry, where ``self.results`` is not populated)."""
        r = (report or {}).get("report", report) or {}
        F = []

        def add(sev, chk, det, src):
            det = re.sub(r"\s+", " ", str(det or "")).strip()[:400]
            F.append((str(sev or "INFO").upper(), str(chk or ""), det, src))

        # dict sections that carry a "findings" list of {severity, message|detail, ...}
        for key, src in (("email_security", "email"), ("external_intel", "ext"),
                         ("cve", "cve"), ("tls", "tls"), ("supply_chain", "supply"),
                         ("breach", "breach"), ("scan_diff", "diff"),
                         ("admin_api", "auth"), ("burp_caido", "burp"),
                         ("nuclei", "nuclei"), ("threat_intel", "intel"),
                         ("correlation", "correlate"), ("compliance", "comp"),
                         ("anomaly", "anomaly"), ("js_secret", "jssecret"),
                         ("wayback", "wayback"), ("params", "param"),
                         ("graphql", "gql"), ("cloud_storage", "cloud"),
                         ("cvss", "cvss"), ("mitre_attack", "attack"),
                         ("cve_intel", "cveintel"), ("takeover_v3", "takeover"),
                         ("watch", "watch")):
            blob = r.get(key)
            if not isinstance(blob, dict):
                continue
            for f in (blob.get("findings") or []):
                if isinstance(f, dict):
                    add(f.get("severity"), f.get("id") or f.get("check") or f.get("title") or src,
                        f.get("detail") or f.get("message") or f.get("desc") or "", src)
                elif isinstance(f, (list, tuple)) and len(f) >= 3:
                    add(f[0], f[1], f[2], src)
                elif isinstance(f, (list, tuple)) and len(f) == 2:
                    add(f[0], src, f[1], src)
        F.sort(key=lambda t: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                              "LOW": 3, "INFO": 4}.get(t[0], 5))
        return F

    def _exec_metrics(self, report):
        s = report.get("summary", {})
        live = self._collect_findings() if getattr(self, "results", None) else []
        if not live:
            live = self._collect_findings_from_report(report)
        F = self._dedupe_findings(live)
        # Zero-noise policy: executive shows only actionable findings
        actionable = []
        for f in F:
            try:
                sev = f[0]
                chk = str(f[1] or "").lower()
                det = str(f[2] or "").lower()
                if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                    actionable.append(f)
                    continue
                if sev == "LOW" and any(x in chk or x in det for x in ["exposed", "missing", "misconfig", "weak", "takeover", "dangling", "cookie", "session", "cors"]):
                    actionable.append(f)
                    continue
            except Exception:
                continue
        F_exec = actionable if actionable else [f for f in F if f[0] != "INFO"]
        sev_count = {k: len([f for f in F_exec if f[0] == k])
                     for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        crit, high, med = sev_count["CRITICAL"], sev_count["HIGH"], sev_count["MEDIUM"]
        score = min(100, crit * 20 + high * 9 + med * 4 + (s.get("secrets", 0) or 0) * 8
                    + (s.get("takeover_risks", 0) or 0) * 15)
        verdict = ("CRITICAL EXPOSURE" if score >= 70 else "HIGH EXPOSURE" if score >= 40
                   else "MODERATE EXPOSURE" if score >= 15 else "LOW RISK")
        comp = report.get("compliance", {}) or {}
        return {
            "score": score, "verdict": verdict, "sev": sev_count,
            "findings": F_exec,
            "top_risks": [f for f in F_exec if f[0] in ("CRITICAL", "HIGH")][:12],
            "compliance": {"coverage_pct": comp.get("coverage_pct", 0),
                           "total_fail": comp.get("total_fail", 0),
                           "total_controls": comp.get("total_controls", 0),
                           "frameworks": comp.get("frameworks", {}),
                           "disclaimer": comp.get("disclaimer", "Indicative Technical Control Mapping — not a certification/compliance attestation")},
            "kpis": {
                "subdomains": s.get("subdomains", 0), "open_ports": s.get("open_ports", 0),
                "secrets": s.get("secrets", 0), "api_endpoints": s.get("api_endpoints", 0),
                "cve_issues": s.get("cve_issues", 0), "takeover_risks": s.get("takeover_risks", 0),
                "admin_api_findings": s.get("admin_api_findings", 0),
                "new_since_last_scan": s.get("diff_new_assets", 0),
            },
        }

    def build_executive_html(self, report):
        """Standalone, print-ready executive (C-level) HTML report."""
        from html import escape as _e
        m = self._exec_metrics(report)
        tgt = _e(str(report.get("target", "")))
        when = _e(str(report.get("started", ""))[:19].replace("T", " "))
        col = "#ef4444" if m["score"] >= 70 else "#f97316" if m["score"] >= 40 else "#eab308" if m["score"] >= 15 else "#22c55e"
        kr = "".join(f"<div class='kpi'><div class='kv'>{_e(str(v))}</div><div class='kl'>{_e(k)}</div></div>"
                     for k, v in m["kpis"].items())
        risks = "".join(
            f"<tr><td><span class='chip' style='background:{'#ef4444' if s=='CRITICAL' else '#f97316'}'>{_e(s)}</span></td>"
            f"<td><b>{_e(c)}</b><div class='det'>{_e(d)}</div></td></tr>"
            for s, c, d, _src in m["top_risks"]) or "<tr><td colspan='2'>No high-severity findings 🎉</td></tr>"
        prio = "".join(
            f"<li><b>{_e(p['title'])}</b> <span class='chip b'>{_e(p['severity'])}</span>"
            f"<div class='det'>{_e(p['check'])} — {_e(p['finding'][:160])}</div></li>"
            for p in (((getattr(self, "results", None) or {}).get('patch', {}) or {}).get('patches', [])[:10]))
        comp = m["compliance"]
        fw = "".join(f"<tr><td>{_e(k)}</td><td>{_e(str(v))}</td></tr>"
                     for k, v in (comp.get("frameworks") or {}).items()) or \
             "<tr><td colspan='2'>Compliance module not run (−a comp)</td></tr>"
        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NULLVEIL Executive Report — {tgt}</title>
<style>
 :root{{--line:#e5e7eb;--mut:#6b7280}}
 *{{box-sizing:border-box}} body{{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:#111827;margin:0;background:#f8fafc}}
 .wrap{{max-width:980px;margin:0 auto;padding:40px 28px}}
 header{{border-bottom:3px solid {col};padding-bottom:16px;margin-bottom:24px}}
 h1{{margin:0;font-size:26px}} h2{{font-size:18px;margin:28px 0 10px;border-left:4px solid {col};padding-left:10px}}
 .sub{{color:var(--mut);font-size:13px;margin-top:6px}}
 .meter{{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}}
 .score{{font-size:44px;font-weight:800;color:{col}}} .verdict{{font-weight:700;color:{col};margin-top:4px}}
 .track{{height:12px;background:#eef2f7;border-radius:8px;overflow:hidden;margin-top:12px}}
 .track i{{display:block;height:100%;width:{m['score']}%;background:{col}}}
 .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}}
 .kpi{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px;text-align:center}}
 .kv{{font-size:24px;font-weight:800}} .kl{{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}}
 table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}}
 .chip{{color:#fff;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}} .chip.b{{background:#6b7280}}
 .det{{color:var(--mut);font-size:12px}} ul{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 18px 14px 34px}}
 li{{margin:8px 0}} footer{{color:var(--mut);font-size:12px;margin-top:30px;border-top:1px solid var(--line);padding-top:12px}}
 @media print{{body{{background:#fff}} .wrap{{padding:0}}}}
</style></head><body><div class="wrap">
<header><h1>Executive Security Report</h1>
<div class="sub">Target <b>{tgt}</b> · {when} · NULLVEIL Recon v{_e(str(report.get('version','')))}</div></header>
<div class="meter"><div class="score">{m['score']}/100</div><div class="verdict">{_e(m['verdict'])}</div>
<div class="track"><i></i></div>
<p style="margin:14px 0 0;color:var(--mut)">Severity mix — CRITICAL {m['sev']['CRITICAL']} · HIGH {m['sev']['HIGH']} · MEDIUM {m['sev']['MEDIUM']} · LOW {m['sev']['LOW']} · INFO {m['sev']['INFO']}</p></div>
<div class="kpis">{kr}</div>
<h2>Top Risks</h2><table><tbody>{risks}</tbody></table>
<h2>Compliance Snapshot</h2>
<table><tbody><tr><th>Framework / metric</th><th>Value</th></tr>
<tr><td>Overall coverage</td><td>{_e(str(comp.get('coverage_pct', 0)))}% ({_e(str(comp.get('total_fail', 0)))} failing controls of {_e(str(comp.get('total_controls', 0)))})</td></tr>
{fw}</tbody></table>
<h2>Prioritised Remediation</h2><ul>{prio or '<li>No remediation items generated.</li>'}</ul>
<footer>Generated by NULLVEIL Recon · Owner NULLVEIL · Engine DeepHat · Evidence-based, read-only assessment — not a certification. Use only on authorized targets.</footer>
</div></body></html>"""

    def export_executive_html(self, report, path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.build_executive_html(report))
        return path

    def export_executive_pdf(self, report, path):
        """Best-effort executive PDF: weasyprint → reportlab → playwright → skip."""
        html_doc = self.build_executive_html(report)
        # 1) weasyprint (pure-python HTML→PDF)
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html_doc).write_pdf(path)
            return path, "weasyprint"
        except Exception:
            pass
        # 2) reportlab (rendered from structured metrics)
        try:
            from reportlab.lib.pagesizes import A4  # type: ignore
            from reportlab.pdfgen import canvas  # type: ignore
            m = self._exec_metrics(report)
            c = canvas.Canvas(path, pagesize=A4)
            w, h = A4
            y = h - 60
            c.setFont("Helvetica-Bold", 18)
            c.drawString(50, y, "NULLVEIL Executive Security Report")
            y -= 26
            c.setFont("Helvetica", 11)
            c.drawString(50, y, f"Target: {report.get('target','')}   v{report.get('version','')}")
            y -= 20
            c.setFont("Helvetica-Bold", 24)
            c.drawString(50, y, f"{m['score']}/100  -  {m['verdict']}")
            y -= 34
            c.setFont("Helvetica", 11)
            c.drawString(50, y, f"CRITICAL {m['sev']['CRITICAL']}  HIGH {m['sev']['HIGH']}  "
                                f"MEDIUM {m['sev']['MEDIUM']}  LOW {m['sev']['LOW']}")
            y -= 28
            c.setFont("Helvetica-Bold", 13)
            c.drawString(50, y, "Top Risks")
            y -= 18
            c.setFont("Helvetica", 10)
            for s, ck, d, _src in m["top_risks"][:14]:
                for line in _wrap(f"[{s}] {ck}: {d}", 95):
                    if y < 60:
                        c.showPage(); y = h - 60; c.setFont("Helvetica", 10)
                    c.drawString(50, y, line); y -= 14
            c.save()
            return path, "reportlab"
        except Exception:
            pass
        # 3) playwright chromium (already optional in the project)
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
            with sync_playwright() as p:
                b = p.chromium.launch()
                pg = b.new_page()
                pg.set_content(html_doc, wait_until="load")
                pg.pdf(path=path, format="A4", print_background=True)
                b.close()
            return path, "playwright"
        except Exception:
            pass
        return None, "unavailable"

    async def executive_report(self):
        """Module 39 — executive C-level HTML (+PDF) report exporter.

        Reads the final report and writes a print-ready HTML file; the PDF is a
        best-effort extras (weasyprint/reportlab/playwright) and degrades quietly."""
        # report is built later; we snapshot current results into a report dict
        report = self.export_dict()
        html_path = getattr(self, "exec_report_path", "") or os.path.join(
            os.getcwd(), f"nullveil-exec-{self.domain}.html")
        try:
            self.export_executive_html(report, html_path)
        except Exception as e:
            self.results['errors'].append(f"exec report: {e!r}")
            self.results['exec'] = {"html": "", "pdf": "", "error": repr(e)}
            return
        pdf_path, engine = "", ""
        want_pdf = getattr(self, "exec_pdf_path", "")
        if want_pdf:
            pdf_path, engine = self.export_executive_pdf(report, want_pdf)
        m = self._exec_metrics(report)
        self.results['exec'] = {
            "html": html_path, "pdf": pdf_path or "", "pdf_engine": engine,
            "score": m["score"], "verdict": m["verdict"], "sev": m["sev"],
            "kpis": m["kpis"], "compliance": m["compliance"],
        }

    # ======================================================== SSRF / Internal Pivot (32)
    SSRF_BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"Client-IP": "10.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Host": "localhost"},
        {"Forwarded": "for=127.0.0.1;host=localhost;proto=http"},
        {"X-Internal-API": "true"},
        {"X-Backend-Host": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
         "X-Internal-API": "true"},
    ]
    SSRF_METADATA_PATHS = [
        "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data", "/computeMetadata/v1/",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/metadata/instance", "/metadata/instance?api-version=2021-02-01",
        "/metadata/v1/", "/machine-metadata/", "/openstack/latest/meta_data.json",
    ]
    SSRF_METADATA_SIG = re.compile(
        r"(?i)(ami-[0-9a-f]{8,}|instance-id|computeengine|projects/\d+/|token_type"
        r"|security-credentials|meta-data|iam/security|\"access_token\")")

    async def ssrf_probe(self):
        """Internal-pivot recon: (1) IP-bypass header fuzz vs baseline, (2) cloud
        metadata path probing with provider headers, (3) optional interactsh
        out-of-band SSRF callbacks (--oob, needs interactsh-client binary)."""
        eps, seen = [], set()
        for e in (self.results.get('api_pool') or []):
            p = str((e or {}).get('path', ''))
            if p.startswith('/') and p not in seen:
                seen.add(p)
                eps.append(p)
        for p in (self.results.get('api_endpoints') or []):
            path = str(p.get('path', '') if isinstance(p, dict) else p)
            if path.startswith('/') and path not in seen:
                seen.add(path)
                eps.append(path)
        for p in (self.results.get('api_endpoints_found') or []):
            path = str(p)
            if path.startswith('/') and path not in seen:
                seen.add(path)
                eps.append(path)
        if not eps:
            eps = ['/']
        eps = eps[: (25 if self.deep else 12)]

        def _abs(p):
            return p if p.startswith('http') else self.base_url.rstrip('/') + p

        # ---- 1) internal bypass header fuzzing (baseline vs injected) ----
        bypass_hits = []
        for p in eps:
            url = _abs(p)
            try:
                async with self.sem:
                    base = await self.client.get(url)
                b_status, b_len = base.status_code, len(base.content)
            except Exception:
                continue
            for hb in self.SSRF_BYPASS_HEADERS:
                try:
                    async with self.sem:
                        r = await self.client.get(url, headers=hb)
                except Exception:
                    continue
                d_len = len(r.content) - b_len
                if r.status_code != b_status or abs(d_len) > max(250, int(b_len * 0.2)):
                    bypass_hits.append({
                        "path": p,
                        "header": "; ".join(f"{k}: {v}" for k, v in hb.items()),
                        "baseline_status": b_status, "status": r.status_code,
                        "size_delta": d_len,
                        "verdict": ("possible ACL/IP bypass" if r.status_code != b_status
                                    else "response variance"),
                    })

        # ---- 2) cloud metadata probing (metadata-proxy exposure) ----
        meta_hits = []
        meta_header_sets = [{}, {"Metadata-Flavor": "Google"},
                            {"Metadata": "true"},
                            {"Metadata-Flavor": "Google", "Metadata": "true"}]
        for mp in self.SSRF_METADATA_PATHS:
            for mh in meta_header_sets:
                try:
                    async with self.sem:
                        r = await self.client.get(self.base_url.rstrip('/') + mp,
                                                  headers=mh)
                except Exception:
                    continue
                ctype = (r.headers.get('content-type') or '').lower()
                sig = bool(self.SSRF_METADATA_SIG.search((r.text or '')[:8000]))
                if sig or (r.status_code == 200 and 'html' not in ctype):
                    meta_hits.append({
                        "path": mp, "status": r.status_code,
                        "header": "; ".join(f"{k}: {v}" for k, v in mh.items()) or "-",
                        "signature": sig, "size": len(r.content),
                    })

        # ---- 3) out-of-band SSRF callbacks (interactsh) ----
        oob = {"enabled": False, "domain": "", "injected": 0,
               "hits": [], "note": "disabled — pass --oob to enable"}
        oob_cfg = getattr(self, "oob_cfg", {}) or {}
        if oob_cfg.get("enabled"):
            import shutil as _shutil
            exe = _shutil.which("interactsh-client")
            if not exe:
                oob["note"] = ("interactsh-client not found — install: go install "
                               "github.com/projectdiscovery/interactsh/cmd/"
                               "interactsh-client@latest")
                self.results['errors'].append(f"ssrf: {oob['note']}")
            else:
                oob["enabled"] = True
                oob_proc = None

                async def _read(tmo):
                    """b'' = EOF, None = timeout (keep polling)."""
                    try:
                        return await asyncio.wait_for(oob_proc.stdout.readline(),
                                                      timeout=tmo)
                    except asyncio.TimeoutError:
                        return None

                try:
                    argv = [exe, "-json"]
                    if oob_cfg.get("server"):
                        argv += ["-s", str(oob_cfg["server"])]
                    oob_proc = await asyncio.create_subprocess_exec(
                        *argv, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL)
                    # registration line -> correlation domain
                    domain = None
                    for _ in range(12):
                        line = await _read(15)
                        if line in (b"", None) and domain:
                            break
                        if not line:
                            if line == b"":
                                break
                            continue
                        txt = line.decode("utf-8", "replace")
                        if txt.lstrip().startswith("{"):
                            continue
                        m = re.search(r"([a-z0-9]{8,64}\.[a-z0-9-]+\.[a-z]{2,})", txt)
                        if m:
                            domain = m.group(1)
                            break
                    if not domain:
                        oob["note"] = "could not parse OOB domain from interactsh-client"
                    else:
                        oob["domain"] = domain
                        oob_url = f"http://{domain}/nullveil-oob"
                        targets = []
                        for p in eps:
                            u = _abs(p)
                            if "?" in u:
                                targets.append(re.sub(r"=[^&]*", "=" + oob_url, u))
                            else:
                                for pn in ("url", "path", "dest", "callback", "webhook",
                                           "next", "img", "file", "target", "proxy",
                                           "redirect", "feed", "host"):
                                    targets.append(f"{u}{'&' if '?' in u else '?'}"
                                                   f"{pn}={oob_url}")
                        targets = list(dict.fromkeys(targets))[: (45 if self.deep else 25)]
                        for t in targets:
                            try:
                                async with self.sem:
                                    await self.client.get(t)
                            except Exception:
                                continue
                        oob["injected"] = len(targets)
                        # poll for interactions
                        wait_s = int(oob_cfg.get("wait") or (90 if self.deep else 45))
                        deadline = time.time() + wait_s
                        while time.time() < deadline:
                            line = await _read(min(10, max(1, deadline - time.time())))
                            if line is None:
                                continue
                            if line == b"":
                                break
                            txt = line.decode("utf-8", "replace").strip()
                            if txt and (txt.startswith("{")
                                        or domain.split(".")[0][:8] in txt):
                                oob["hits"].append(txt[:400])
                                if len(oob["hits"]) >= 50:
                                    break
                        if oob["hits"]:
                            oob["note"] = (f"{len(oob['hits'])} out-of-band interaction(s) "
                                           f"received — SSRF/OOB callback confirmed")
                        else:
                            oob["note"] = (f"no interactions within {wait_s}s after "
                                           f"{oob['injected']} injected probe(s)")
                except Exception as e:
                    oob["note"] = f"interactsh failed: {type(e).__name__} — {e}"
                    self.results['errors'].append(f"ssrf: {oob['note']}")
                finally:
                    if oob_proc:
                        try:
                            oob_proc.kill()
                        except Exception:
                            pass

        for h in bypass_hits[:80]:
            if h["verdict"].startswith("possible"):
                self.results['api_pool'].append(
                    {"path": h["path"], "source": "ssrf:bypass"})
        self.results['ssrf'] = {
            "available": True, "endpoints": len(eps),
            "bypass_count": len(bypass_hits),
            "bypass": bypass_hits[:120],
            "metadata": meta_hits, "oob": oob,
        }

    # ======================================================== Smart Context Fuzz (33)
    BUSINESS_NOUNS = {
        "ecommerce": ["cart", "checkout", "order", "orders", "payment", "payments",
                      "invoice", "refund", "coupon", "sku", "wishlist", "shipment",
                      "tracking", "catalog", "inventory", "stock", "address", "review"],
        "fintech": ["transaction", "transactions", "transfer", "balance", "ledger",
                    "upi", "kyc", "mandate", "payout", "settlement", "wallet",
                    "beneficiary", "statement", "card", "loan", "credit"],
        "saas": ["tenant", "workspace", "subscription", "plan", "billing", "seat",
                 "invite", "webhook", "integration", "usage", "quota", "sso",
                 "organization", "deployment"],
        "blog": ["post", "posts", "author", "authors", "comment", "comments",
                 "category", "categories", "tag", "tags", "draft", "publish"],
        "health": ["patient", "appointment", "prescription", "record", "vitals",
                   "insurance", "claim", "doctor", "clinic", "booking"],
        "edu": ["student", "course", "enrollment", "grade", "assignment", "exam",
                "class", "teacher"],
        "travel": ["booking", "itinerary", "pnr", "flight", "hotel", "seatmap",
                   "fare", "voucher"],
        "social": ["feed", "story", "follower", "following", "message", "thread",
                   "mention", "group"],
    }
    CTX_MODIFIERS = ["", "api/", "api/v1/", "api/v2/", "internal/", "private/",
                     "admin/", "mobile/", "v2/", "v3/"]
    CTX_SUFFIXES = ["", "/internal", "/v2", "/bulk", "/export", "/search",
                    "/stats", "/config"]
    STATIC_EXT_RE = re.compile(
        r"(?i)\.(png|jpe?g|gif|svg|css|ico|woff2?|ttf|mp4|map|pdf)(\?|$)")

    # --- read-only vulnerability verification (module 50) ---
    # Benign SQL error signatures — used to DETECT that input reaches a query
    # layer, never to extract data. Matched against a response body that also
    # contains our unique marker, so a pre-existing error page cannot match.
    SQL_ERROR_SIGS = re.compile(
        r"(?i)(you have an error in your sql syntax|warning:\s*mysql_|"
        r"unclosed quotation mark after the character string|"
        r"quoted string not properly terminated|pg_query\(\)|psql:|"
        r"microsoft ole db provider for sql server|odbc sql server driver|"
        r"sqlite3?:?\s*(error|operationalerror)|"
        r"ora-\d{4,5}|postgresql.*error|syntax error at or near|"
        r"jdbc.*sqlexception|sqlexception|sqlstate\[)")
    # TLS/SSL + template injection are NOT probed — only reflective output,
    # SQL error/boolean signatures and path-traversal reachability.
    XSS_MARKER = "nvx9zq7"
    XSS_PROBE = 'nvx9zq7"<b>'   # benign: alphanumeric marker + a quote/bracket pair.
    #   If reflected RAW the bracket survives; if the app HTML-escapes output the
    #   bracket becomes an entity — that difference is the sink proof. No script,
    #   no event handler, no executable payload is ever sent.
    SQL_MARKER = "nvq9z7"
    TRAVERSAL_PROBES = [
        ("/etc/passwd", re.compile(r"(?m)^root:.*:0:0:")),
        ("/windows/win.ini", re.compile(r"(?i)\[fonts\]|\[extensions\]")),
        ("....//....//....//etc/passwd", re.compile(r"(?m)^root:.*:0:0:")),
        ("..%2f..%2f..%2fetc%2fpasswd", re.compile(r"(?m)^root:.*:0:0:")),
        ("/proc/self/environ", re.compile(r"(?i)\bPATH=|HTTP_USER_AGENT=")),
    ]

    def _param_targets(self):
        """Collect (url, param, method) candidates from the discovered surface."""
        out, seen = [], set()
        # explicit hidden-param inventory (module 42) first — highest confidence
        for entry in (self.results.get('param', {}) or {}).get('params', []) or []:
            if isinstance(entry, dict):
                url = entry.get('url') or entry.get('path') or ''
                for p in (entry.get('params') or []):
                    key = (url, p)
                    if url and key not in seen:
                        seen.add(key)
                        out.append((url, p, entry.get('method', 'GET')))
        # then any endpoint in the pool that already carries a query string
        for entry in (self.results.get('api_pool') or []):
            u = entry.get('url') if isinstance(entry, dict) else str(entry)
            if not u or '?' not in u:
                continue
            base, _, qs = u.partition('?')
            for pair in qs.split('&'):
                if '=' in pair:
                    p = pair.split('=', 1)[0]
                    key = (base, p)
                    if p and key not in seen:
                        seen.add(key)
                        out.append((base, p, 'GET'))
        # common reflective params as a last resort against the homepage
        if not out:
            for p in ('q', 's', 'search', 'id', 'page', 'redirect', 'url', 'file', 'path'):
                out.append((self.base_url.rstrip('/') + '/', p, 'GET'))
        return out

    async def vuln_verify(self):
        """Read-only vulnerability verification (module 50).

        Proves *reachability* of a vulnerability class without ever exploiting
        it or extracting data:

        * **Reflected XSS sink** — a unique benign marker is placed in a
          parameter; if it is echoed back **unencoded** into an HTML context
          (raw marker present, not HTML-entity-escaped) the parameter reaches a
          sink. No script tag, no payload — the marker is alphanumeric only.
        * **SQL injection surface** — a benign marker plus a single quote is
          sent; if the response contains BOTH the marker AND a recognised
          database error string, the parameter reaches a query layer. No data
          is read; the marker prevents a pre-existing error page matching.
        * **Path traversal reach** — traversal sequences are appended to file
          parameters; a hit is only reported when the body matches a known
          system-file signature (``root:…:0:0:`` / ``[fonts]``), proven with a
          control request that does NOT contain the sequence.

        Everything is GET/POST with benign markers, rate-limited by the shared
        semaphore, and skipped entirely if the scan already runs authenticated
        (to avoid touching user data).
        """
        targets = self._param_targets()
        cap = 40 if self.deep else 20
        targets = targets[:cap]
        xss, sqli, traversal = [], [], []
        tested = 0
        if not targets:
            self.results['vuln_verify'] = {"tested": 0, "xss": [], "sqli": [],
                                           "traversal": [], "note": "no parameters discovered"}
            return

        async def _get(url):
            async with self.sem:
                return await self.client.get(url, timeout=min(self.timeout, 12))

        for url, param, method in targets:
            sep = '&' if '?' in url else '?'
            base_url = f"{url}{sep}{param}="
            try:
                # control: the parameter set to an inert value, to isolate variance
                ctrl = await _get(base_url + "1")
                ctrl_body = (ctrl.text or '')[:200_000]
            except Exception:
                continue
            tested += 1

            # ---------- 1) reflected XSS sink (unencoded echo of marker) ----------
            try:
                r = await _get(base_url + quote(self.XSS_PROBE, safe=""))
                body = (r.text or '')[:200_000]
                # The marker must appear; its RAW bracket form means the value
                # reached an HTML sink unencoded. If only the escaped entity is
                # present the output is safely encoded -> NOT reported.
                raw = self.XSS_PROBE in body
                if raw and self.XSS_PROBE not in ctrl_body:
                    idx = body.find(self.XSS_PROBE)
                    ctx = body[max(0, idx - 40):idx + len(self.XSS_PROBE) + 40]
                    fixed = re.sub(r"\s+", " ", ctx).strip()
                    xss.append({
                        "url": url, "param": param, "method": method,
                        "reflected": True, "encoded": False,
                        "context": fixed[:120],
                        "note": "probe reflected RAW (bracket survived) — parameter reaches an HTML output sink unencoded",
                    })
            except Exception:
                pass

            # ---------- 2) SQL error signature (benign marker + quote) ----------
            try:
                r = await _get(base_url + self.SQL_MARKER + "%27")
                body = (r.text or '')[:200_000]
                if self.SQL_MARKER in body and self.SQL_ERROR_SIGS.search(body):
                    sig = self.SQL_ERROR_SIGS.search(body).group(0)[:60]
                    sqli.append({
                        "url": url, "param": param, "method": method,
                        "signature": sig,
                        "note": "marker + DB error string in response — parameter reaches a query layer",
                    })
            except Exception:
                pass

            # ---------- 3) path traversal (system-file signature + control) ----------
            for seq, sig in self.TRAVERSAL_PROBES:
                try:
                    r = await _get(base_url + seq)
                    body = (r.text or '')[:200_000]
                    if sig.search(body) and not sig.search(ctrl_body):
                        traversal.append({
                            "url": url, "param": param, "method": method,
                            "payload": seq,
                            "note": "system-file signature returned (control did not) — traversal reaches the filesystem",
                        })
                        break
                except Exception:
                    continue

        self.results['vuln_verify'] = {
            "tested": tested, "xss": xss, "sqli": sqli, "traversal": traversal,
        }
        # surface the confirmed surface as standard findings so every downstream
        # engine (CVSS, ATT&CK, remediation, report, webhooks) picks them up.
        for h in xss:
            self.results['vuln_verify_findings'].append(
                ("HIGH", f"Reflected XSS sink · {h['param']}",
                 f"{h['url']}?{h['param']}=… — marker reflected unencoded into an HTML context (sink reachable; no payload sent)"))
        for h in sqli:
            self.results['vuln_verify_findings'].append(
                ("CRITICAL", f"SQL injection surface · {h['param']}",
                 f"{h['url']}?{h['param']}=… — DB error signature ({h['signature']}) on a benign marker (query layer reachable; no data read)"))
        for h in traversal:
            self.results['vuln_verify_findings'].append(
                ("CRITICAL", f"Path traversal · {h['param']}",
                 f"{h['url']}?{h['param']}={h['payload']} — system-file signature returned (no file contents extracted)"))

    async def smart_fuzz(self):
        """Context-aware API discovery:
        1. business/domain/tech analysis -> targeted wordlist generation
        2. JS data-flow analysis -> resolve variable concatenation into endpoints
        3. fuzz with the generated list (ffuf if present, native fallback)."""
        # ---- 1) context: homepage + meta + domain + tech stack ----
        page = ""
        try:
            async with self.sem:
                r = await self.client.get(self.base_url + "/")
                page = r.text[:300_000]
        except Exception:
            page = ""
        meta = self.results.get('meta', {}) or {}
        title = str(meta.get('title', '') or "")
        meta_kw = " ".join(str(meta.get(k, '') or '')
                           for k in ('keywords', 'description', 'og:title', 'og:description'))
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))[:20000]
        hay = (f"{title} {meta_kw} {text} "
               f"{' '.join(self.results.get('tech_stack', []))} {self.domain}").lower()
        scores = {v: sum(1 for n in ns if n in hay)
                  for v, ns in self.BUSINESS_NOUNS.items()}
        verticals = sorted((v for v, s in scores.items() if s >= 3),
                           key=lambda v: -scores[v])[:3]
        if not verticals:
            verticals = ["ecommerce", "saas"]

        nouns = []
        for v in verticals:
            nouns += self.BUSINESS_NOUNS[v][:14]
        nouns += ["user", "users", "account", "profile", "settings", "config",
                  "search", "upload", "report", "reports", "notification",
                  "session", "token", "device", "dashboard", "export"]
        stop = {"www", "com", "org", "net", "io", "app", "co", "dev", "site",
                "web", "api", "the", "www2"}
        nouns += [t for t in re.split(r"[.\-/]", self.domain.lower())
                  if t and t not in stop][:6]

        # ---- 2) JS data-flow: variable + concatenation -> concrete endpoints ----
        js_urls = set()
        for src in (self.results.get('js_files') or [],
                    (self.results.get('katana') or {}).get('js_files') or []):
            for u in src:
                u = str(u).strip()
                if u.startswith(('http://', 'https://', '/')) and ':' not in u.split('/')[0]:
                    js_urls.add(u)
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', page, re.I):
            js_urls.add(urljoin(self.base_url + "/", m.group(1)))
        js_urls = sorted(js_urls)[: (14 if self.deep else 8)]

        VAR_RE = re.compile(
            r"""(?:const|let|var)\s+([A-Za-z_$][\w$.]*)\s*=\s*["'`]([^"'`]{1,200})["'`]""")
        CONCAT_RE = re.compile(
            r"""([A-Za-z_$][\w$.]*)\s*\+\s*["'`]([^"'`]{1,160})["'`]""")
        BASEURL_RE = re.compile(r"""baseURL\s*[:=]\s*["'`]([^"'`]{1,200})["'`]""")
        CFG_RE = re.compile(
            r"""([A-Za-z_$][\w$.]*(?:api_?url|api_?base|base_?url|api_?endpoint"""
            r"""|graphql_?url|rest_?url|api_?root)[\w$.]*)\s*[:=]\s*["'`]([^"'`]{1,200})["'`]""",
            re.I)
        js_candidates, external = set(), set()
        for ju in js_urls:
            body = ""
            try:
                u = ju if ju.startswith("http") else urljoin(self.base_url + "/", ju)
                async with self.sem:
                    r = await self.client.get(u)
                if r.status_code == 200:
                    body = r.text[:3_000_000]
            except Exception:
                continue
            if not body:
                continue
            varmap = {}
            for m in VAR_RE.finditer(body):
                # fold simple literal concatenation: const X = "a" + "b" + "c";
                val, tail, pos = m.group(2), body[m.end():m.end() + 400], 0
                while pos < 300:
                    fm = re.match(r"""\s*\+\s*["'`]([^"'`]{1,200})["'`]""", tail[pos:])
                    if not fm:
                        break
                    val += fm.group(1)
                    pos += fm.end()
                varmap[m.group(1)] = val
            for m in BASEURL_RE.finditer(body):
                varmap.setdefault("baseURL", m.group(1))
                js_candidates.add(m.group(1))
            for m in CFG_RE.finditer(body):
                js_candidates.add(varmap.get(m.group(1), m.group(2)))
            for m in CONCAT_RE.finditer(body):
                name, lit = m.group(1), m.group(2)
                base = varmap.get(name)
                if base is None:
                    base = next((v for k, v in varmap.items()
                                 if k.endswith("." + name)), None)
                if not base:
                    continue
                if base.endswith('/') and lit.startswith('/'):
                    joined = base.rstrip('/') + lit
                elif base.endswith('/') or lit.startswith('/'):
                    joined = base + lit
                else:
                    joined = base + '/' + lit
                if re.search(r"(?i)(api|v\d|graphql|auth|user|admin|internal|service)",
                             joined):
                    js_candidates.add(joined)

        js_paths = set()
        for c in js_candidates:
            c = str(c).strip().strip('"\'')
            if not c or c.startswith('//') or len(c) > 300:
                continue
            if c.startswith('http'):
                u = urlparse(c)
                if u.netloc and self.domain not in u.netloc:
                    external.add(f"{u.scheme}://{u.netloc}{u.path}")
                    continue
                path = (u.path or '/') + (f"?{u.query}" if u.query else '')
            elif c.startswith('/'):
                path = c
            else:
                continue
            if self.STATIC_EXT_RE.search(path):
                continue
            js_paths.add(path)

        js_resolved = []
        for p in sorted(js_paths)[: (80 if self.deep else 40)]:
            url = p if p.startswith('http') else self.base_url.rstrip('/') + p
            try:
                async with self.sem:
                    r = await self.client.get(url)
                if r.status_code != 404:
                    js_resolved.append({"path": p, "status": r.status_code,
                                        "size": len(r.content)})
                    self.results['api_pool'].append(
                        {"path": p, "source": f"smartfuzz:js-flow:{r.status_code}"})
            except Exception:
                continue

        # ---- generated context wordlist ----
        words, seen_w = [], set()
        for n in nouns:
            for mod in self.CTX_MODIFIERS:
                for suf in self.CTX_SUFFIXES:
                    w = f"{mod}{n}{suf}".strip('/')
                    if w and w not in seen_w and 2 < len(w) < 60:
                        seen_w.add(w)
                        words.append(w)
        known = set(FFUF_API_WORDLIST)          # module 30 already covered these
        words = [w for w in words if w not in known]
        words = words[: (1500 if self.deep else 700)]

        # ---- 3) fuzz with the generated list ----
        import shutil as _shutil
        exe = _shutil.which("ffuf") or _shutil.which("ffuf.exe")
        findings, engine, wl_file, out_file = [], "native", None, None
        if exe and words:
            try:
                engine = "ffuf"
                fd, wl_file = tempfile.mkstemp(prefix="nullveil_smart_", suffix=".txt")
                with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                    fh.write("\n".join(words))
                ofd, out_file = tempfile.mkstemp(prefix="nullveil_smart_", suffix=".json")
                os.close(ofd)
                url = self.base_url.rstrip('/') + "/FUZZ"
                cmd = [exe, "-u", url, "-w", wl_file,
                       "-mc", "200,201,202,204,207,301,302,307,401,403,405,500,501,502,503",
                       "-t", str(min(self.concurrency, 200)),
                       "-timeout", str(max(self.timeout, 8)),
                       "-of", "json", "-o", out_file, "-s",
                       "-H", f"User-Agent: Mozilla/5.0 NULLVEIL-Recon/{__version__}"]
                if self.deep:
                    cmd += ["-recursion", "-recursion-depth", "2"]
                for h in getattr(self, "_auth_cmd", []):
                    cmd += ["-H", h]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
                try:
                    await asyncio.wait_for(proc.communicate(),
                                           timeout=300 if self.deep else 180)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    self.results['errors'].append("smartfuzz: ffuf wall-time cap reached")
                try:
                    with open(out_file, encoding='utf-8') as fh:
                        data = json.load(fh)
                except Exception:
                    data = {}
                for r_ in (data.get('results') or []):
                    findings.append({"url": r_.get('url', ''),
                                     "status": r_.get('status', 0),
                                     "size": r_.get('length', 0),
                                     "content_type": r_.get('content-type', ''),
                                     "source": "context-wordlist"})
            except Exception as e:
                self.results['errors'].append(
                    f"smartfuzz: ffuf failed: {type(e).__name__} — {e}")
                engine, findings = "native", []
            finally:
                for f in (wl_file, out_file):
                    if f:
                        try:
                            os.unlink(f)
                        except Exception:
                            pass
        if engine == "native":
            for w in words[: (400 if self.deep else 200)]:
                try:
                    async with self.sem:
                        r = await self.client.get(
                            self.base_url.rstrip('/') + '/' + w.strip('/'))
                    if r.status_code != 404:
                        findings.append({"url": str(r.url), "status": r.status_code,
                                         "size": len(r.content),
                                         "content_type": r.headers.get('content-type', ''),
                                         "source": "context-wordlist"})
                except Exception:
                    continue

        seen_u, uniq_f = set(), []
        for f in findings:
            p = urlparse(f['url']).path or '/'
            if p in seen_u:
                continue
            seen_u.add(p)
            uniq_f.append(f)
            self.results['api_pool'].append(
                {"path": p, "source": f"smartfuzz:{f['status']}"})
        self.results['smartfuzz'] = {
            "available": True, "engine": engine,
            "business_profile": verticals,
            "keyword_hits": {v: scores.get(v, 0) for v in verticals},
            "wordlist_size": len(words), "js_analyzed": len(js_urls),
            "js_resolved": js_resolved, "js_endpoints": sorted(js_paths)[:200],
            "external_bases": sorted(external)[:20],
            "count": len(uniq_f), "findings": uniq_f[:300],
        }

    # ---------------------------------------------------------- Scan History
    HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".nullveil", "history")

    def _modules_run_names(self):
        """Module names that actually ran (accurate for interrupted / resumed scans)."""
        idxs = set(self.attack_set) | set(getattr(self, "_resume_done", []))
        done = getattr(self, "_completed", None)
        if done is not None:
            done_set = set(done)
            idxs = ({i for i in idxs if (module_entry(i) or ("",))[0] in done_set}
                    | set(getattr(self, "_resume_done", [])))
        return [(module_entry(i) or ("",))[0] for i in sorted(idxs)
                if module_entry(i)]

    def _history_save(self, report=None):
        """Auto-save every completed scan for --history / --resume."""
        if getattr(self, "no_history", False):
            return None
        try:
            os.makedirs(self.HISTORY_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            # include the full target (scheme://host:port) + microseconds so that
            # parallel workers scanning the same host (different ports) in the
            # same second never collide on the same history id/filename.
            hid = f"{ts}-{hashlib.md5((self.base_url + ts).encode()).hexdigest()[:6]}"
            report = report or self.export_dict()
            entry = {
                "id": hid, "target": self.base_url, "domain": self.domain,
                "when": datetime.now().isoformat(), "duration_s": round(self.scan_duration, 1),
                "version": __version__,
                "modules_run": self._modules_run_names(),
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

    @classmethod
    def _history_list(cls):
        """Return scan entries sorted newest-first."""
        out = []
        try:
            for fn in sorted(os.listdir(cls.HISTORY_DIR), reverse=True):
                if not fn.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(cls.HISTORY_DIR, fn), encoding="utf-8") as fh:
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

    # ---------------------------------------------------------- Change Detection / Diff
    @staticmethod
    def _asset_sets(report):
        """Normalise a report into comparable sets of assets."""
        r = (report or {}).get("report", report) or {}

        def _ports(v):
            out = set()
            for p in (v or []):
                if isinstance(p, dict):
                    n = p.get("port", p.get("number"))
                    if n is not None:
                        out.add(str(n))
                elif p is not None and str(p) != "":
                    out.add(str(p).split('/')[0])
            return out

        def _paths(v):
            out = set()
            for p in (v or []):
                if isinstance(p, dict):
                    if p.get("path"):
                        out.add(str(p["path"]))
                elif p:
                    out.add(str(p))
            return out

        api = r.get("api", {}) or {}
        return {
            "subdomains": {str(x).lower() for x in (r.get("subdomains") or []) if x},
            "ports": _ports(r.get("open_ports")),
            "paths": _paths(r.get("paths")),
            "api_endpoints": _paths(api.get("live_endpoints")) | _paths(api.get("paths_in_source")),
            "cookies": {str(x) for x in (api.get("cookies") or []) if x},
            "js_files": {str(x) for x in (r.get("js_files") or []) if x},
            "tech_stack": {str(x) for x in (r.get("tech_stack") or []) if x},
            "users": {str(x) for x in (r.get("users") or []) if x},
        }

    def _compute_diff(self, report):
        """Compare this scan against the newest previous scan of the same target
        and produce security-relevant change alerts (new subdomains, open ports,
        paths, API endpoints, cookies, tech …), with a CLI + report + dashboard view."""
        if getattr(self, "no_history", False) or getattr(self, "diff_disabled", False):
            return
        # newest prior entry that is not this very scan (save happens after us).
        # Prefer an exact target match (scheme://host:port) so that scanning
        # host:8080 and host:8443 do not diff against each other; fall back to
        # the bare domain for older history entries that lack a full target.
        prev = None
        prev_domain = None
        _base = (self.base_url or "").lower().rstrip("/")
        for e in self._history_list():
            edom = (e.get("domain") or "").lower()
            etgt = (e.get("target") or "").lower().rstrip("/")
            if etgt and etgt == _base:
                prev = e
                break
            if edom == self.domain.lower() and prev_domain is None:
                prev_domain = e
        if prev is None:
            prev = prev_domain
        if not prev:
            self.results['diff'] = {
                "available": False, "baseline": None,
                "note": "first scan of this target — no baseline to diff against yet",
            }
            return

        cur, old = self._asset_sets(report), self._asset_sets(prev.get("report", {}))
        added = {k: sorted(cur[k] - old[k]) for k in cur}
        removed = {k: sorted(old[k] - cur[k]) for k in old}

        # severity mapping for newly-appeared assets
        SEV = {
            "subdomains": ("MEDIUM", "new subdomain appeared"),
            "ports": ("HIGH", "new open port"),
            "paths": ("MEDIUM", "new reachable path"),
            "api_endpoints": ("HIGH", "new API endpoint"),
            "cookies": ("LOW", "new cookie observed"),
            "js_files": ("LOW", "new JS bundle"),
            "tech_stack": ("INFO", "new technology fingerprinted"),
            "users": ("LOW", "new user/author exposed"),
        }
        findings = []
        for key, items in added.items():
            if not items:
                continue
            sev, desc = SEV.get(key, ("INFO", "new " + key))
            findings.append({
                "severity": sev, "check": f"new-{key.rstrip('s')}",
                "detail": f"{len(items)} {desc}(s): {', '.join(items[:8])}"
                          + (" …" if len(items) > 8 else ""),
                "items": items,
            })

        # score the change set (new risky ports weigh heaviest)
        risk_ports = [p for p in added.get("ports", []) if p.isdigit()
                      and int(p) in getattr(type(self), "CRIT_PORTS", {})]
        score = (len(added.get("ports", [])) * 12 + len(risk_ports) * 18
                 + len(added.get("api_endpoints", [])) * 6
                 + len(added.get("subdomains", [])) * 4
                 + len(added.get("paths", [])) * 3
                 + len(added.get("users", [])) * 2
                 + (len(added.get("cookies", [])) + len(added.get("js_files", []))) * 1)
        score = min(100, score)
        verdict = ("CRITICAL DRIFT" if score >= 70 else "HIGH DRIFT" if score >= 40
                   else "MODERATE DRIFT" if score >= 15 else
                   ("LOW DRIFT" if score else "NO CHANGE"))

        self.results['diff'] = {
            "available": True,
            "baseline_id": prev.get("id"), "baseline_when": prev.get("when"),
            "added": added, "removed": removed,
            "score": score, "verdict": verdict,
            "summary": {k: len(v) for k, v in added.items()},
            "findings": findings,
        }
        # surface notable new assets as first-class findings too
        if added.get("ports"):
            self.results['diff_findings'] = [
                (f["severity"], f"change:{f['check']}", f["detail"]) for f in findings]
            for sev, chk, det in self.results['diff_findings']:
                if sev in ("CRITICAL", "HIGH"):
                    self.results['errors'].append(
                        f"change-alert: {det}")

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
            [p for p in self.results['paths'] if isinstance(p, dict) and p.get('flagged')],
        )
        risk_body = Group(
            Text.from_markup(f"{bar}  [bold {color}]{score}/100 — {verdict}[/]"),
            Align.center(Text.from_markup(
                f"[dim]Risk Level:[/] [bold {color}]{level}[/]   "
                f"[dim]Secrets:[/] [white]{len(set(self.results['secrets']))}[/]   "
                f"[dim]Flagged Paths:[/] [white]{len([p for p in self.results['paths'] if isinstance(p, dict) and p.get('flagged')])}[/]   "
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
            ("API Endpoints", len(set([ep.get('path') if isinstance(ep, dict) else ep for ep in (self.results.get('api_endpoints', []) or [])] + [ep for ep in (self.results.get('api_endpoints_found', []) or []) if ep]))),
            ("API Documents", len(self.results.get('api_docs', []))),
            ("Forms", len(self.results.get('forms', []))),
            ("WAF / CDN", len(self.results.get('waf', []))),
            ("Email Issues", len([f for f in self.results.get('email_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Audit Issues", len([f for f in self.results.get('api_audit_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Takeover Risks", len(self.results.get('takeover', []))),
            ("CVE / Misconfig", len([f for f in self.results.get('cve_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Crawled Pages", self.results.get('crawl', {}).get('pages_crawled', 0)),
            ("TLS Issues", len([f for f in self.results.get('tls_findings', []) if f[0] in ('CRITICAL', 'HIGH', 'MEDIUM')])),
            ("Auth-Gated APIs", self.results.get('authscan', {}).get('auth_gated', 0)
             if isinstance(self.results.get('authscan'), dict) else 0),
            ("Role-Hidden APIs", len(self.results.get('authscan', {}).get('role_gated', []))
             if isinstance(self.results.get('authscan'), dict) else 0),
            ("SSRF / Bypass Hits", (len(self.results.get('ssrf', {}).get('bypass', []))
                                    + len(self.results.get('ssrf', {}).get('metadata', []))
                                    + len(self.results.get('ssrf', {}).get('oob', {}).get('hits', [])))
             if isinstance(self.results.get('ssrf'), dict) else 0),
            ("Smart Fuzz Hits", self.results.get('smartfuzz', {}).get('count', 0)
             if isinstance(self.results.get('smartfuzz'), dict) else 0),
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
            sec_wafs = self.results.get('waf_security', [])
            grid = "   ".join(
                (f"[bold red]🛡 {w}[/]" if w in sec_wafs else f"[bold cyan]☁ {w}[/]")
                for w in wafs)
            body = f"  [bold white]Detected:[/] {grid}\n"
            body += "  [dim]Red shield = security WAF · Cyan cloud = CDN/edge only[/]\n\n"
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
                                 f"{len(nuc.get('findings', []))} finding(s)[/]")
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
        # --- Katana crawler ---
        kat = self.results.get('katana', [])
        if isinstance(kat, dict) and (kat.get('urls_crawled') or kat.get('note')):
            if kat.get('urls_crawled'):
                body = (f"  [green]✓[/] v{kat.get('version', '?')}  ·  depth {kat.get('depth', '?')}  ·  "
                        f"[bold]{kat.get('urls_crawled', 0)}[/] URLs crawled  ·  "
                        f"[bold]{len(kat.get('endpoints', []))}[/] API endpoints  ·  "
                        f"[bold]{len(kat.get('js_files', []))}[/] JS files\n")
                eps = kat.get('endpoints', [])[:40]
                if eps:
                    body += "\n" + "\n".join(f"  [cyan]•[/] {e}" for e in eps)
                console.print(Panel(body, title="[bold cyan]◈ KATANA CRAWLER ◈[/]",
                                    border_style="cyan", box=rbox.ROUNDED))
            elif kat.get('note'):
                console.print(Panel(f"  [yellow]•[/] {kat['note']}",
                                    title="[bold yellow]◈ KATANA (not available) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))
        # --- LinkFinder JS endpoints ---
        lf = self.results.get('linkfinder', [])
        if isinstance(lf, dict) and lf.get('count'):
            src_note = ("external linkfinder CLI" if lf.get('external_cli')
                        else "built-in LinkFinder regex engine")
            body = (f"  [green]✓[/] {lf.get('js_analyzed', 0)} JS bundle(s) analyzed via {src_note}  ·  "
                    f"[bold]{lf.get('count', 0)}[/] hidden endpoint(s) found\n")
            eps = lf.get('endpoints', [])[:40]
            if eps:
                body += "\n" + "\n".join(f"  [magenta]•[/] {e}" for e in eps)
            console.print(Panel(body, title="[bold magenta]◈ LINKFINDER JS ENDPOINTS ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))
        # --- FFUF fuzzing ---
        ff = self.results.get('ffuf', [])
        if isinstance(ff, dict) and (ff.get('count') or ff.get('note')):
            if ff.get('count'):
                sev_col2 = {"200": "bold green", "201": "bold green", "204": "green",
                            "301": "yellow", "302": "yellow", "307": "yellow",
                            "401": "red", "403": "red", "405": "magenta"}
                ft = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_blue",
                           title=f"[bold blue]◈ FFUF API FUZZING ◈[/] [dim]{ff.get('count', 0)} live path(s) · "
                                 f"wordlist: {ff.get('wordlist_size', 0)}[/]")
                ft.add_column("Status", justify="center")
                ft.add_column("URL")
                ft.add_column("Size", justify="right")
                ft.add_column("Type")
                for x in ff.get('findings', [])[:50]:
                    st = str(x.get('status', ''))
                    ft.add_row(f"[{sev_col2.get(st, 'white')}]{st}[/]",
                               str(x.get('url', ''))[:90],
                               str(x.get('size', '')),
                               str(x.get('content_type', ''))[:24])
                console.print(ft)
            elif ff.get('note'):
                console.print(Panel(f"  [yellow]•[/] {ff['note']}",
                                    title="[bold yellow]◈ FFUF (not available) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))
        # --- Burp / Caido traffic bridge ---
        bur = self.results.get('burp', [])
        if isinstance(bur, dict) and (bur.get('proxy') or bur.get('har_entries') or bur.get('proxy_note')):
            body = ""
            if bur.get('proxy'):
                ok = bur.get('proxy_ok')
                body += (f"  {'[green]✓[/]' if ok else '[red]✗[/]'} Proxy: [bold]{bur['proxy']}[/] — "
                         + (f"[green]capture active[/]  [dim]{bur.get('proxy_note', '')}[/]"
                            if ok else f"[red]unreachable[/]  [dim]{bur.get('proxy_note', '')}[/]") + "\n")
            if bur.get('har_files'):
                names = ", ".join(os.path.basename(h.get('file', '')) for h in bur['har_files'])
                body += (f"  [green]✓[/] HAR import: [bold]{bur.get('har_entries', 0)}[/] entrie(s) from "
                         f"[bold]{len(bur['har_files'])}[/] file(s) [dim]({names})[/]\n")
                if bur.get('endpoints'):
                    body += (f"    [cyan]•[/] [bold]{len(bur['endpoints'])}[/] endpoint(s)  ·  "
                             f"[bold]{len(bur.get('params', []))}[/] parameter(s)  ·  "
                             f"[bold]{len(bur.get('cookies', []))}[/] cookie(s)  ·  "
                             f"[bold]{len(bur.get('js_files', []))}[/] JS bundle(s)\n")
                eps = bur.get('endpoints', [])[:30]
                if eps:
                    body += "\n" + "\n".join(f"  [magenta]•[/] {e}" for e in eps)
            if bur.get('secrets'):
                body += "\n\n  [red]secrets visible in captured responses:[/]\n"
                body += "\n".join(f"  [red]•[/] {s}" for s in bur['secrets'][:15])
            console.print(Panel(body or f"  [dim]{bur.get('proxy_note', '')}[/]",
                                title="[bold yellow]◈ BURP / CAIDO TRAFFIC BRIDGE ◈[/]",
                                border_style="yellow", box=rbox.ROUNDED))
        # --- Change detection vs previous scan (diff tracking) ---
        dif = self.results.get('diff', {})
        if isinstance(dif, dict) and dif.get('available'):
            score_d = int(dif.get('score', 0))
            vcol = ("bold red" if score_d >= 70 else "bold yellow" if score_d >= 40
                    else "yellow" if score_d >= 15 else ("cyan" if score_d else "green"))
            body = (f"  change score: [bold]{score_d}[/][dim]/100[/]  ·  "
                    f"verdict: [{vcol}]{dif.get('verdict', '')}[/]\n"
                    f"  [dim]baseline:[/] {dif.get('baseline_id', '?')} "
                    f"[dim]({str(dif.get('baseline_when', ''))[:19].replace('T', ' ')})[/]\n")
            for key, items in (dif.get('added') or {}).items():
                if items:
                    body += (f"\n  [green]+{len(items)}[/] new [bold]{key}[/]: "
                             + ", ".join(items[:8]) + (" …" if len(items) > 8 else ""))
            for key, items in (dif.get('removed') or {}).items():
                if items:
                    body += (f"\n  [red]-{len(items)}[/] gone [bold]{key}[/]: "
                             + ", ".join(items[:8]) + (" …" if len(items) > 8 else ""))
            if not any((dif.get('added') or {}).values()):
                body += "\n  [green]no new assets since the last scan[/]"
            console.print(Panel(body, title="[bold magenta]◈ SCAN DIFF — CHANGES SINCE LAST SCAN ◈[/]",
                                border_style=vcol.split()[-1], box=rbox.ROUNDED))
        # --- Authenticated scan (session injection + role diff) ---
        asc = self.results.get('authscan', [])
        if isinstance(asc, dict) and (asc.get('available') or asc.get('note')):
            if asc.get('available'):
                ainfo = self.results.get('auth_setup', {}) or {}
                body = (f"  [green]✓[/] session — headers: "
                        f"{', '.join(ainfo.get('headers', [])) or '-'} · cookies: "
                        f"{', '.join(ainfo.get('cookies', [])) or '-'}"
                        + (f" · login: HTTP {ainfo['login'].get('status')}"
                           if isinstance(ainfo.get('login'), dict) else "")
                        + f"\n  [bold]{asc.get('endpoints_probed', 0)}[/] endpoint(s) probed "
                          f"with & without auth · [bold]{asc.get('auth_gated', 0)}[/] auth-gated"
                          f" · [bold]{asc.get('status_changed', 0)}[/] status changed"
                          + (" · session [green]verified[/]" if asc.get('session_verified') else "")
                          + "\n")
                roles = asc.get('roles', [])
                if roles:
                    body += f"  [cyan]roles:[/] {', '.join(roles)}\n"
                changed = [x for x in asc.get('findings', []) if x.get('auth_gated')][:25]
                if changed:
                    body += "\n" + "\n".join(
                        f"  [red]•[/] {x['path']}  [dim]noauth {x['status_noauth']} → "
                        f"auth [bold]{x['status_auth']}[/][/]" for x in changed)
                console.print(Panel(body, title="[bold red]◈ AUTHENTICATED API SCAN ◈[/]",
                                    border_style="red", box=rbox.ROUNDED))
                gated = asc.get('role_gated', [])
                if gated:
                    gt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_red",
                               title=f"[bold red]◈ ROLE-HIDDEN APIs ◈[/] [dim]{len(gated)} endpoint(s) "
                                     f"visible to some roles only[/]")
                    gt.add_column("Endpoint")
                    gt.add_column("Visible to")
                    gt.add_column("Hidden from")
                    for g in gated[:40]:
                        gt.add_row(str(g.get('path', ''))[:70],
                                   ", ".join(g.get('visible_to', [])) or "-",
                                   ", ".join(f"{h.get('role')}:{h.get('status')}"
                                             for h in g.get('hidden_from', [])))
                    console.print(gt)
                # --- backend / admin API audit with injected session ---
                adm = asc.get('admin_audit') or {}
                if adm.get('probed'):
                    ab = (f"  [bold]{adm.get('probed', 0)}[/] admin/backend path(s) probed with your session  ·  "
                          f"[bold]{adm.get('reachable', 0)}[/] reachable  ·  "
                          f"[bold]{adm.get('session_only', 0)}[/] session-only  ·  "
                          f"[bold]{adm.get('sensitive', 0)}[/] sensitive-data\n")
                    for f in (adm.get('findings') or [])[:25]:
                        sev, chk, det = (f[0], f[1], f[2]) if isinstance(f, (list, tuple)) else (f.get('severity', ''), f.get('check', ''), f.get('detail', ''))
                        col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "cyan")
                        ab += f"\n  [{col}]•[/] [{col}]{sev}[/] {det}"
                    console.print(Panel(ab, title="[bold red]◈ BACKEND / ADMIN API AUDIT ◈[/]",
                                        border_style="red", box=rbox.ROUNDED))
            elif asc.get('note'):
                console.print(Panel(f"  [yellow]•[/] {asc['note']}",
                                    title="[bold yellow]◈ AUTH SCAN (no session) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))
        # --- SSRF / internal pivot ---
        ssr = self.results.get('ssrf', [])
        if isinstance(ssr, dict) and ssr.get('available'):
            body = (f"  [bold]{ssr.get('endpoints', 0)}[/] endpoint(s) × "
                    f"{len(self.SSRF_BYPASS_HEADERS)} bypass header set(s)  ·  "
                    f"[bold]{ssr.get('bypass_count', 0)}[/] response diff(s)  ·  "
                    f"[bold]{len(ssr.get('metadata', []))}[/] metadata path hit(s)\n")
            bps = [b for b in ssr.get('bypass', [])
                   if str(b.get('verdict', '')).startswith('possible')][:20]
            bt = None
            if bps:
                bt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_red")
                bt.add_column("Endpoint")
                bt.add_column("Header")
                bt.add_column("Baseline→New", justify="center")
                bt.add_column("Verdict")
                for b in bps:
                    bt.add_row(str(b.get('path', ''))[:40], str(b.get('header', ''))[:46],
                               f"{b.get('baseline_status')}→{b.get('status')}",
                               str(b.get('verdict', '')))
                body += "\n  [red]possible internal bypass:[/]\n"
            oob = ssr.get('oob', {}) or {}
            if oob.get('enabled'):
                body += (f"\n  [cyan]OOB:[/] domain [bold]{oob.get('domain', '?')}[/] · "
                         f"{oob.get('injected', 0)} probe(s) · {oob.get('note', '')}\n")
            console.print(Panel(body, title="[bold red]◈ SSRF & INTERNAL PIVOT ◈[/]",
                                border_style="red", box=rbox.ROUNDED))
            if bt is not None:
                console.print(bt)
            mds = ssr.get('metadata', [])[:12]
            if mds:
                mt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_orange",
                           title="[bold yellow]◈ CLOUD METADATA PROBE HITS ◈[/]")
                mt.add_column("Path")
                mt.add_column("Status", justify="center")
                mt.add_column("Header")
                mt.add_column("Sig", justify="center")
                for m in mds:
                    mt.add_row(str(m.get('path', ''))[:52], str(m.get('status', '')),
                               str(m.get('header', ''))[:30],
                               "[green]✓[/]" if m.get('signature') else "[dim]-[/]")
                console.print(mt)
        # --- Smart context fuzz ---
        smf = self.results.get('smartfuzz', [])
        if isinstance(smf, dict) and smf.get('available'):
            body = (f"  [green]✓[/] business profile: "
                    f"[bold]{', '.join(smf.get('business_profile', [])) or '?'}[/] "
                    f"[dim]{smf.get('keyword_hits', {})}[/]\n"
                    f"  [bold]{smf.get('wordlist_size', 0)}[/] generated path(s) fuzzed via "
                    f"{'ffuf' if smf.get('engine') == 'ffuf' else 'native prober'} · "
                    f"[bold]{smf.get('js_analyzed', 0)}[/] JS bundle(s) data-flow analyzed → "
                    f"[bold]{len(smf.get('js_endpoints', []))}[/] candidate(s), "
                    f"[bold]{len(smf.get('js_resolved', []))}[/] live\n")
            for b in smf.get('external_bases', [])[:5]:
                body += f"  [magenta]• external API base (JS data-flow):[/] {b}\n"
            js_live = smf.get('js_resolved', [])[:15]
            if js_live:
                body += "\n" + "\n".join(
                    f"  [cyan]•[/] {j['path']}  [dim]{j['status']}[/]"
                    for j in js_live)
            console.print(Panel(body, title="[bold blue]◈ SMART CONTEXT FUZZ ◈[/]",
                                border_style="blue", box=rbox.ROUNDED))
            sf = smf.get('findings', [])
            if sf:
                sft = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_blue",
                            title=f"[bold blue]◈ CONTEXT-AWARE FINDINGS ◈[/] "
                                  f"[dim]{smf.get('count', 0)} live path(s)[/]")
                sft.add_column("Status", justify="center")
                sft.add_column("URL")
                sft.add_column("Size", justify="right")
                sft.add_column("Source")
                for x in sf[:40]:
                    sft.add_row(str(x.get('status', '')), str(x.get('url', ''))[:90],
                                str(x.get('size', '')), str(x.get('source', '')))
                console.print(sft)
        # --- Unified API pool (katana + linkfinder + ffuf + api modules) ---
        pool = self.results.get('api_pool', [])
        if pool:
            seen, uniq = set(), []
            for e in pool:
                k = str(e.get('path', ''))
                if k and k not in seen:
                    seen.add(k)
                    uniq.append(e)
            pt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_green",
                       title=f"[bold green]◈ UNIFIED API POOL ◈[/] [dim]{len(uniq)} unique endpoint(s) across all modules[/]")
            pt.add_column("Endpoint", style="bold")
            pt.add_column("Source(s)", style="dim")
            src_map = {}
            for e in uniq:
                src_map.setdefault(str(e.get('path', '')), set()).add(str(e.get('source', '')))
            for p, srcs in list(src_map.items())[:60]:
                pt.add_row(p[:80], ", ".join(sorted(srcs))[:60])
            console.print(pt)
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

        # --- AI patch & remediation generator (35) ---
        pat = self.results.get('patch', {})
        if isinstance(pat, dict) and pat.get('generated'):
            body = f"  [green]✓[/] [bold]{pat.get('generated', 0)}[/] remediation item(s) · " \
                   f"[dim]offline template/heuristic engine (no AI key needed)[/]\n"
            for p in (pat.get('patches') or [])[:12]:
                sev = str(p.get('severity', 'INFO'))
                col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                       "LOW": "cyan"}.get(sev, "dim")
                body += f"\n  [{col}]•[/] [{col}]{sev}[/] [bold]{p.get('title', '')}[/]  [dim]({p.get('check', '')})[/]"
            console.print(Panel(body, title="[bold cyan]◈ AI PATCH & REMEDIATION ◈[/]",
                                border_style="cyan", box=rbox.ROUNDED))
        # --- Read-only PoC verification (36) ---
        poc = self.results.get('poc', {})
        if isinstance(poc, dict) and poc.get('generated'):
            body = f"  [green]✓[/] [bold]{poc.get('generated', 0)}[/] read-only verification set(s)  ·  " \
                   f"[dim]{poc.get('policy', '')}[/]\n"
            for p in (poc.get('pocs') or [])[:6]:
                body += f"\n  [magenta]•[/] [{ 'red' if p.get('severity') in ('CRITICAL','HIGH') else 'yellow'}]" \
                        f"{p.get('severity')}[/] {p.get('check', '')}"
                for cm in (p.get('commands') or [])[:2]:
                    body += f"\n      [dim]{cm.get('desc', '')}:[/] [white]{cm.get('cmd', '')[:110]}[/]"
            console.print(Panel(body, title="[bold magenta]◈ READ-ONLY PoC VERIFICATION ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))
        # --- Multi-channel notifications (37) ---
        ntf = self.results.get('notify', {})
        if isinstance(ntf, dict) and (ntf.get('channels') or ntf.get('note')):
            if ntf.get('channels'):
                body = f"  channels: [bold]{', '.join(ntf.get('channels', []))}[/]  ·  " \
                       f"[green]{len(ntf.get('sent', []))} sent[/]  ·  " \
                       f"[red]{len(ntf.get('failed', []))} failed[/]\n"
                sv = ntf.get('severity') or {}
                if sv:
                    body += (f"  alert severity: [bold red]CRITICAL {sv.get('CRITICAL', 0)}[/] · "
                             f"[red]HIGH {sv.get('HIGH', 0)}[/] · "
                             f"[yellow]MEDIUM {sv.get('MEDIUM', 0)}[/]\n")
                for x in ntf.get('failed', [])[:10]:
                    body += f"  [red]•[/] {x.get('channel')}: {x.get('status', '')} {x.get('error') or x.get('body', '')}\n"
                console.print(Panel(body, title="[bold green]◈ WEBHOOK NOTIFICATIONS ◈[/]",
                                    border_style="green", box=rbox.ROUNDED))
            elif ntf.get('note'):
                console.print(Panel(f"  [yellow]•[/] {ntf['note']}",
                                    title="[bold yellow]◈ WEBHOOK NOTIFICATIONS (not configured) ◈[/]",
                                    border_style="yellow", box=rbox.ROUNDED))
        # --- Executive report (39) ---
        ex = self.results.get('exec', {})
        if isinstance(ex, dict) and ex.get('html'):
            body = (f"  [green]✓[/] executive HTML → [cyan]{ex.get('html')}[/]\n"
                    f"  exposure: [bold]{ex.get('score', 0)}[/]/100 — [bold]{ex.get('verdict', '')}[/]\n"
                    f"  severity: CRITICAL {ex.get('sev', {}).get('CRITICAL', 0)} · "
                    f"HIGH {ex.get('sev', {}).get('HIGH', 0)} · MEDIUM {ex.get('sev', {}).get('MEDIUM', 0)}")
            if ex.get('pdf'):
                body += f"\n  [green]✓[/] executive PDF ({ex.get('pdf_engine', '')}) → [cyan]{ex.get('pdf')}[/]"
            elif getattr(self, "exec_pdf_path", ""):
                body += "\n  [yellow]•[/] PDF skipped — install weasyprint / reportlab / playwright"
            console.print(Panel(body, title="[bold blue]◈ EXECUTIVE REPORT ◈[/]",
                                border_style="blue", box=rbox.ROUNDED))
        # --- Smart deduplication stats ---
        dd = self.results.get('dedupe_stats', {})
        if isinstance(dd, dict) and dd.get('removed'):
            console.print(Panel(
                f"  [green]✓[/] deduplicated findings: {dd.get('before', 0)} → {dd.get('after', 0)} "
                f"[dim]({dd.get('removed', 0)} redundant removed)[/]",
                title="[bold white]◈ SMART DEDUPLICATION ◈[/]", border_style="white", box=rbox.ROUNDED))

        # --- JS Secret & Source-Map Miner (40) ---
        jsec = self.results.get('js_secret', {})
        if isinstance(jsec, dict) and jsec.get('available'):
            body = (f"  [green]✓[/] {jsec.get('js_analyzed', 0)} JS bundle(s) · "
                    f"[bold]{jsec.get('secret_count', 0)}[/] secret(s) · "
                    f"{jsec.get('sink_count', 0)} sink(s) · "
                    f"{jsec.get('endpoint_count', 0)} endpoint(s) · "
                    f"[magenta]{jsec.get('map_count', 0)}[/] source map(s)\n")
            for s in (jsec.get('secrets') or [])[:10]:
                col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(s.get('severity'), "cyan")
                body += f"  [{col}]• {s.get('severity')}[/] [bold]{s.get('type')}[/] " \
                        f"[dim]{s.get('masked', '')} · {str(s.get('source', ''))[:70]}[/]\n"
            console.print(Panel(body, title="[bold magenta]◈ JS SECRET & SOURCE-MAP MINER ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))
        # --- Historical URL Miner (41) ---
        wb = self.results.get('wayback', {})
        if isinstance(wb, dict) and wb.get('available'):
            body = (f"  [green]✓[/] {wb.get('url_count', 0)} historical URL(s) · "
                    f"[bold]{wb.get('interesting_count', 0)}[/] interesting · "
                    f"{wb.get('param_count', 0)} param(s)  [dim]sources: {', '.join(wb.get('sources', []))}[/]\n")
            for u in (wb.get('interesting') or [])[:8]:
                body += f"  [yellow]•[/] [white]{str(u)[:110]}[/]\n"
            console.print(Panel(body, title="[bold yellow]◈ HISTORICAL URL MINER ◈[/]",
                                border_style="yellow", box=rbox.ROUNDED))
        # --- Hidden Parameter Miner (42) ---
        pm = self.results.get('param', {})
        if isinstance(pm, dict) and pm.get('available'):
            body = (f"  [green]✓[/] {pm.get('count', 0)} hidden param(s) discovered across "
                    f"{pm.get('urls_tested', 0)} endpoint(s)  [dim]{pm.get('policy', '')[:70]}[/]\n")
            for p in (pm.get('params') or [])[:12]:
                col = "bold red" if p.get('type') == 'reflected' else "cyan"
                body += f"  [{col}]•[/] [bold]{p.get('name')}[/] [dim]({p.get('type')}) · {str(p.get('url', ''))[:70]}[/]\n"
            console.print(Panel(body, title="[bold cyan]◈ HIDDEN PARAMETER MINER ◈[/]",
                                border_style="cyan", box=rbox.ROUNDED))
        # --- GraphQL Deep Audit (43) ---
        gql = self.results.get('graphql', {})
        if isinstance(gql, dict) and gql.get('count'):
            body = f"  [green]✓[/] {gql.get('count', 0)} GraphQL endpoint(s) found\n"
            for e in (gql.get('endpoints') or [])[:8]:
                flags = []
                if e.get('introspection'):
                    flags.append("[red]introspection[/]")
                if e.get('field_suggestions'):
                    flags.append("[yellow]suggestions[/]")
                if e.get('depth_limited') is False:
                    flags.append("[yellow]no-depth-limit[/]")
                body += (f"  [magenta]•[/] [white]{e.get('endpoint', '')}[/] "
                         f"[dim]({e.get('status', '')})[/] {' '.join(flags) or '[green]hardened[/]'}\n")
            console.print(Panel(body, title="[bold magenta]◈ GRAPHQL DEEP AUDIT ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))
        # --- Cloud Storage Enumeration (44) ---
        cl = self.results.get('cloud', {})
        if isinstance(cl, dict) and cl.get('count'):
            body = (f"  [green]✓[/] {cl.get('count', 0)} bucket(s) exist of "
                    f"{cl.get('candidates_tested', 0)} tested  [dim]{cl.get('policy', '')[:60]}[/]\n")
            for b in (cl.get('buckets') or [])[:12]:
                col = "bold red" if b.get('public_listing') or b.get('writable_probe') else "dim"
                tag = "PUBLIC LISTING" if b.get('public_listing') else "exists"
                if b.get('writable_probe'):
                    tag = "Writable?"
                body += f"  [{col}]•[/] [white]{b.get('provider')}[/] [bold]{b.get('bucket')}[/] [dim]{tag}[/]\n"
            console.print(Panel(body, title="[bold blue]◈ CLOUD STORAGE ENUMERATION ◈[/]",
                                border_style="blue", box=rbox.ROUNDED))

        # --- CVSS 4.0 / CWE Risk Scoring (45) ---
        cvs = self.results.get('cvss', {})
        if isinstance(cvs, dict) and cvs.get('count'):
            dist = cvs.get('distribution', {})
            body = (f"  [green]✓[/] {cvs.get('count', 0)} finding(s) scored · "
                    f"mean CVSS [bold]{cvs.get('mean_score', 0)}[/] · "
                    f"[red]{dist.get('CRITICAL', 0)}[/] crit / "
                    f"[yellow]{dist.get('HIGH', 0)}[/] high / "
                    f"{dist.get('MEDIUM', 0)} med / {dist.get('LOW', 0)} low\n"
                    f"  [dim]{cvs.get('method', '')[:100]}[/]\n")
            for e in (cvs.get('top') or [])[:10]:
                col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(e.get('severity'), "cyan")
                reb = f" [magenta]({e['rebanded']})[/]" if e.get('rebanded') else ""
                body += (f"  [{col}]• {e.get('score', 0):>4}[/] [white]{e.get('check', '')[:60]}[/] "
                         f"[dim]{e.get('cwe', '')}{reb}[/]\n")
            console.print(Panel(body, title="[bold cyan]◈ CVSS 4.0 / CWE RISK SCORING ◈[/]",
                                border_style="cyan", box=rbox.ROUNDED))
        # --- MITRE ATT&CK Mapping (46) ---
        am = self.results.get('attack_map', {})
        if isinstance(am, dict) and am.get('technique_count'):
            body = (f"  [green]✓[/] {am.get('technique_count', 0)} technique(s) across "
                    f"{am.get('tactic_count', 0)} tactic(s)  "
                    f"[dim]{am.get('note', '')[:70]}[/]\n")
            for t in (am.get('techniques') or [])[:12]:
                col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(t.get('max_severity'), "cyan")
                body += (f"  [{col}]•[/] [bold]{t.get('id')}[/] {t.get('name', '')[:48]} "
                         f"[dim]· {t.get('tactic')} × {t.get('count')}[/]\n")
            console.print(Panel(body, title="[bold red]◈ MITRE ATT&CK MAPPING ◈[/]",
                                border_style="red", box=rbox.ROUNDED))
        # --- CVE Intelligence Enricher (47) ---
        ci = self.results.get('cve_intel', {})
        if isinstance(ci, dict) and ci.get('count'):
            badge = (f"[bold green]LIVE[/] [dim]({ci.get('live_enriched', 0)}/"
                     f"{ci.get('count', 0)} from NVD+EPSS)[/]"
                     if ci.get('live') else "[dim]offline curated[/]")
            body = (f"  [green]✓[/] {ci.get('count', 0)} CVE(s) enriched · "
                    f"source: {badge} · "
                    f"KEV [bold red]{ci.get('kev_count', 0)}[/] · "
                    f"mean CVSS {ci.get('cvss_mean', 0)}\n")
            for r in (ci.get('cves') or [])[:12]:
                col = "bold red" if r.get('kev') else "red" if r.get('severity') == 'CRITICAL' else "yellow"
                tags = " ".join(t for t in ("KEV" if r.get('kev') else "",
                                            f"EPSS {r.get('epss'):.0%}" if r.get('epss') else "",
                                            "exploit" if r.get('exploit_available') else "") if t)
                body += (f"  [{col}]• {r.get('cve')} (CVSS {r.get('cvss')})[/] "
                         f"{r.get('cwe')} [magenta]{tags}[/] [dim]{r.get('priority', '')}[/]\n")
            console.print(Panel(body, title="[bold yellow]◈ CVE INTELLIGENCE ENRICHER ◈[/]",
                                border_style="yellow", box=rbox.ROUNDED))
        # --- Subdomain Takeover v3 (48) ---
        tv = self.results.get('takeover_v3', {})
        if isinstance(tv, dict) and tv.get('hosts_checked'):
            body = (f"  [green]✓[/] {tv.get('hosts_checked', 0)} host(s) with CNAME checked · "
                    f"[bold red]{tv.get('risk_count', 0)}[/] risk(s) · "
                    f"{tv.get('providers', 0)} provider fingerprints\n")
            for r in (tv.get('risks') or [])[:12]:
                col = "bold red" if r.get('severity') == 'HIGH' else "yellow"
                body += (f"  [{col}]• {r.get('status')}[/] [white]{r.get('host')}[/] "
                         f"[dim]→ {r.get('service')}[/]\n")
            console.print(Panel(body, title="[bold red]◈ SUBDOMAIN TAKEOVER V3 ◈[/]",
                                border_style="red", box=rbox.ROUNDED))
        # --- Continuous Change Monitor (49) ---
        wm = self.results.get('watch', {})
        if isinstance(wm, dict) and wm.get('available'):
            if not wm.get('baseline'):
                body = f"  [cyan]•[/] {wm.get('note', '')}\n"
            else:
                col = {"REGRESSION": "bold red", "IMPROVEMENT": "green",
                       "CHANGED": "yellow"}.get(wm.get('verdict'), "cyan")
                body = (f"  [{col}]{wm.get('verdict')}[/] · "
                        f"[bold]{wm.get('added_total', 0)}[/] new · "
                        f"{wm.get('removed_total', 0)} removed · "
                        f"risk Δ {wm.get('risk_delta', 0):+d} "
                        f"[dim](baseline {str(wm.get('baseline_when', ''))[:19]})[/]\n")
                for f in (wm.get('findings') or [])[:8]:
                    body += f"  [dim]•[/] [white]{f.get('check', '')}[/] {f.get('detail', '')[:70]}\n"
            console.print(Panel(body, title="[bold magenta]◈ CONTINUOUS CHANGE MONITOR ◈[/]",
                                border_style="magenta", box=rbox.ROUNDED))

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
            "duration_s": round(getattr(self, "scan_duration", 0.0), 1),
            "mode": "deep" if self.deep else "normal",
            "modules_run": self._modules_run_names(),
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
                "api_endpoints": len(set([ep.get('path') if isinstance(ep, dict) else ep for ep in (self.results.get('api_endpoints', []) or [])] + [ep for ep in (self.results.get('api_endpoints_found', []) or []) if ep])),
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
                "katana_urls": self.results.get('katana', {}).get('urls_crawled', 0),
                "katana_endpoints": len(self.results.get('katana', {}).get('endpoints', [])),
                "linkfinder_endpoints": self.results.get('linkfinder', {}).get('count', 0),
                "ffuf_found": self.results.get('ffuf', {}).get('count', 0),
                "har_endpoints": len(self.results.get('burp', {}).get('endpoints', [])),
                "har_entries": self.results.get('burp', {}).get('har_entries', 0),
                "auth_gated_apis": self.results.get('authscan', {}).get('auth_gated', 0),
                "role_hidden_apis": len(self.results.get('authscan', {}).get('role_gated', [])),
                "admin_api_findings": len(self.results.get('admin_findings', [])),
                "ssrf_bypass_hits": len(self.results.get('ssrf', {}).get('bypass', [])),
                "ssrf_metadata_hits": len(self.results.get('ssrf', {}).get('metadata', [])),
                "vuln_verify_xss": len(self.results.get('vuln_verify', {}).get('xss', [])),
                "vuln_verify_sqli": len(self.results.get('vuln_verify', {}).get('sqli', [])),
                "vuln_verify_traversal": len(self.results.get('vuln_verify', {}).get('traversal', [])),
                "oob_interactions": len(self.results.get('ssrf', {}).get('oob', {}).get('hits', [])),
                "smartfuzz_found": self.results.get('smartfuzz', {}).get('count', 0),
                "api_pool_total": len(self.results.get('api_pool', [])),
                "diff_new_assets": sum(len(v) for v in
                                       (self.results.get('diff', {}).get('added') or {}).values()),
                "diff_score": self.results.get('diff', {}).get('score', 0),
                "remediation_patches": self.results.get('patch', {}).get('generated', 0),
                "poc_verifications": self.results.get('poc', {}).get('generated', 0),
                "notifications_sent": len(self.results.get('notify', {}).get('sent', [])),
                "dedupe_removed": self.results.get('dedupe_stats', {}).get('removed', 0),
                "js_secrets": self.results.get('js_secret', {}).get('secret_count', 0),
                "js_source_maps": self.results.get('js_secret', {}).get('map_count', 0),
                "historical_urls": self.results.get('wayback', {}).get('url_count', 0),
                "hidden_params": self.results.get('param', {}).get('count', 0),
                "graphql_endpoints": self.results.get('graphql', {}).get('count', 0),
                "cloud_buckets": self.results.get('cloud', {}).get('count', 0),
                "cvss_findings": self.results.get('cvss', {}).get('count', 0),
                "cvss_mean": self.results.get('cvss', {}).get('mean_score', 0),
                "attack_techniques": self.results.get('attack_map', {}).get('technique_count', 0),
                "cve_intel_kev": self.results.get('cve_intel', {}).get('kev_count', 0),
                "cve_intel_live": self.results.get('cve_intel', {}).get('live_enriched', 0),
                "takeover_v3_risks": self.results.get('takeover_v3', {}).get('risk_count', 0),
                "watch_changes": self.results.get('watch', {}).get('added_total', 0),
            },
            "http": {k: v for k, v in self.scalar_results.items() if k != 'http_headers'},
            "headers": self.scalar_results.get('http_headers', {}),
            "security_headers": self.results['security_headers'],
            "missing_security_headers": self.results['missing_security_headers'],
            "dns": self.results['dns'],
            "subdomains": sorted(set(self.results['subdomains'])),
            "open_ports": _norm_ports(self.results['ports']),
            "ports_detail": self.results.get('port_details', []),
            "paths": _norm_paths(self.results['paths']),
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
                "disclaimer": self.results.get('compliance', {}).get('disclaimer', 'Indicative Technical Control Mapping — not a certification/compliance attestation'),
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
            "katana": {
                "available": self.results.get('katana', {}).get('available', False),
                "binary": self.results.get('katana', {}).get('binary', ''),
                "version": self.results.get('katana', {}).get('version', ''),
                "depth": self.results.get('katana', {}).get('depth', 0),
                "urls_crawled": self.results.get('katana', {}).get('urls_crawled', 0),
                "js_files": self.results.get('katana', {}).get('js_files', []),
                "endpoints": self.results.get('katana', {}).get('endpoints', []),
                "note": self.results.get('katana', {}).get('note', ''),
            },
            "linkfinder": {
                "available": self.results.get('linkfinder', {}).get('available', False),
                "js_analyzed": self.results.get('linkfinder', {}).get('js_analyzed', 0),
                "external_cli": self.results.get('linkfinder', {}).get('external_cli', False),
                "ext_found": self.results.get('linkfinder', {}).get('ext_found', 0),
                "count": self.results.get('linkfinder', {}).get('count', 0),
                "endpoints": self.results.get('linkfinder', {}).get('endpoints', []),
                "sources": self.results.get('linkfinder', {}).get('sources', {}),
            },
            "ffuf": {
                "available": self.results.get('ffuf', {}).get('available', False),
                "binary": self.results.get('ffuf', {}).get('binary', ''),
                "fuzz_url": self.results.get('ffuf', {}).get('fuzz_url', ''),
                "wordlist_size": self.results.get('ffuf', {}).get('wordlist_size', 0),
                "count": self.results.get('ffuf', {}).get('count', 0),
                "note": self.results.get('ffuf', {}).get('note', ''),
                "findings": self.results.get('ffuf', {}).get('findings', []),
            },
            "burp_caido": {
                "proxy": self.results.get('burp', {}).get('proxy', ''),
                "proxy_ok": self.results.get('burp', {}).get('proxy_ok', False),
                "proxy_note": self.results.get('burp', {}).get('proxy_note', ''),
                "har_files": self.results.get('burp', {}).get('har_files', []),
                "har_entries": self.results.get('burp', {}).get('har_entries', 0),
                "endpoints": self.results.get('burp', {}).get('endpoints', []),
                "params": self.results.get('burp', {}).get('params', []),
                "cookies": self.results.get('burp', {}).get('cookies', []),
                "auth_headers": self.results.get('burp', {}).get('auth_headers', []),
                "js_files": self.results.get('burp', {}).get('js_files', []),
                "secrets": self.results.get('burp', {}).get('secrets', []),
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('proxy_findings', [])],
            },
            "api_pool": self.results.get('api_pool', []),
            "auth_setup": self.results.get('auth_setup', {}),
            "authscan": self.results.get('authscan', {}),
            "admin_api": {
                "findings": [{"severity": s, "check": c, "detail": d}
                             for s, c, d in self.results.get('admin_findings', [])],
            },
            "ssrf": self.results.get('ssrf', {}),
            "vuln_verify": self.results.get('vuln_verify', {}),
            "smartfuzz": self.results.get('smartfuzz', {}),
            "scan_diff": self.results.get('diff', {"available": False}),
            "remediation": self.results.get('patch', {}),
            "poc_verification": self.results.get('poc', {}),
            "notifications": self.results.get('notify', {}),
            "executive_report": self.results.get('exec', {}),
            "dedupe": self.results.get('dedupe_stats', {}),
            "js_secret": self.results.get('js_secret', {}),
            "wayback": self.results.get('wayback', {}),
            "params": self.results.get('param', {}),
            "graphql": self.results.get('graphql', {}),
            "cloud_storage": self.results.get('cloud', {}),
            "cvss": self.results.get('cvss', {}),
            "mitre_attack": self.results.get('attack_map', {}),
            "cve_intel": self.results.get('cve_intel', {}),
            "takeover_v3": self.results.get('takeover_v3', {}),
            "watch": self.results.get('watch', {}),
            "ruleset": (self.ruleset.summary() if getattr(self, "ruleset", None)
                        else {"files": [], "cve_rules": 0, "misconfig_rules": 0, "errors": []}),
            "plugins": (self.plugins.summary() if getattr(self, "plugins", None)
                        else {"files": [], "loaded": 0, "findings": 0, "errors": []}),
            "plugin_runs": self.results.get('plugin_runs', []),
            "timeline": (self.timeline_db.stats() if getattr(self, "timeline_db", None)
                         else {"enabled": False}),
            "retries": (getattr(getattr(self, "_retry_transport", None), "retries", 0) or 0),
            "evasion": {
                "level": getattr(self, "evade_level", "none") or "none",
                "requests_rewritten": (getattr(getattr(self, "_evasion_transport", None),
                                              "requests", 0) or 0),
                "rotate_every": getattr(self, "evade_rotate_every", 1),
            },
            "verification": (self.results.get('verify_stats', {}) if getattr(self, "deep_verify", False)
                             else {}),
            "verify_dropped": self.results.get('verify_dropped', []),
            "errors": self.results['errors'],
        }
        return out

    # ---------------------------------------------------------- HTML Export
    def export_html(self, path):
        """Generate a standalone dark-themed HTML report (no external assets)."""
        html_doc = self._render_html(self.export_dict())
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(html_doc)
        return path

    @staticmethod
    def _render_html(d):
        """Render a report dict to a standalone dark-themed HTML document (no external assets).

        Accepts both a raw ``-o`` export and a ``~/.nullveil/history`` entry
        (which wraps the same report under a ``report`` key).
        """
        from html import escape as _e

        if isinstance(d, dict) and isinstance(d.get("report"), dict):
            d = d["report"]          # unwrap history entry
        s = d['summary']
        risk = _risk_meter(d.get('secrets', []),
                           len(d.get('missing_security_headers', [])),
                           [p for p in d.get('paths', []) if str(p.get('status')) in ('200', '403')])
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
            chips = "".join(
                f"<span class='chip green'>{_e(str(p.get('port', p.get('number', p))))}"
                f" ({_e(str(p.get('service', p.get('name', '?'))))})</span>"
                if isinstance(p, dict) else f"<span class='chip green'>{_e(str(p))}</span>"
                for p in ports)
            parts.append(sec("Open Ports", "<div class='chips'>" + chips + "</div>", "#22c55e"))
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
                                       "<span class='chip yellow'>YES ⚠</span>" if p.get('reflected') else "no"]
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
                parts.append(sec(f"Nuclei Scan (v{nuc.get('version','?')}) — {len(nf)} finding(s)",
                                 tbl(["Severity", "ID", "Detail"],
                                     [[f"<span class='chip {'red' if f['severity'] in ('CRITICAL','HIGH') else ('yellow' if f['severity']=='MEDIUM' else 'green')}'>{_e(f['severity'])}</span>",
                                       _e(f['id']), _e(str(f['detail'])[:140])] for f in nf[:80]]), "#ef4444"))
            elif nuc.get('note'):
                parts.append(sec("Nuclei Scan", f"<p class='muted'>{_e(nuc['note'])}</p>", "#64748b"))
        # Katana crawler
        kat = d.get('katana', {})
        if kat and (kat.get('urls_crawled') or kat.get('note')):
            if kat.get('urls_crawled'):
                eps = kat.get('endpoints', [])
                inner = (f"<p><b>{kat.get('urls_crawled',0)}</b> URLs crawled · "
                         f"<b>{len(eps)}</b> API endpoints · <b>{len(kat.get('js_files',[]))}</b> JS files "
                         f"(katana v{_e(str(kat.get('version','?')))})</p>")
                if eps:
                    inner += tbl(["Endpoint"], [[_e(e)] for e in eps[:120]])
                parts.append(sec("Katana Crawler (API Discovery)", inner, "#06b6d4"))
            else:
                parts.append(sec("Katana Crawler", f"<p class='muted'>{_e(kat.get('note',''))}</p>", "#64748b"))
        # LinkFinder JS endpoints
        lf = d.get('linkfinder', {})
        if lf and lf.get('count'):
            src_note = "external linkfinder CLI" if lf.get('external_cli') else "built-in LinkFinder regex engine"
            rows = [[_e(e)] for e in lf.get('endpoints', [])[:150]]
            parts.append(sec(f"LinkFinder JS Endpoints ({lf.get('count',0)}) — {lf.get('js_analyzed',0)} JS via {src_note}",
                             tbl(["Endpoint"], rows) if rows else "", "#d946ef"))
        # FFUF fuzzing
        ff = d.get('ffuf', {})
        if ff and (ff.get('count') or ff.get('note')):
            if ff.get('count'):
                rows = [[f"<span class='chip {'green' if str(x.get('status','')).startswith('2') else ('yellow' if str(x.get('status','')).startswith(('3','4')) else 'red')}'>{_e(str(x.get('status','')))}</span>",
                         _e(str(x.get('url',''))[:120]), _e(str(x.get('size',''))),
                         _e(str(x.get('content_type',''))[:40])] for x in ff.get('findings', [])[:100]]
                parts.append(sec(f"FFUF API Fuzzing — {ff.get('count',0)} live path(s)",
                                 tbl(["Status", "URL", "Size", "Type"], rows), "#3b82f6"))
            elif ff.get('note'):
                parts.append(sec("FFUF API Fuzzing", f"<p class='muted'>{_e(ff['note'])}</p>", "#64748b"))
        # Burp / Caido traffic bridge
        bur = d.get('burp_caido', {})
        if bur and (bur.get('proxy') or bur.get('har_entries') or bur.get('proxy_note')):
            head = ""
            if bur.get('proxy'):
                head += (f"<p>Proxy: <b>{_e(str(bur['proxy']))}</b> — "
                         + ("<span class='chip green'>capture active</span>" if bur.get('proxy_ok')
                            else "<span class='chip red'>unreachable</span>")
                         + f" <span class='muted'>{_e(str(bur.get('proxy_note', '')))}</span></p>")
            if bur.get('har_files'):
                head += (f"<p>HAR import: <b>{bur.get('har_entries', 0)}</b> entries from "
                         f"<b>{len(bur['har_files'])}</b> file(s) · <b>{len(bur.get('endpoints', []))}</b> endpoint(s) · "
                         f"<b>{len(bur.get('params', []))}</b> parameter(s) · <b>{len(bur.get('cookies', []))}</b> cookie(s)</p>")
                if bur.get('endpoints'):
                    head += tbl(["Captured endpoint"], [[_e(str(e)[:160])] for e in bur['endpoints'][:150]])
                if bur.get('secrets'):
                    head += "<h3>Secrets in captured responses</h3>" + tbl(
                        ["Secret"], [[_e(str(s)[:160])] for s in bur['secrets'][:40]])
            parts.append(sec("Burp / Caido Traffic Bridge", head, "#eab308"))
        # Authenticated scan (session injection + role diff)
        asc = d.get('authscan', {})
        ainfo = d.get('auth_setup', {}) or {}
        if asc and (asc.get('available') or asc.get('note')):
            if asc.get('available'):
                head = (f"<p>Headers: <b>{_e(', '.join(ainfo.get('headers', [])) or '-')}</b> · "
                        f"Cookies: <b>{_e(', '.join(ainfo.get('cookies', [])) or '-')}</b> · "
                        f"Probed: <b>{asc.get('endpoints_probed', 0)}</b> · "
                        f"Auth-gated: <b>{asc.get('auth_gated', 0)}</b> · "
                        f"Status changed: <b>{asc.get('status_changed', 0)}</b>"
                        + (" · <span class='chip green'>session verified</span>"
                           if asc.get('session_verified') else "") + "</p>")
                rows = [[_e(str(x.get('path', ''))[:140]), _e(str(x.get('status_noauth'))),
                         _e(str(x.get('status_auth'))), _e(str(x.get('size_auth')))]
                        for x in asc.get('findings', [])[:120]
                        if x.get('auth_gated') or x.get('status_noauth') != x.get('status_auth')]
                if rows:
                    head += tbl(["Endpoint", "No-auth", "Auth", "Size (auth)"], rows)
                gated = asc.get('role_gated', [])
                if gated:
                    head += "<h3>Role-hidden APIs</h3>" + tbl(
                        ["Endpoint", "Visible to", "Hidden from"],
                        [[_e(str(g.get('path', ''))[:140]), _e(', '.join(g.get('visible_to', []))),
                          _e(', '.join(f"{h.get('role')}:{h.get('status')}"
                                       for h in g.get('hidden_from', [])))]
                         for g in gated[:100]])
                parts.append(sec("Authenticated API Scan", head, "#ef4444"))
            elif asc.get('note'):
                parts.append(sec("Authenticated API Scan",
                                 f"<p class='muted'>{_e(asc['note'])}</p>", "#64748b"))
        # SSRF / internal pivot
        ssr = d.get('ssrf', {})
        if ssr and ssr.get('available'):
            head = (f"<p>Endpoints: <b>{ssr.get('endpoints', 0)}</b> · "
                    f"bypass response diffs: <b>{ssr.get('bypass_count', 0)}</b> · "
                    f"metadata hits: <b>{len(ssr.get('metadata', []))}</b></p>")
            bps = [b for b in ssr.get('bypass', [])
                   if str(b.get('verdict', '')).startswith('possible')][:60]
            if bps:
                head += tbl(["Endpoint", "Header", "Baseline→New", "Verdict"],
                            [[_e(str(b.get('path', ''))[:100]), _e(str(b.get('header', ''))[:80]),
                              _e(f"{b.get('baseline_status')}→{b.get('status')}"),
                              _e(str(b.get('verdict', '')))] for b in bps])
            mds = ssr.get('metadata', [])[:40]
            if mds:
                head += "<h3>Cloud metadata probe hits</h3>" + tbl(
                    ["Path", "Status", "Header", "Signature"],
                    [[_e(str(m.get('path', ''))), _e(str(m.get('status', ''))),
                      _e(str(m.get('header', ''))[:60]),
                      "yes" if m.get('signature') else "-"] for m in mds])
            oob = ssr.get('oob', {}) or {}
            if oob.get('enabled'):
                head += (f"<p class='muted'>OOB domain: <b>{_e(str(oob.get('domain', '?')))}</b> · "
                         f"{oob.get('injected', 0)} probe(s) · {_e(str(oob.get('note', '')))}</p>")
                if oob.get('hits'):
                    head += ("<h3>OOB interactions</h3><pre>"
                             + _e("\n".join(str(h) for h in oob['hits'][:30])) + "</pre>")
            parts.append(sec("SSRF & Internal Pivot", head, "#ef4444"))
        # Smart context fuzz
        smf = d.get('smartfuzz', {})
        if smf and smf.get('available'):
            head = (f"<p>Business profile: <b>{_e(', '.join(smf.get('business_profile', [])) or '?')}</b> "
                    f"<span class='muted'>{_e(str(smf.get('keyword_hits', {})))}</span><br>"
                    f"Generated wordlist: <b>{smf.get('wordlist_size', 0)}</b> "
                    f"(engine: {_e(str(smf.get('engine', '')))}) · "
                    f"JS analyzed: <b>{smf.get('js_analyzed', 0)}</b> → candidates "
                    f"<b>{len(smf.get('js_endpoints', []))}</b>, "
                    f"live <b>{len(smf.get('js_resolved', []))}</b></p>")
            if smf.get('js_resolved'):
                head += tbl(["JS data-flow endpoint", "Status", "Size"],
                            [[_e(str(j.get('path', ''))[:140]), _e(str(j.get('status', ''))),
                              _e(str(j.get('size', '')))] for j in smf['js_resolved'][:60]])
            if smf.get('external_bases'):
                head += ("<p class='muted'>external API bases: "
                         + _e(', '.join(smf['external_bases'][:10])) + "</p>")
            sf = smf.get('findings', [])
            if sf:
                rows = [[f"<span class='chip {'green' if str(x.get('status', '')).startswith('2') else ('yellow' if str(x.get('status', '')).startswith(('3', '4')) else 'red')}'>{_e(str(x.get('status', '')))}</span>",
                         _e(str(x.get('url', ''))[:120]), _e(str(x.get('size', ''))),
                         _e(str(x.get('source', ''))[:30])] for x in sf[:100]]
                head += tbl(["Status", "URL", "Size", "Source"], rows)
            parts.append(sec(f"Smart Context Fuzz — {smf.get('count', 0)} live path(s)",
                             head, "#3b82f6"))
        # Unified API pool
        pool = d.get('api_pool', [])
        if pool:
            src_map = {}
            for e in pool:
                p = str(e.get('path', ''))
                if p:
                    src_map.setdefault(p, set()).add(str(e.get('source', '')))
            if src_map:
                rows = [[_e(p[:140]), _e(', '.join(sorted(s))[:80])] for p, s in list(src_map.items())[:160]]
                parts.append(sec(f"Unified API Pool ({len(src_map)} unique endpoint(s))",
                                 tbl(["Endpoint", "Source(s)"], rows), "#22c55e"))
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
    Duration: {_e(str(round(d.get('duration_s') or 0, 1)))}s · Modules: {_e(', '.join(d.get('modules_run', [])) or '-')} ·
    Version {_e(str(d.get('version', '')))}
  </div>
</header>
<main>
  <div class="meter">
    <div class="muted">EXPOSURE LEVEL</div>
    <div class="bar"><div style="width:{score}%"></div></div>
    <div class="score">{score}/100 — {verdict}</div>
    <div class="muted">Risk: {level} · Secrets: {s.get('secrets',0)} ·
      Missing headers: {len(d.get('missing_security_headers', []))} ·
      Flagged paths: {len([p for p in d.get('paths', []) if str(p.get('status')) in ('200','403')])}</div>
  </div>
  {"".join(parts)}
</main>
<footer>
  Generated by <strong>NULLVEIL Recon</strong> v{_e(str(d.get('version','')))} · Owner: NULLVEIL · Engine: DeepHat<br>
  Authorized testing only. This report may contain sensitive data — handle with care.
</footer>
</body>
</html>"""
        return html_doc

    @staticmethod
    def render_html_from_dict(d, path):
        """Render an arbitrary saved report dict (e.g. old JSON) to HTML."""
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(WebsiteRecon._render_html(d))
        return path

    # ---------------------------------------------------------- PDF Export
    @staticmethod
    def _html_to_pdf(html_doc, pdf_path):
        """Render an HTML document to a client-ready PDF via headless Chromium.
        Uses the same optional dependency as screenshots (playwright).
        Returns (ok: bool, message: str)."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False, ("playwright not installed — run: pip install playwright && "
                           "playwright install chromium")
        try:
            import glob as _glob
            _cache = os.path.expanduser("~/.cache/ms-playwright")
            if not _glob.glob(os.path.join(_cache, "chromium*")):
                return False, "browser binary not downloaded — run: playwright install chromium"
        except Exception:
            pass

        async def _go():
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True,
                                                   args=["--no-sandbox", "--disable-gpu"])
                try:
                    page = await browser.new_page()
                    await page.set_content(html_doc, wait_until="load")
                    await page.pdf(path=pdf_path, format="A4", print_background=True,
                                   margin={"top": "12mm", "bottom": "12mm",
                                           "left": "10mm", "right": "10mm"})
                finally:
                    await browser.close()

        try:
            asyncio.run(_go())
            return True, pdf_path
        except Exception as e:
            return False, f"PDF render failed ({type(e).__name__}) — {e}"

    def export_pdf(self, path):
        """Save this scan as a client-ready PDF (renders the branded HTML report)."""
        return self._html_to_pdf(self._render_html(self.export_dict()), path)

    @classmethod
    def pdf_from_dict_file(cls, json_path, pdf_path):
        """Convert an existing NULLVEIL JSON report into a PDF."""
        with open(json_path, encoding="utf-8") as fh:
            d = json.load(fh)
        return cls._html_to_pdf(cls._render_html(d), pdf_path)



# ---------------------------------------------------------- Web Dashboard
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NULLVEIL · Recon Dashboard</title>
<style>
  :root{--bg:#080c18;--panel:#0f1626;--panel2:#131c30;--line:#1e2942;--txt:#dbe4f3;--mut:#7b8aa6;
        --cri:#ef4444;--hig:#f97316;--med:#eab308;--low:#38bdf8;--inf:#64748b;--ok:#22c55e;--acc:#a855f7;--cy:#22d3ee}
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 700px at 75% -10%,#22104080,transparent),var(--bg);
       color:var(--txt);font:14px/1.5 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif}
  header{display:flex;align-items:center;gap:18px;padding:14px 22px;border-bottom:1px solid var(--line);
         background:#0a1020cc;backdrop-filter:blur(8px);position:sticky;top:0;z-index:9}
  .brand{font-weight:800;letter-spacing:3px;font-size:19px}
  .brand span{background:linear-gradient(90deg,var(--acc),var(--cy));-webkit-background-clip:text;background-clip:text;color:transparent}
  .tag{color:var(--mut);font-size:11px;letter-spacing:2px;text-transform:uppercase}
  .grow{flex:1}
  input,button{background:var(--panel);color:var(--txt);border:1px solid var(--line);border-radius:9px;
               padding:9px 13px;font:inherit;outline:none}
  input:focus{border-color:var(--acc)}
  button{cursor:pointer;transition:.15s} button:hover{border-color:var(--acc);color:#fff}
  .layout{display:grid;grid-template-columns:290px 1fr;min-height:calc(100vh - 58px)}
  aside{border-right:1px solid var(--line);padding:12px;overflow:auto;max-height:calc(100vh - 58px)}
  .scan{padding:10px 12px;border:1px solid transparent;border-radius:10px;cursor:pointer;margin-bottom:6px}
  .scan:hover{background:var(--panel)}
  .scan.on{background:var(--panel2);border-color:var(--acc)}
  .scan .t{font-weight:600;display:flex;justify-content:space-between;gap:8px}
  .scan .m{color:var(--mut);font-size:11px;margin-top:3px;display:flex;gap:10px;flex-wrap:wrap}
  main{padding:20px 24px 70px;overflow:auto}
  .kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin:6px 0 18px}
  .kpi{background:linear-gradient(180deg,var(--panel),#0d1424);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
  .kpi .v{font-size:26px;font-weight:800} .kpi .l{color:var(--mut);font-size:11px;letter-spacing:1.4px;text-transform:uppercase}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:16px}
  .card h2{margin:0 0 12px;font-size:12px;letter-spacing:1.6px;text-transform:uppercase;color:#c9d6ee}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
  tr:hover td{background:#0e1729}
  .chip{display:inline-block;padding:1px 9px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.4px}
  .CRITICAL{background:#ef444422;color:var(--cri)} .HIGH{background:#f9731622;color:var(--hig)}
  .MEDIUM{background:#eab30822;color:var(--med)} .LOW{background:#38bdf822;color:var(--low)}
  .INFO{background:#64748b22;color:var(--inf)}
  .chip.mod{background:#a855f722;color:#c4a6ff;margin:2px}
  .bars{display:flex;flex-direction:column;gap:7px;margin-top:4px}
  .barrow{display:grid;grid-template-columns:74px 1fr 46px;align-items:center;gap:10px;font-size:12px}
  .track{height:11px;background:#16203a;border-radius:6px;overflow:hidden}
  .track>i{display:block;height:100%;border-radius:6px}
  .meter{margin:2px 0 16px}
  .meter .top{display:flex;justify-content:space-between;align-items:baseline}
  .meter .score{font-size:30px;font-weight:800}
  .meter .track{height:16px;margin-top:8px}
  .grid2{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
  .shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
  .shot{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#0a0f1c}
  .shot img{width:100%;display:block}
  .shot .cap{padding:7px 10px;font-size:11px;color:var(--mut);word-break:break-all}
  ul{margin:4px 0;padding-left:18px} li{margin:2px 0;word-break:break-all}
  code{background:#0a1120;padding:1px 6px;border-radius:5px;color:var(--cy);font-size:.9em}
  .mut{color:var(--mut)} .empty{color:var(--mut);text-align:center;margin-top:120px;font-size:15px}
  h3{font-size:12px;text-transform:uppercase;letter-spacing:1.4px;color:var(--mut);margin:18px 0 8px}
  .err{color:#fca5a5}
</style>
</head>
<body>
<header>
  <div>
    <div class="brand"><span>NULLVEIL</span></div>
    <div class="tag">Recon Dashboard · Engine DeepHat</div>
  </div>
  <div class="grow"></div>
  <input id="q" placeholder="filter findings…" style="width:230px">
  <button id="refresh">↻ Refresh</button>
  <button id="dl-pdf" title="Download the executive PDF (module 39) for the selected scan">⬇ Executive PDF</button>
</header>
<div class="layout">
  <aside id="list"></aside>
  <main id="main"><div class="empty">Select a scan from the left panel →</div></main>
</div>
<script>
const SEV_ORDER=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const SEV_COLOR={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#38bdf8',INFO:'#64748b'};
const e=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let SCANS=[],DATA=null;

async function loadScans(){
  const r=await fetch('/api/scans');const j=await r.json();SCANS=j.scans||[];
  document.getElementById('list').innerHTML = SCANS.length? SCANS.map(s=>{
    const n=(s.summary&&(s.summary.cve_issues+s.summary.audit_issues+s.summary.supply_issues+s.summary.nuclei_issues>0||0))||0;
    const tot=findCount(s.summary);
    return `<div class="scan" data-id="${e(s.id)}">
      <div class="t"><span>${e(s.target)}</span><span class="chip ${tot.cri?'CRITICAL':(tot.hig?'HIGH':'INFO')}">${tot.all}</span></div>
      <div class="m"><span>${e((s.when||'').slice(0,16).replace('T',' '))}</span>
      <span>${(s.modules||[]).length} modules</span><span>${s.duration_s||0}s</span></div></div>`;
  }).join('') : '<div class="mut" style="padding:10px">No scans yet. Run a scan first — every scan auto-saves.</div>';
  document.querySelectorAll('.scan').forEach(el=>el.onclick=()=>openScan(el.dataset.id));
  if(SCANS.length && !DATA) openScan(SCANS[0].id);
}
function findCount(s){ s=s||{}; const keys=['cve_issues','audit_issues','supply_issues','nuclei_issues','anomaly_issues','intel_issues','breach_issues','tls_issues','email_issues','ssrf_bypass_hits'];
  let cri=0,hig=0,all=0; keys.forEach(k=>{all+=(s[k]||0)}); return {all,cri:s.cve_issues||0,hig:s.supply_issues||0}; }

function findings(d){
  const out=[];
  const push=(section,arr,idKey)=>{(arr||[]).forEach(f=>{
    const sev=(f.severity||'INFO').toUpperCase();
    out.push({section,sev,id:f.id||f.check||'',detail:f.detail||f.title||f.message||'',evidence:f.evidence||''});
  })};
  push('API Audit',d.api_audit&&d.api_audit.findings);
  push('External Intel',d.external_intel&&d.external_intel.findings);
  push('CVE',d.cve&&d.cve.findings);
  push('TLS',d.tls&&d.tls.findings);
  push('Supply Chain',d.supply_chain&&d.supply_chain.findings);
  push('Anomaly',d.anomaly&&d.anomaly.findings);
  push('Threat Intel',d.threat_intel&&d.threat_intel.findings);
  push('Breach',d.breach&&d.breach.findings);
  push('Correlation',d.correlation&&d.correlation.findings);
  push('Nuclei',d.nuclei&&d.nuclei.findings);
  push('Burp / Caido',d.burp_caido&&d.burp_caido.findings);
  push('Scan Diff',d.scan_diff&&d.scan_diff.findings);
  push('Admin API',d.admin_api&&d.admin_api.findings);
  push('Email',d.email_security&&d.email_security.findings);
  push('Remediation',(d.remediation&&d.remediation.patches||[]).map(p=>({severity:p.severity,check:p.title,detail:p.finding})));
  push('PoC Verify',(d.poc_verification&&d.poc_verification.pocs||[]).map(p=>({severity:p.severity,check:p.check,detail:p.finding})));
  push('JS Secret',d.js_secret&&d.js_secret.findings);
  push('Historical URL',d.wayback&&d.wayback.findings);
  push('Hidden Param',d.params&&d.params.findings);
  push('GraphQL',d.graphql&&d.graphql.findings);
  push('Cloud Storage',d.cloud_storage&&d.cloud_storage.findings);
  push('CVSS',d.cvss&&d.cvss.findings);
  push('ATT&CK',d.mitre_attack&&d.mitre_attack.findings);
  push('CVE Intel',d.cve_intel&&d.cve_intel.findings);
  push('Takeover v3',d.takeover_v3&&d.takeover_v3.findings);
  push('Watch',d.watch&&d.watch.findings);
  out.sort((a,b)=>SEV_ORDER.indexOf(a.sev)-SEV_ORDER.indexOf(b.sev));
  return out;
}

async function openScan(id){
  document.querySelectorAll('.scan').forEach(el=>el.classList.toggle('on',el.dataset.id===id));
  const r=await fetch('/api/scan?id='+encodeURIComponent(id)); if(!r.ok)return;
  DATA=await r.json(); DATA.__id=id; render(DATA);
}
function render(d){
  const s=d.summary||{}, F=findings(d);
  const crit=F.filter(f=>f.sev==='CRITICAL').length, high=F.filter(f=>f.sev==='HIGH').length,
        med=F.filter(f=>f.sev==='MEDIUM').length;
  let score=Math.min(100, crit*22+high*10+med*4+(s.secrets||0)*12+(s.takeover_risks||0)*25);
  const verdict = score>=70?'CRITICAL EXPOSURE':score>=40?'HIGH EXPOSURE':score>=15?'MODERATE':'LOW RISK';
  const color = score>=70?'var(--cri)':score>=40?'var(--hig)':score>=15?'var(--med)':'var(--ok)';
  const cnt=sev=>F.filter(f=>f.sev===sev).length;
  const maxc=Math.max(1,...SEV_ORDER.map(cnt));
  const shots=(d.screenshots&&d.screenshots.shots)||[];
  const chains=(d.attack_graph&&d.attack_graph.chains)||[];
  const comp=d.compliance||{};

  let html=`
  <div class="meter">
    <div class="top"><div><div class="tag">Exposure level</div>
      <div class="score" style="color:${color}">${score}<span class="mut" style="font-size:16px">/100</span></div></div>
      <div style="text-align:right"><div class="tag">Target</div>
        <div style="font-weight:700;font-size:16px">${e(d.target)}</div>
        <div class="mut" style="font-size:12px">${e((d.started||'').slice(0,19).replace('T',' '))} · v${e(d.version)} · ${e(d.mode)}</div>
        <div style="margin-top:8px">
          <button onclick="window.location='/api/exec-pdf?id='+encodeURIComponent(d.__id)">⬇ Executive PDF</button>
          <button onclick="window.location='/api/exec-pdf?id='+encodeURIComponent(d.__id)+'&format=html'">⬇ HTML</button>
        </div></div></div>
    <div class="track"><i style="width:${score}%;background:${color}"></i></div>
    <div style="margin-top:6px;font-weight:700;color:${color}">${verdict}</div>
  </div>
  <div class="kpis">
    ${kpi(crit,'Critical','var(--cri)')}${kpi(high,'High','var(--hig)')}${kpi(med,'Medium','var(--med)')}
    ${kpi(s.secrets||0,'Secrets leaked','var(--cri)')}${kpi(s.subdomains||0,'Subdomains')}
    ${kpi(s.open_ports||0,'Open ports')}${kpi(s.takeover_risks||0,'Takeover risks')}
    ${kpi(chains.length,'Attack chains')}${kpi(shots.length,'Screenshots')}
    ${kpi((s.diff_new_assets||0),'New since last scan',(s.diff_score>=40?'var(--hig)':''))}
    ${kpi((comp.coverage_pct||0)+'%','Compliance')}
  </div>
  <div class="grid2">
    <div class="panel">
      <h3>Severity distribution</h3>
      <div class="bars">${SEV_ORDER.map(v=>`<div class="barrow"><span>${v}</span>
        <div class="track"><i style="width:${(cnt(v)/maxc*100).toFixed(1)}%;background:${SEV_COLOR[v]}"></i></div>
        <span class="mut" style="text-align:right">${cnt(v)}</span></div>`).join('')}</div>
      <h3>Modules run (${(d.modules_run||[]).length})</h3>
      <div>${(d.modules_run||[]).map(m=>`<span class="chip mod">${e(m)}</span>`).join('')}</div>
    </div>
    <div class="panel">
      <h3>Attack surface</h3>
      <div class="kv">
        <div><span class="mut">IPs</span><b>${(d.ips||[]).length}</span></div>
        <div><span class="mut">Emails</span><b>${(d.emails||[]).length}</b></div>
        <div class="mut" style="font-size:11px">${(d.tech_stack||[]).slice(0,14).map(e).join(' · ')}</div>
      </div>
      <h3>Compliance coverage</h3>
      ${comp.frameworks? Object.entries(comp.frameworks).map(([k,v])=>`<div class="barrow"><span>${e(k)}</span>
        <div class="track"><i style="width:${(v.coverage_pct||0)}%;background:var(--acc)"></i></div>
        <span class="mut" style="text-align:right">${v.coverage_pct||0}%</span></div>`).join('') : '<div class="mut">not run</div>'}
      <h3>Email security</h3>
      <ul><li>SPF: <code>${e((d.email_security&&d.email_security.spf)||'none')}</code></li>
      <li>DMARC: <code>${e((d.email_security&&d.email_security.dmarc)||'none')}</code></li></ul>
    </div>
  </div>

  <h3>Findings (${F.length})</h3>
  <div id="ftable"></div>

  ${chains.length?`<h3>Attack chain hypotheses (${chains.length})</h3><div class="panel">${
     chains.map(c=>`<div style="margin-bottom:10px"><span class="chip ${c.severity||'HIGH'}">${e(c.severity||'')}</span>
       <b style="margin-left:8px">${e(c.name||c.title||'chain')}</b>
       <div class="mut" style="font-size:12px;margin-top:3px">${e(c.narrative||c.detail||'')}</div></div>`).join('')}</div>`:''}

  ${shots.length?`<h3>Screenshots (${shots.length})</h3><div class="shots">${
     shots.map((x,i)=>x.file?`<div class="shot"><img loading="lazy" src="/api/shot?id=${encodeURIComponent(d.__id)}&i=${i}">
       <div class="cap">${e(x.status||'')} · ${e(x.url||'')}</div></div>`:'').join('')}</div>`:''}

  ${(d.scan_diff&&d.scan_diff.available)?`<h3>Changes since last scan <span class="mut" style="font-size:12px">· baseline ${e((d.scan_diff.baseline_when||'').slice(0,16).replace('T',' '))} · score ${e(d.scan_diff.score||0)}/100 · ${e(d.scan_diff.verdict||'')}</span></h3>
    <div class="panel">${(d.scan_diff.findings||[]).length?(d.scan_diff.findings||[]).map(f=>`<div style="margin-bottom:8px">
      <span class="chip ${e((f.severity||'INFO').toUpperCase())}">${e((f.severity||'INFO').toUpperCase())}</span>
      <b style="margin-left:8px">${e(f.check||'')}</b>
      <div class="mut" style="font-size:12px;margin-top:3px">${e(f.detail||'')}</div>
      ${(f.items||[]).length?`<div style="margin-top:4px">${(f.items||[]).slice(0,40).map(x=>`<span class="chip mod">${e(x)}</span>`).join('')}</div>`:''}
    </div>`).join(''):'<div class="mut">No new assets since the last scan.</div>'}</div>`:''}

  ${(d.remediation&&d.remediation.generated)?`<h3>Remediation plan (${d.remediation.generated})</h3><div class="panel">${
     (d.remediation.patches||[]).slice(0,30).map(p=>`<div style="margin-bottom:10px">
       <span class="chip ${e((p.severity||'INFO').toUpperCase())}">${e((p.severity||'INFO').toUpperCase())}</span>
       <b style="margin-left:8px">${e(p.title||'')}</b> <span class="mut">(${e(p.check||'')})</span>
       <div class="mut" style="font-size:12px;margin-top:3px">${e((p.finding||'').slice(0,180))}</div>
       <pre style="white-space:pre-wrap;font-size:11px;margin-top:4px;background:#0b1220;padding:8px;border-radius:6px">${e((p.remediation||'').slice(0,700))}</pre>
     </div>`).join('')}</div>`:''}

  ${(d.poc_verification&&d.poc_verification.generated)?`<h3>Read-only PoC verification (${d.poc_verification.generated})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(d.poc_verification.policy||'')}</div>${
     (d.poc_verification.pocs||[]).slice(0,25).map(p=>`<div style="margin-bottom:8px">
       <span class="chip ${e((p.severity||'INFO').toUpperCase())}">${e((p.severity||'INFO').toUpperCase())}</span>
       <b style="margin-left:8px">${e(p.check||'')}</b>
       ${(p.commands||[]).map(c=>`<pre style="white-space:pre-wrap;font-size:11px;margin-top:4px;background:#0b1220;padding:8px;border-radius:6px"># ${e(c.desc||'')}\n${e(c.cmd||'')}</pre>`).join('')}
     </div>`).join('')}</div>`:''}

  ${(d.js_secret&&d.js_secret.secret_count)?`<h3>JS secrets &amp; source maps (${d.js_secret.secret_count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(d.js_secret.policy||'')}</div>${
     (d.js_secret.secrets||[]).slice(0,20).map(s=>`<div style="margin-bottom:6px">
       <span class="chip ${e((s.severity||'INFO').toUpperCase())}">${e((s.severity||'INFO').toUpperCase())}</span>
       <b style="margin-left:8px">${e(s.type||'')}</b>
       <span class="mut" style="font-size:12px"> ${e(s.masked||'')} · ${e((s.source||'').slice(0,80))}</span>
     </div>`).join('')}</div>`:''}

  ${(d.wayback&&d.wayback.url_count)?`<h3>Historical URLs (${d.wayback.url_count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(d.wayback.note||'')} · sources: ${e((d.wayback.sources||[]).join(', '))}</div>
     <ul>${(d.wayback.interesting||[]).slice(0,40).map(u=>`<li><code style="font-size:12px">${e(u)}</code></li>`).join('')}</ul></div>`:''}

  ${(d.params&&d.params.count)?`<h3>Hidden parameters (${d.params.count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(d.params.policy||'')}</div>
     ${(d.params.params||[]).slice(0,40).map(p=>`<div style="margin-bottom:4px">
       <span class="chip ${p.type==='reflected'?'CRITICAL':'MEDIUM'}">${e(p.type||'')}</span>
       <b style="margin-left:8px">${e(p.name||'')}</b>
       <span class="mut" style="font-size:12px"> · ${e((p.url||'').slice(0,80))}</span></div>`).join('')}</div>`:''}

  ${(d.graphql&&d.graphql.count)?`<h3>GraphQL audit (${d.graphql.count})</h3><div class="panel">${
     (d.graphql.endpoints||[]).map(g=>`<div style="margin-bottom:8px">
       <b>${e(g.endpoint||'')}</b> <span class="mut">(${e(String(g.status||''))})</span>
       <div class="mut" style="font-size:12px">${g.introspection?'introspection exposed · ':''}${g.field_suggestions?'field suggestions · ':''}${g.depth_limited===false?'no depth limit · ':''}${e((g.issues||[]).join(', '))}</div>
     </div>`).join('')}</div>`:''}

  ${(d.cloud_storage&&d.cloud_storage.count)?`<h3>Cloud storage (${d.cloud_storage.count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(d.cloud_storage.policy||'')}</div>${
     (d.cloud_storage.buckets||[]).slice(0,30).map(b=>`<div style="margin-bottom:4px">
       <span class="chip ${b.public_listing||b.writable_probe?'CRITICAL':'INFO'}">${b.writable_probe?'WRITABLE?':(b.public_listing?'PUBLIC':'exists')}</span>
       <b style="margin-left:8px">${e(b.bucket||'')}</b> <span class="mut">${e(b.provider||'')}</span></div>`).join('')}</div>`:''}

  ${(d.cvss&&d.cvss.count)?`<h3>CVSS 4.0 / CWE risk register (${d.cvss.count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">mean CVSS ${e(String(d.cvss.mean_score||0))} · ${e(d.cvss.method||'')}</div>${
     (d.cvss.top||[]).slice(0,25).map(r=>`<div style="margin-bottom:6px">
       <span class="chip ${e((r.severity||'INFO').toUpperCase())}">${e((r.severity||'INFO').toUpperCase())}</span>
       <b style="margin-left:8px">${e(String(r.score||''))}</b>
       <span style="margin-left:8px">${e(r.check||'')}</span>
       <span class="mut" style="font-size:12px"> ${e(r.cwe||'')}${r.rebanded?(' · rebanded '+e(r.rebanded)):''}</span>
       <div class="mut" style="font-size:11px">${e(r.cvss4_vector||'')}</div>
     </div>`).join('')}</div>`:''}

  ${(d.mitre_attack&&d.mitre_attack.technique_count)?`<h3>MITRE ATT&amp;CK coverage (${d.mitre_attack.technique_count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(d.mitre_attack.note||'')}</div>${
     (d.mitre_attack.techniques||[]).slice(0,40).map(t=>`<div style="margin-bottom:4px">
       <span class="chip ${e((t.max_severity||'INFO').toUpperCase())}">${e((t.max_severity||'INFO').toUpperCase())}</span>
       <b style="margin-left:8px">${e(t.id||'')}</b> ${e(t.name||'')}
       <span class="mut" style="font-size:12px"> · ${e(t.tactic||'')} × ${e(String(t.count||0))}</span></div>`).join('')}</div>`:''}

  ${(d.cve_intel&&d.cve_intel.count)?`<h3>CVE intelligence (${d.cve_intel.count})</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${d.cve_intel.live?`<span class="chip INFO" style="background:#16a34a">LIVE NVD+EPSS</span> ${e(String(d.cve_intel.live_enriched||0))}/${e(String(d.cve_intel.count||0))} enriched · `:'<span class="chip INFO">offline curated</span> · '}KEV ${e(String(d.cve_intel.kev_count||0))} · mean CVSS ${e(String(d.cve_intel.cvss_mean||0))} · ${e(d.cve_intel.note||'')}</div>${
     (d.cve_intel.cves||[]).slice(0,30).map(c=>`<div style="margin-bottom:5px">
       <span class="chip ${c.kev?'CRITICAL':e((c.severity||'INFO').toUpperCase())}">${c.kev?'KEV':e((c.severity||'INFO').toUpperCase())}</span>
       <b style="margin-left:8px">${e(c.cve||'')}</b> <span class="mut">CVSS ${e(String(c.cvss||''))} · ${e(c.cwe||'')}${c.epss?(' · EPSS '+e(String(Math.round((c.epss||0)*100))+'%')):''} · ${e(c.source||'')}</span>
       ${c.exploit_available?'<span class="mut" style="color:#f97316"> · exploitable</span>':''}
       <div class="mut" style="font-size:11px">${e(c.desc||'')} · ${e(c.priority||'')}</div></div>`).join('')}</div>`:''}

  ${(d.takeover_v3&&d.takeover_v3.hosts_checked)?`<h3>Subdomain takeover v3 (${d.takeover_v3.risk_count} risk)</h3><div class="panel">
     <div class="mut" style="font-size:12px;margin-bottom:8px">${e(String(d.takeover_v3.hosts_checked||0))} CNAME host(s) · ${e(String(d.takeover_v3.providers||0))} fingerprints · ${e(d.takeover_v3.policy||'')}</div>${
     (d.takeover_v3.risks||[]).slice(0,30).map(r=>`<div style="margin-bottom:5px">
       <span class="chip ${e((r.severity||'INFO').toUpperCase())}">${e(r.status||'')}</span>
       <b style="margin-left:8px">${e(r.host||'')}</b> <span class="mut">→ ${e(r.service||'')}</span>
       <div class="mut" style="font-size:11px">${e((r.cname_chain||[]).join(' → '))}</div></div>`).join('')}</div>`:''}

  ${(d.watch&&d.watch.available)?`<h3>Continuous change monitor</h3><div class="panel">
     ${d.watch.baseline?`<div style="margin-bottom:8px"><span class="chip ${d.watch.verdict==='REGRESSION'?'CRITICAL':'INFO'}">${e(d.watch.verdict||'')}</span>
       <b style="margin-left:8px">${e(String(d.watch.added_total||0))} new · ${e(String(d.watch.removed_total||0))} removed</b>
       <span class="mut"> · risk Δ ${e(String(d.watch.risk_delta||0))} (baseline ${e(String(d.watch.baseline_when||'').slice(0,19))})</span></div>${
       (d.watch.findings||[]).slice(0,25).map(f=>`<div style="margin-bottom:3px">
         <span class="chip ${e((f.severity||'INFO').toUpperCase())}">${e((f.severity||'INFO').toUpperCase())}</span>
         <span style="margin-left:8px">${e(f.check||'')}</span> <span class="mut" style="font-size:12px">${e(f.detail||'')}</span></div>`).join('')}`
       :`<div class="mut">${e(d.watch.note||'')}</div>`}
  </div>`:''}

  <div class="grid2" style="margin-top:18px">
    <div class="panel"><h3>Assets</h3>
      <h4 class="tag">Subdomains</h4><ul>${list(d.subdomains,40)}</ul>
      <h4 class="tag">Open ports</h4><ul>${list(portList(d.open_ports),30)}</ul>
    </div>
    <div class="panel"><h3>Secrets & intel</h3>
      <h4 class="tag">Secrets (masked)</h4><ul>${list(d.secrets,30)}</ul>
      <h4 class="tag">Tech stack</h4><ul>${list(d.tech_stack,40)}</ul>
    </div>
  </div>
  ${(d.errors&&d.errors.length)?`<h3>Notes / errors</h3><div class="panel err">${list(d.errors,40)}</div>`:''}
  `;  document.getElementById('main').innerHTML=html;
  renderFindings(F);
  document.getElementById('q').oninput=()=>renderFindings(F);
}
function kpi(v,l,col){return `<div class="kpi"><div class="tag">${e(l)}</div>
  <div class="kpi-v" style="${col?'color:'+col:''}">${e(v)}</div></div>`}
function portList(a){a=a||[];return a.map(p=>{
  if(p==null||p==='') return '';
  if(typeof p==='object'){const n=p.port!=null?p.port:(p.number!=null?p.number:'');const s=p.service||p.name||'?';return n===''?'':(n+' ('+s+')');}
  return String(p);
}).filter(Boolean);}
function list(a,n){a=a||[];return a.length?a.slice(0,n||99).map(x=>`<li>${e(x)}</li>`).join(''):'<li class="mut">none</li>'}
function renderFindings(F){
  const q=(document.getElementById('q').value||'').toLowerCase();
  const rows=F.filter(f=>!q||(f.section+f.id+f.detail).toLowerCase().includes(q));
  document.getElementById('ftable').innerHTML=`<div class="panel"><table><thead><tr>
    <th>Sev</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>${
    rows.slice(0,500).map(f=>`<tr><td><span class="chip ${f.sev}">${e(f.sev)}</span></td>
      <td class="mut">${e(f.section)}</td><td>${e(f.id)}</td>
      <td>${e(f.detail)}${f.evidence?`<div class="mut" style="font-size:11px">${e(f.evidence)}</div>`:''}</td></tr>`).join('')
    ||'<tr><td colspan="4" class="mut">no findings</td></tr>'}</tbody></table></div>`;
}
document.getElementById('refresh').onclick=loadScans;
document.getElementById('dl-pdf').onclick=()=>{
  if(!DATA||!DATA.__id){alert('Select a scan first.');return;}
  window.location='/api/exec-pdf?id='+encodeURIComponent(DATA.__id);
};
loadScans();
setInterval(loadScans,30000);
</script>
</body>
</html>
"""


def serve_dashboard(port=8899, open_browser=True, host="127.0.0.1"):
    """Zero-dependency local web dashboard over NULLVEIL scan history.
    Stdlib-only HTTP server bound to localhost; embedded offline SPA (no CDN)."""
    import re as _re
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    hist_dir = WebsiteRecon.HISTORY_DIR

    def _entry_path(scan_id):
        if not _re.fullmatch(r"[A-Za-z0-9-]{1,64}", scan_id or ""):
            return None
        p = os.path.join(hist_dir, scan_id + ".json")
        return p if os.path.isfile(p) else None

    def _load_entry(scan_id):
        p = _entry_path(scan_id)
        if not p:
            return None
        try:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None

    class Handler(BaseHTTPRequestHandler):
        server_version = "NULLVEIL-Dashboard"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False, default=str),
                       "application/json; charset=utf-8")

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            if u.path in ("/", "/index.html"):
                return self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
            if u.path == "/api/scans":
                scans = []
                for x in WebsiteRecon._history_list():
                    scans.append({"id": x.get("id"), "target": x.get("domain"),
                                  "url": x.get("target"), "when": x.get("when"),
                                  "duration_s": x.get("duration_s"), "version": x.get("version"),
                                  "modules": x.get("modules_run", []),
                                  "summary": x.get("summary", {})})
                return self._json({"scans": scans, "history_dir": WebsiteRecon.HISTORY_DIR})
            if u.path == "/api/scan":
                x = _load_entry((qs.get("id") or [""])[0])
                if not x:
                    return self._json({"error": "scan not found"}, 404)
                return self._json(x.get("report", {}))
            if u.path == "/api/exec-pdf":
                # 1-click executive report from a history entry (module 39)
                x = _load_entry((qs.get("id") or [""])[0])
                if not x:
                    return self._json({"error": "scan not found"}, 404)
                report = x.get("report", {}) or {}
                try:
                    recon = WebsiteRecon.__new__(WebsiteRecon)
                    recon.domain = str(report.get("target") or x.get("domain") or "target")
                    recon.base_url = recon.domain
                    # seed results so patch/remediation sections render from the saved report
                    from collections import defaultdict as _dd
                    recon.results = _dd(list)
                    recon.results['patch'] = {"patches": report.get("remediation", {}).get("patches", [])}
                    recon.no_dedupe = False
                except Exception:
                    return self._json({"error": "cannot build executive report"}, 500)
                fmt = (qs.get("format") or ["pdf"])[0].lower()
                safe = _re.sub(r"[^A-Za-z0-9._-]", "_",
                               str(report.get("target") or x.get("domain") or "scan"))
                if fmt == "html":
                    html_doc = recon.build_executive_html(report)
                    return self._send(
                        200, html_doc, "text/html; charset=utf-8")
                # render PDF to a temp file, then stream it back
                import tempfile
                tmp = os.path.join(tempfile.gettempdir(),
                                   f"nullveil-exec-{safe}-{x.get('id', 'scan')}.pdf")
                got, engine = recon.export_executive_pdf(report, tmp)
                if got and os.path.isfile(got):
                    try:
                        with open(got, "rb") as fh:
                            data = fh.read()
                    finally:
                        try:
                            os.remove(got)
                        except Exception:
                            pass
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pdf")
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="nullveil-exec-{safe}.pdf"')
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    try:
                        self.wfile.write(data)
                    except Exception:
                        pass
                    return
                # PDF engines unavailable → serve the print-ready HTML instead
                console.print("[yellow]Dashboard PDF: no PDF engine "
                              "(weasyprint/reportlab/playwright) — serving HTML[/]")
                html_doc = recon.build_executive_html(report)
                return self._send(200, html_doc, "text/html; charset=utf-8")
            if u.path == "/api/shot":
                x = _load_entry((qs.get("id") or [""])[0])
                try:
                    idx = int((qs.get("i") or ["-1"])[0])
                except Exception:
                    idx = -1
                if not x or idx < 0:
                    return self._send(404, "not found", "text/plain")
                shots = ((x.get("report", {}) or {}).get("screenshots", {}) or {}).get("shots", []) or []
                if idx >= len(shots):
                    return self._send(404, "not found", "text/plain")
                fp = shots[idx].get("file", "")
                if not (fp and str(fp).lower().endswith(".png") and os.path.isfile(fp)):
                    return self._send(404, "not found", "text/plain")
                # constrain to user-owned locations (home / workspace)
                rp = os.path.realpath(fp)
                roots = [os.path.realpath(os.path.expanduser("~")),
                         os.path.realpath(os.getcwd())]
                if not any(rp == r or rp.startswith(r + os.sep) for r in roots):
                    return self._send(403, "forbidden", "text/plain")
                try:
                    with open(rp, "rb") as fh:
                        return self._send(200, fh.read(), "image/png")
                except Exception:
                    return self._send(500, "read error", "text/plain")
            return self._send(404, "NULLVEIL dashboard: not found", "text/plain")

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as ex:
        console.print(f"[red]Cannot start dashboard on {host}:{port}[/] — {ex}")
        console.print("[dim]Try another port:[/] nullveil --dashboard 9000")
        return
    url = f"http://{host}:{port}"
    console.print(Panel(f"[bold green]Dashboard live →[/] [bold cyan]{url}[/]\n"
                        f"[dim]History: {WebsiteRecon.HISTORY_DIR}[/]\n"
                        f"[dim]Localhost-only · offline · Ctrl+C to stop[/]",
                        title="[bold magenta]◈ NULLVEIL DASHBOARD ◈[/]", border_style="magenta"))
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/]")
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass


# ---------------------------------------------------------- headless JSON API
def serve_api(host="127.0.0.1", port=8900):
    """Headless JSON scan API for CI/CD and automation (``--serve-api``).

    Endpoints (localhost-only by default):

    * ``GET  /health``            → liveness + version
    * ``POST /scan``              → run a scan, return the full report JSON
          body: {"target": "example.com", "modules": "all", "deep": false,
                 "timeout": 10, "concurrency": 100, "verify": false,
                 "evade": "none", "retries": 2}
    * ``GET  /report?id=SCAN_ID`` → a saved history report

    A single scan runs at a time (scans are network-heavy); concurrent POSTs
    queue on a lock. Every response is JSON. This is a **scanning** API — bind
    it to localhost or a trusted network only.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    _lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "NULLVEIL-API"

        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            if u.path == "/health":
                return self._json({"status": "ok", "tool": "NULLVEIL Recon",
                                   "version": __version__})
            if u.path == "/report":
                sid = (qs.get("id") or [""])[0]
                if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", sid or ""):
                    return self._json({"error": "invalid id"}, 400)
                p = os.path.join(WebsiteRecon.HISTORY_DIR, sid + ".json")
                if not os.path.isfile(p):
                    return self._json({"error": "scan not found"}, 404)
                try:
                    with open(p, encoding="utf-8") as fh:
                        return self._json(json.load(fh).get("report", {}))
                except Exception as ex:
                    return self._json({"error": str(ex)}, 500)
            if u.path in ("/", "/index.html"):
                return self._json({"tool": "NULLVEIL Recon", "version": __version__,
                                   "endpoints": ["GET /health", "POST /scan",
                                                 "GET /report?id=…"]})
            return self._json({"error": "not found"}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            if u.path != "/scan":
                return self._json({"error": "not found"}, 404)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(n) or b"{}")
            except Exception as ex:
                return self._json({"error": f"bad JSON: {ex}"}, 400)
            target = str(payload.get("target") or "").strip()
            if not target:
                return self._json({"error": "target is required"}, 400)
            if not _lock.acquire(timeout=1):
                return self._json({"error": "a scan is already running; retry shortly"}, 429)
            try:
                report = _api_scan(payload, target)
                return self._json(report)
            except Exception as ex:
                return self._json({"error": f"{type(ex).__name__}: {ex}"}, 500)
            finally:
                _lock.release()

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as ex:
        console.print(f"[red]Cannot start API on {host}:{port}[/] — {ex}")
        return
    url = f"http://{host}:{port}"
    console.print(Panel(
        f"[bold green]JSON scan API live →[/] [bold cyan]{url}[/]\n"
        f"[dim]POST /scan  ·  GET /health  ·  GET /report?id=…[/]\n"
        f"[dim]{host}-only · Ctrl+C to stop[/]",
        title="[bold magenta]◈ NULLVEIL API ◈[/]", border_style="magenta"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]API stopped.[/]")
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass


def _api_scan(payload, target):
    """Build a minimal args namespace and run exactly one scan for the API."""
    ns = argparse.Namespace()
    # defaults for every attribute _scan_target / WebsiteRecon touches
    ns.target = target
    ns.deep = bool(payload.get("deep", False))
    ns.timeout = int(payload.get("timeout", 10))
    ns.concurrency = int(payload.get("concurrency", 100))
    ns.ports = payload.get("ports")
    ns.wordlist = payload.get("wordlist")
    ns.proxy = payload.get("proxy")
    ns.output = None
    ns.html = None
    ns.pdf = None
    ns.repro = None
    ns.dashboard = None
    ns.quiet = True
    ns.har = payload.get("har") or []
    ns.hibp_key = payload.get("hibp_key")
    ns.correlate = payload.get("correlate")
    ns.dot = None
    ns.nuclei_templates = payload.get("nuclei_templates")
    ns.ffuf_wordlist = None
    ns.rules = payload.get("rules")
    ns.no_retry = False
    ns.retries = int(payload.get("retries", 2))
    ns.evade = payload.get("evade", "none")
    ns.evade_rotate_every = 1
    ns.verify = bool(payload.get("verify", False))
    ns.plugin = payload.get("plugin")
    # auth — off by default in the API (avoid touching private data implicitly)
    for a in ("auth_header", "auth_cookie", "role", "login_extra"):
        setattr(ns, a, [])
    ns.auth_token = None
    ns.auth_api_key = None
    ns.auth_api_key_header = "X-API-Key"
    ns.login_url = None
    ns.login_user = None
    ns.login_pass = None
    ns.login_user_field = "username"
    ns.login_pass_field = "password"
    ns.login_body = None
    ns.login_form = False
    ns.login_token_path = None
    ns.oob = False
    ns.oob_server = None
    ns.oob_wait = 0
    ns.no_history = False
    ns.module_timeout = 180.0
    ns.module_timeout_heavy = 300.0
    ns.no_dedupe = False
    ns.exec_report = None
    ns.exec_pdf = None
    ns.webhook_slack = ns.webhook_telegram = ns.webhook_discord = ns.webhook_teams = None
    ns.attack_layer = None
    ns.cve_live = bool(payload.get("cve_live", False))
    ns.watch = None
    ns.interval = 300
    ns.resume = None

    mod_spec = payload.get("modules", "all")
    attack_indices = parse_attack_list(mod_spec) or list(ALL_MODULE_NUMS)
    ports = None
    if ns.ports:
        try:
            ports = sorted({int(p) for p in str(ns.ports).split(",") if p.strip()})
        except ValueError:
            ports = None
    out = _scan_target(ns, attack_indices, ports, target, out_suffix="") or {}
    return out.get("report") or out


def _timeline_report(target, db_path=None):
    """Print the timeline trend + first-seen assets for a target (--timeline-query)."""
    db = TimelineDB(db_path)
    st = db.stats()
    console.print(Panel(f"[bold cyan]{st['path']}[/]\n"
                        f"[dim]{st['scans']} scan(s) · {st['domains']} domain(s) · "
                        f"{st['findings']} finding row(s) · {st['assets']} asset row(s)[/]",
                        title="[bold magenta]◈ NULLVEIL TIMELINE ◈[/]", border_style="magenta"))
    if not st["enabled"]:
        console.print(f"[yellow]Timeline DB not available:[/] {st['error']}")
        db.close()
        return
    domain = target.strip().lower()
    for pfx in ("https://", "http://"):
        if domain.startswith(pfx):
            domain = domain[len(pfx):]
    domain = domain.split("/")[0].split(":")[0]

    rows = db.history(domain, limit=50)
    if not rows:
        console.print(f"[yellow]No timeline entries for[/] [bold]{domain}[/] "
                      f"[dim](run a scan with --timeline first)[/]")
        db.close()
        return

    tt = Table(box=rbox.SIMPLE_HEAVY, header_style="bold white on dark_blue",
               title=f"[bold]{domain}[/] — {len(rows)} scan(s)")
    tt.add_column("#", style="bold cyan", justify="right")
    tt.add_column("When")
    tt.add_column("Score", justify="right")
    tt.add_column("Verdict")
    tt.add_column("High/ Crit", justify="right")
    tt.add_column("Subs", justify="right")
    tt.add_column("Ports", justify="right")
    for r in rows:
        sc = r.get("score")
        color = ("red" if isinstance(sc, int) and sc >= 60
                 else "yellow" if isinstance(sc, int) and sc >= 30 else "green")
        tt.add_row(str(r.get("id")), str(r.get("scanned_at", ""))[:16],
                   f"[{color}]{sc if sc is not None else '—'}[/]",
                   str(r.get("verdict") or "—"),
                   f"{r.get('high', 0)}/{r.get('critical', 0)}",
                   str(r.get("subdomains", 0)), str(r.get("ports", 0)))
    console.print(tt)

    trend = db.trend(domain, limit=30)
    if len(trend) >= 2:
        first, last = trend[0].get("score"), trend[-1].get("score")
        if isinstance(first, int) and isinstance(last, int):
            delta = last - first
            arrow = "[red]▲[/]" if delta > 0 else "[green]▼[/]" if delta < 0 else "[dim]▬[/]"
            console.print(f"\n{arrow} [bold]Exposure trend:[/] {first} → {last} "
                          f"({'+' if delta >= 0 else ''}{delta}) over {len(trend)} scan(s)")

    # first-seen: when did each currently-known asset first show up?
    try:
        fs = db.conn.execute(
            "SELECT a.kind, a.value, MIN(a.scan_id) AS first_id, s.scanned_at "
            "FROM assets a JOIN scans s ON s.id = a.scan_id "
            "WHERE s.domain = ? AND a.kind IN ('subdomain','port') "
            "GROUP BY a.kind, a.value ORDER BY a.kind, a.scan_id ASC LIMIT 40",
            (domain,)).fetchall()
        if fs:
            ft = Table(box=rbox.SIMPLE, header_style="bold white on dark_blue",
                       title="First seen (subdomains / ports)")
            ft.add_column("Kind", style="cyan")
            ft.add_column("Asset", style="bold")
            ft.add_column("Scan #", justify="right")
            ft.add_column("First seen")
            for kind, value, first_id, seen_at in fs:
                ft.add_row(str(kind), str(value)[:60], str(first_id),
                           str(seen_at or "")[:16])
            console.print(ft)
    except Exception:
        pass
    db.close()


# ---------------------------------------------------------- batch targets
def _expand_targets(spec_list):
    """Expand a list of target specs (domains/URLs/CIDRs) into a flat, ordered,
    de-duplicated list of scan targets. CIDR blocks are expanded to host IPs,
    capped to keep an accidental ``/8`` from launching a million scans."""
    out, seen = [], set()
    for spec in spec_list:
        spec = (spec or "").strip()
        if not spec or spec.startswith("#"):
            continue
        items = [x.strip() for x in re.split(r"[,\s]+", spec) if x.strip()]
        for it in items:
            if "/" in it and not it.startswith(("http://", "https://")):
                try:
                    net = ipaddress.ip_network(it, strict=False)
                    for host in net.hosts():
                        h = str(host)
                        if h not in seen:
                            seen.add(h)
                            out.append(h)
                    continue
                except ValueError:
                    pass
            if it not in seen:
                seen.add(it)
                out.append(it)
    return out


def _load_targets_file(path, max_hosts=1024):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    except FileNotFoundError:
        console.print(f"[bold red]Targets file not found:[/] {path}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Could not read targets file:[/] {e}")
        sys.exit(1)
    expanded = _expand_targets(raw)
    if len(expanded) > max_hosts:
        console.print(f"[yellow]! {len(expanded)} targets exceed --max-hosts {max_hosts}; "
                      f"scanning the first {max_hosts}.[/]")
        expanded = expanded[:max_hosts]
    return expanded


# ---------------------------------------------------------- CLI
def main():
    import warnings as _warnings
    _warnings.filterwarnings("ignore", category=DeprecationWarning)
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
               "  nullveil example.com -a auth --login-url https://x/login --login-user u --login-pass p\n"
               "  nullveil example.com -a auth --auth-token eyJ... --role 'admin=Authorization: Bearer eyJ...'\n"
               "  nullveil example.com -a ssrf,smartfuzz --oob  -> OOB SSRF probe + context-aware fuzz\n"
               "  nullveil example.com --proxy http://127.0.0.1:8080 -> route scan via Burp/Caido for manual follow-up\n"
               "  nullveil example.com -a burp --har capture.har -> import Burp/Caido HAR into the API pool\n"
               "  HIBP_API_KEY=xxx nullveil example.com -a breach -> breach monitoring\n"
               "  nullveil example.com --pdf report.pdf -> client-ready PDF report\n"
               "  nullveil example.com -a patch,poc    -> AI-style remediation + read-only PoC commands\n"
               "  nullveil example.com -a exec --exec-report exec.html --exec-pdf exec.pdf -> C-level report\n"
               "  nullveil example.com --webhook-slack https://hooks.slack.com/... -> push summary to Slack\n"
               "  nullveil example.com -a jsecret,wayback,param,gql,cloud -> Tier-1 discovery (JS secrets, history, params, GraphQL, buckets)\n"
               "  nullveil --dashboard                -> local web dashboard (scan history)\n"
               "  nullveil --targets-file t.txt -a all -o out.json -> mass scan + combined index\n"
               "  nullveil example.com --evade light --retries 4 --verify -> evasive, resilient, low-FP scan\n"
               "  nullveil example.com -a vulnverify  -> read-only XSS/SQLi/traversal reachability proof\n"
               "  nullveil example.com -a all --timeline -> index the scan for trend/first-seen queries\n"
               "  nullveil --timeline-query example.com -> exposure trend + first-seen assets\n"
               "  nullveil --targets-file t.txt --workers 4 -o fleet.json -> concurrent fleet scan\n"
               "  nullveil --pdf-from old.json --pdf out.pdf -> convert saved JSON to PDF\n"
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
                        help="Comma-separated modules: 1=dns,2=sub,3=ports,4=http,5=ssl,6=content,7=robots,8=paths,9=users,10=api,11=waf,12=email,13=audit,14=ext,15=cve,16=crawl,17=tls,18=supply,19=crit,20=anom,21=intel,22=breach,23=comp,24=graph,25=correlate,26=shot,27=nuclei,28=katana,29=linkfinder,30=ffuf,31=auth,32=ssrf,33=smartfuzz,34=burp,35=patch,36=poc,37=notify,39=exec,40=jsecret,41=wayback,42=param,43=gql,44=cloud,45=cvss,46=attack,47=cveintel,48=takeover,49=watch or 'all'")
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
    parser.add_argument("--ffuf-wordlist", metavar="FILE", default=None,
                        help="Custom path wordlist for ffuf (used by -a ffuf; default: built-in API list)")
    parser.add_argument("--rules", action="append", metavar="PATH", default=None,
                        help="Load external plugin rules (YAML/JSON file or directory, repeatable) that extend the "
                             "built-in CVE + misconfig rule sets — e.g. --rules rules/. YAML needs PyYAML; JSON always works")
    parser.add_argument("--no-retry", action="store_true",
                        help="Disable the transparent retry/backoff layer (default: retry 429/503 + connection "
                             "errors twice with exponential backoff)")
    parser.add_argument("--retries", type=int, metavar="N", default=2,
                        help="Max transparent retries per request for transient failures (default: 2)")

    # ---- advanced: mass scanning + WAF evasion (v3.9.0) ----
    advg = parser.add_argument_group("advanced scanning (mass targets + WAF evasion)")
    advg.add_argument("--targets-file", metavar="FILE", default=None,
                      help="Batch mode: scan every target (one per line, '#' comments) in FILE sequentially. "
                           "Per-target reports are written next to -o/-H with the target name appended; a combined "
                           "index is added when -o is given.")
    advg.add_argument("--targets-list", metavar="LIST", default=None,
                      help="Batch mode: comma-separated inline target list (e.g. 'a.com,b.com,10.0.0.0/30'). "
                           "CIDR blocks are expanded to host IPs (capped by --max-hosts).")
    advg.add_argument("--max-hosts", type=int, metavar="N", default=1024,
                      help="Safety cap on how many hosts a CIDR expands to in batch mode (default: 1024)")
    advg.add_argument("--evade", choices=["none", "light", "stealth"], default="none",
                      help="WAF-evasion profile (default: none). 'light' rotates a coherent real-browser header "
                           "profile per request + small jitter; 'stealth' adds wider jitter. Read-only — never "
                           "forges auth or mutates the target")
    advg.add_argument("--evade-rotate-every", type=int, metavar="N", default=1,
                      help="Rotate the browser profile every N requests in --evade mode (default: 1)")
    advg.add_argument("--verify", action="store_true",
                      help="Deep-accuracy pass: re-verify each finding with a second, independent request and drop "
                           "anything that does not reproduce (reduces false positives; slower)")
    advg.add_argument("--plugin", action="append", metavar="FILE.py", default=None,
                      help="Load an external Python plugin (repeatable) that runs over the finished results. The "
                           "file must define run(ctx) and may return (severity, check, detail) findings — they flow "
                           "into CVSS/report/webhooks. Only load plugins you trust (arbitrary local code).")
    advg.add_argument("--serve-api", nargs="?", const="8900", metavar="PORT", default=None,
                      help="Serve a headless JSON scan API (default port 8900): POST /scan {target,modules,…} -> "
                           "report JSON, GET /health, GET /report?id=…  — for CI/CD integration")
    advg.add_argument("--api-host", metavar="HOST", default="127.0.0.1",
                      help="Bind address for --serve-api (default: 127.0.0.1 — localhost only)")
    advg.add_argument("--timeline", action="store_true",
                      help="Index every completed scan into a local SQLite timeline DB (added to the JSON history, "
                           "never replacing it) for trend / first-seen queries")
    advg.add_argument("--timeline-db", metavar="FILE", default=None,
                      help="Path to the timeline SQLite DB (default: ~/.nullveil/history/timeline.db)")
    advg.add_argument("--timeline-query", metavar="TARGET", default=None,
                      help="Print the exposure-score trend + first-seen assets for TARGET from the timeline DB and exit")
    advg.add_argument("--workers", type=int, metavar="N", default=1,
                      help="Batch mode: scan N targets concurrently (default: 1 = sequential). Each worker runs the "
                           "full pipeline against one target at a time; reports never overlap")
    authg = parser.add_argument_group("authenticated scanning (module 31: auth)")
    authg.add_argument("--auth-header", action="append", metavar="'Name: Value'",
                       help="Header injected into EVERY scan request (repeatable), e.g. --auth-header 'X-Api-Key: abc'")
    authg.add_argument("--auth-cookie", action="append", metavar="name=value",
                       help="Session cookie injected into every request (repeatable)")
    authg.add_argument("--auth-token", metavar="TOKEN", default=None,
                       help="Bearer token shorthand -> Authorization: Bearer TOKEN on every request")
    authg.add_argument("--auth-api-key", metavar="KEY", default=None,
                       help="API key sent in --auth-api-key-header (default header: X-API-Key)")
    authg.add_argument("--auth-api-key-header", metavar="NAME", default="X-API-Key",
                       help="Header name used for --auth-api-key (default: X-API-Key)")
    authg.add_argument("--login-url", metavar="URL", default=None,
                       help="Automated login endpoint (POST) — engine captures cookies/token, then every module runs authenticated")
    authg.add_argument("--login-user", metavar="USER", default=None,
                       help="Login username/email for --login-url")
    authg.add_argument("--login-pass", metavar="PASS", default=None,
                       help="Login password for --login-url")
    authg.add_argument("--login-user-field", metavar="NAME", default="username",
                       help="JSON/form field name for the username (default: username)")
    authg.add_argument("--login-pass-field", metavar="NAME", default="password",
                       help="JSON/form field name for the password (default: password)")
    authg.add_argument("--login-body", metavar="JSON", default=None,
                       help="Raw login JSON template with {user}/{pass} placeholders (overrides field names)")
    authg.add_argument("--login-form", action="store_true",
                       help="Send login fields as form data instead of JSON")
    authg.add_argument("--login-token-path", metavar="PATH", default=None,
                       help="Dot-path of bearer token in login JSON response (auto-detects access_token/token/jwt if omitted)")
    authg.add_argument("--login-extra", action="append", metavar="K=V",
                       help="Extra login body field (repeatable), e.g. --login-extra device=web")
    authg.add_argument("--role", action="append", metavar="'NAME=SPEC'",
                       help="Multi-role profile for role-diff scan (repeatable). SPEC: 'Header: value', "
                            "'name=value' cookie, or bare token. e.g. --role 'user=Cookie: sid=123' "
                            "--role 'admin=Authorization: Bearer eyJ...'")
    oobg = parser.add_argument_group("SSRF / out-of-band (module 32: ssrf)")
    oobg.add_argument("--oob", action="store_true",
                      help="Enable interactsh out-of-band SSRF callbacks (needs interactsh-client binary)")
    oobg.add_argument("--oob-server", metavar="HOST", default=None,
                      help="Custom interactsh server host (default: interactsh public server)")
    oobg.add_argument("--oob-wait", type=int, default=0, metavar="SEC",
                      help="Seconds to wait for OOB callbacks (default: 45 normal / 90 deep)")
    proxg = parser.add_argument_group("Burp Suite / Caido bridge (module 34: burp)")
    proxg.add_argument("--proxy", metavar="URL", default=None,
                       help="Route the whole scan (httpx + katana/ffuf/nuclei) through an intercepting proxy, "
                            "e.g. Burp http://127.0.0.1:8080 or Caido http://127.0.0.1:8080 — traffic lands in "
                            "their HTTP history for manual follow-up")
    proxg.add_argument("--har", action="append", metavar="FILE", default=None,
                       help="Import a HAR capture exported from Burp (Save items → HAR) or Caido (Export HAR) — "
                            "endpoints, params, cookies & secrets feed the unified API pool (repeatable)")
    parser.add_argument("--pdf", metavar="FILE", default=None,
                        help="Export a client-ready PDF report (headless Chromium; needs playwright)")
    parser.add_argument("--pdf-from", metavar="JSON", default=None,
                        help="Convert an existing NULLVEIL JSON report to PDF (use with --pdf)")
    # ---- webhook notifications (module 37) ----
    parser.add_argument("--webhook-slack", metavar="URL", default=None,
                        help="Post the scan summary to a Slack incoming-webhook URL")
    parser.add_argument("--webhook-telegram", metavar="TOKEN:CHATID", default=None,
                        help="Post to Telegram (bot TOKEN:CHAT_ID), e.g. 123:abc:-100123456")
    parser.add_argument("--webhook-discord", metavar="URL", default=None,
                        help="Post the scan summary to a Discord webhook URL")
    parser.add_argument("--webhook-teams", metavar="URL", default=None,
                        help="Post the scan summary to a Microsoft Teams incoming-webhook URL")
    # ---- strict per-module timeouts ----
    parser.add_argument("--module-timeout", type=float, metavar="SEC", default=180.0,
                        help="Per-module hard timeout for normal modules (default: 180s)")
    parser.add_argument("--module-timeout-heavy", type=float, metavar="SEC", default=300.0,
                        help="Per-module hard timeout for crawl/fuzz modules (default: 300s)")
    parser.add_argument("--no-dedupe", action="store_true",
                        help="Disable smart deduplication of redundant low-severity findings")
    parser.add_argument("--exec-report", metavar="FILE", default=None,
                        help="Write the executive C-level HTML report to FILE (module 39)")
    parser.add_argument("--exec-pdf", metavar="FILE", default=None,
                        help="Also export the executive report as PDF (needs weasyprint/reportlab/playwright)")
    parser.add_argument("--dashboard", nargs="?", const="8899", metavar="PORT", default=None,
                        help="Serve a local web dashboard of scan history (default port: 8899)")
    parser.add_argument("--watch", nargs="?", const=0, type=int, metavar="N", default=None,
                        help="Continuous monitor: repeat the scan N times (0 = until Ctrl+C) "
                             "and report drift (module 49 auto-enabled)")
    parser.add_argument("--interval", type=int, metavar="SEC", default=300,
                        help="Seconds between --watch runs (default: 300)")
    parser.add_argument("--attack-layer", metavar="FILE", default=None,
                        help="Write a MITRE ATT&CK Navigator layer JSON to FILE (module 46)")
    parser.add_argument("--cve-live", action="store_true",
                        help="Enrich CVEs with LIVE NVD 2.0 + FIRST EPSS + CISA KEV data "
                             "(disk-cached, module 47). Without this, curated offline intel is used")
    parser.add_argument("--cve-cache-clear", action="store_true",
                        help="Delete the local live-CVE cache (~/.nullveil/cve_cache/) and exit")
    parser.add_argument("-V", "--version", action="version", version=f"NULLVEIL Recon v{__version__} | Owner: NULLVEIL | Engine: DeepHat")
    args = parser.parse_args()

    if args.cve_cache_clear:
        import shutil as _sh
        d = WebsiteRecon.CVE_CACHE_DIR
        if os.path.isdir(d):
            n = len([f for f in os.listdir(d) if f.endswith(".json")])
            _sh.rmtree(d, ignore_errors=True)
            console.print(f"[bold green]Live-CVE cache cleared:[/] {n} file(s) removed from {d}")
        else:
            console.print(f"[yellow]No live-CVE cache found at {d}[/]")
        return

    if args.history:
        entries = WebsiteRecon._history_list()
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

    if args.timeline_query:
        _timeline_report(args.timeline_query, db_path=args.timeline_db)
        return

    if args.pdf_from:
        if not args.pdf:
            console.print("[yellow]--pdf-from needs --pdf FILE[/] (e.g. --pdf-from old.json --pdf out.pdf)")
            sys.exit(1)
        ok, msg = WebsiteRecon.pdf_from_dict_file(args.pdf_from, args.pdf)
        if ok:
            console.print(f"[bold green]PDF report saved:[/] {msg}")
        else:
            console.print(f"[red]PDF export failed:[/] {msg}")
            sys.exit(1)
        if not args.target and args.dashboard is None:
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

    if not args.target and not (args.targets_file or args.targets_list):
        if args.dashboard is not None:
            serve_dashboard(port=int(args.dashboard))
            return
        if args.serve_api is not None:
            serve_api(port=int(args.serve_api), host=args.api_host or "127.0.0.1")
            return
        parser.print_help()
        console.print("\n[red]Error:[/] target is required (unless using -l / --history / --dashboard / --pdf-from / --targets-file / --targets-list / --serve-api)")
        sys.exit(1)

    # Attack selection: -m menu > -a list > default ALL
    if args.menu:
        attack_indices = attack_menu(args.target or "target")
    elif args.attack is not None:
        attack_indices = parse_attack_list(args.attack)
        if not attack_indices:
            console.print(f"[bold red]Invalid attack list:[/] {args.attack}")
            console.print("[dim]Use -l or --list-attacks to see available modules[/]")
            sys.exit(1)
    else:
        attack_indices = list(ALL_MODULE_NUMS)
    # Using --proxy / --har implies the Burp/Caido bridge (module 34) should run
    if (args.proxy or args.har) and 34 not in attack_indices:
        attack_indices = sorted(set(attack_indices) | {34})
    ports = None
    if args.ports:
        try:
            ports = sorted(set(int(p.strip()) for p in args.ports.split(',') if p.strip()))
        except ValueError:
            print("[!] Invalid --ports value. Example: --ports 80,443,8080")
            sys.exit(1)

    # ---- mass scanning (batch): resolve the target list ------------------
    batch = None
    if args.targets_file or args.targets_list:
        if args.targets_file:
            batch = _load_targets_file(args.targets_file, max_hosts=max(1, int(args.max_hosts)))
        inline = _expand_targets([args.targets_list]) if args.targets_list else []
        if batch is None:
            batch = inline[:max(1, int(args.max_hosts))]
        elif inline:
            batch += [t for t in inline if t not in batch]
        if not batch:
            console.print("[bold red]No targets found in --targets-file / --targets-list.[/]")
            sys.exit(1)
        console.print(f"[bold cyan]◆ Batch mode[/] — {len(batch)} target(s) queued"
                      + ("  [dim](sequential, one report each)[/]" if not args.quiet else ""))

    targets = batch if batch else [args.target]
    workers = max(1, int(getattr(args, "workers", 1) or 1))
    if batch and workers > 1:
        workers = min(workers, len(targets))
        if not args.quiet:
            console.print(f"[dim]{workers} worker(s) — reports never overlap (per-target suffix)[/]")
    batch_index = []

    def _one(job):
        _ti, _tgt = job
        # Each worker gets its OWN copy of the parsed args. _scan_target sets
        # args.target and reads many attributes; a shared object would let
        # concurrent workers clobber each other's target/report.
        import copy as _copy
        _args = _copy.copy(args)
        if batch and not args.quiet:
            console.print(f"\n[bold magenta]━━ scan {_ti}/{len(targets)}:[/] [bold white]{_tgt}[/] ━━")
        suffix = ""
        if batch:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", _tgt)[:80]
            suffix = f".{safe}"
        try:
            _summary = _scan_target(_args, attack_indices, ports, _tgt, suffix)
            _sc = (_summary or {}).get("score") or {}
            return {"target": _tgt, "ok": True,
                    "exposure": _sc.get("score") if isinstance(_sc, dict) else _sc,
                    "verdict": _sc.get("verdict") if isinstance(_sc, dict) else None}
        except SystemExit:
            raise
        except Exception as e:
            console.print(f"[bold red]scan failed for {_tgt}:[/] {type(e).__name__} — {e}")
            return {"target": _tgt, "ok": False, "error": str(e)}

    jobs = list(enumerate(targets, 1))
    if batch and workers > 1:
        # targets run concurrently; each writes its own name-suffixed report so
        # outputs never collide. Results are collected in target order.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as pool:
            batch_index = list(pool.map(_one, jobs))
    else:
        for job in jobs:
            try:
                res = _one(job)
            except SystemExit:
                raise
            except Exception:
                raise
            if batch:
                batch_index.append(res)

    # combined batch index
    if batch and args.output:
        try:
            idx_path = os.path.splitext(args.output)[0] + ".index.json"
            with open(idx_path, "w", encoding="utf-8") as f:
                json.dump({"tool": "NULLVEIL Recon", "version": __version__,
                           "mode": "batch", "count": len(batch_index),
                           "targets": batch_index}, f, indent=2, ensure_ascii=False)
            console.print(f"\n[bold green]Batch index saved:[/] {idx_path} "
                          f"[dim]({len(batch_index)} target(s))[/]")
        except Exception as e:
            console.print(f"[yellow]Could not write batch index: {e}[/]")
    return


def _scan_target(args, attack_indices, ports, target, out_suffix=""):
    """Run one full scan of ``target`` using the parsed ``args``.

    Extracted so batch mode (--targets-file / --targets-list) can reuse the
    exact single-target pipeline — configuration, exports, watch loop and all.
    """
    args.target = target
    recon = WebsiteRecon(
        args.target,
        deep=args.deep,
        timeout=args.timeout,
        concurrency=args.concurrency,
        ports=ports,
        wordlist=args.wordlist,
        proxy=args.proxy or None,
    )
    recon.attack_set = attack_indices
    recon.har_files = [str(f) for f in (args.har or [])]
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
    recon.ffuf_wordlist = args.ffuf_wordlist
    # ---- plugin rule engine (--rules): extend CVE + misconfig knowledge ----
    recon.ruleset = RuleSet()
    if args.rules:
        recon.ruleset.load_paths(args.rules)
        s = recon.ruleset.summary()
        if s["cve_rules"] or s["misconfig_rules"]:
            console.print(f"[bold green]✓ Rules loaded[/] — "
                          f"{s['cve_rules']} CVE · {s['misconfig_rules']} misconfig "
                          f"from {len(s['files'])} file(s)")
        for err in s["errors"]:
            console.print(f"[yellow]! {err}[/]")
    # ---- resilience tuning (retry/backoff layer) ----
    recon.max_retries = 0 if args.no_retry else max(0, int(args.retries))
    # ---- WAF evasion (--evade) ----
    recon.evade_level = args.evade or "none"
    recon.evade_rotate_every = max(1, int(args.evade_rotate_every or 1))
    if recon.evade_level != "none":
        console.print(f"[bold green]✓ WAF evasion[/] — profile [cyan]{recon.evade_level}[/] "
                      f"(rotate every {recon.evade_rotate_every} req)")
    recon.deep_verify = bool(args.verify)
    # ---- external Python plugins (--plugin) ----
    if args.plugin:
        recon.plugins = PluginManager().load_paths(args.plugin)
        s = recon.plugins.summary()
        if s["loaded"]:
            console.print(f"[bold green]✓ Plugins loaded[/] — {s['loaded']}: "
                          f"{', '.join(s['files'])}")
        for err in s["errors"]:
            console.print(f"[yellow]! {err}[/]")
    # ---- SQLite timeline (--timeline) ----
    if args.timeline:
        recon.timeline_db = TimelineDB(args.timeline_db)
        st = recon.timeline_db.stats()
        if st["enabled"]:
            console.print(f"[bold green]✓ Timeline DB[/] — {st['path']} "
                          f"[dim]({st['scans']} scan(s), {st['domains']} domain(s))[/]")
        else:
            console.print(f"[yellow]! Timeline DB unavailable:[/] {st['error']}")
    recon.auth_cfg = {
        "headers": args.auth_header or [],
        "cookies": args.auth_cookie or [],
        "token": args.auth_token or "",
        "api_key": args.auth_api_key or "",
        "api_key_header": args.auth_api_key_header,
        "login_url": args.login_url or "",
        "login_user": args.login_user or "",
        "login_pass": args.login_pass or "",
        "user_field": args.login_user_field,
        "pass_field": args.login_pass_field,
        "body": args.login_body or "",
        "form": bool(args.login_form),
        "token_path": args.login_token_path or "",
        "extra": args.login_extra or [],
        "roles": args.role or [],
    }
    recon.oob_cfg = {"enabled": bool(args.oob),
                     "server": args.oob_server or "",
                     "wait": int(args.oob_wait or 0)}
    recon.no_history = args.no_history
    # ---- roadmap v3.6.0 wiring ----
    recon.module_timeout = float(args.module_timeout or 180.0)
    recon.module_timeout_heavy = float(args.module_timeout_heavy or 300.0)
    recon.no_dedupe = bool(args.no_dedupe)
    recon.exec_report_path = args.exec_report or ""
    recon.exec_pdf_path = args.exec_pdf or ""
    recon.webhooks = {
        "slack": args.webhook_slack or "",
        "telegram": args.webhook_telegram or "",
        "discord": args.webhook_discord or "",
        "teams": args.webhook_teams or "",
    }
    if any(recon.webhooks.values()):
        recon.attack_set = sorted(set(recon.attack_set) | {37})
    if args.exec_report or args.exec_pdf:
        recon.attack_set = sorted(set(recon.attack_set) | {39})
    # ---- roadmap v3.7.0 Tier-2 wiring ----
    recon.attack_layer_path = args.attack_layer or ""
    if args.attack_layer:
        recon.attack_set = sorted(set(recon.attack_set) | {46})
    recon.cve_live = bool(args.cve_live)
    if args.cve_live:
        recon.attack_set = sorted(set(recon.attack_set) | {47})
    if args.watch is not None:
        recon.attack_set = sorted(set(recon.attack_set) | {49})
    recon.watch_runs = args.watch
    recon.watch_interval = int(args.interval or 300)
    if args.resume is not None:
        entry = recon._history_load(args.resume or None)
        if entry:
            recon.resume_entry = entry
        else:
            console.print(f"[yellow]No history entry found{' for ' + args.resume if args.resume else ' for ' + recon.domain}[/]"
                          f" — running a fresh scan.")

    try:
        report = asyncio.run(recon.run())
        # ---- --watch continuous monitor loop (module 49) ----
        watch_runs = getattr(recon, "watch_runs", None)
        if watch_runs is not None:
            interval = int(getattr(recon, "watch_interval", 300) or 300)
            run_no = 1
            while (watch_runs == 0) or (run_no < watch_runs):
                run_no += 1
                console.print(f"\n[bold magenta]◈ WATCH[/] run {run_no}"
                              f"{'' if watch_runs == 0 else '/' + str(watch_runs)} — "
                              f"sleeping {interval}s… [dim](Ctrl+C to stop)[/]")
                try:
                    time.sleep(interval)
                except KeyboardInterrupt:
                    break
                # fresh per-run state (results/errors must not accumulate across runs)
                recon.results = defaultdict(list)
                recon.scalar_results = {}
                recon.resume_entry = None
                for _attr in ("exec_report_path",):
                    if getattr(recon, _attr, ""):
                        # avoid overwriting the same exec file each run; suffix by run
                        base = getattr(recon, _attr)
                        if run_no == 2:
                            root, ext = os.path.splitext(base)
                            setattr(recon, _attr, f"{root}-r{run_no}{ext}")
                try:
                    report = asyncio.run(recon.run())
                except Exception as e:
                    console.print(f"[red]watch run {run_no} failed:[/] {e!r}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")
        sys.exit(130)

    def _out(path):
        if not path or not out_suffix:
            return path
        root, ext = os.path.splitext(path)
        return f"{root}{out_suffix}{ext}"

    if args.output:
        try:
            op = _out(args.output)
            with open(op, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            console.print(f"\n[bold green]Report saved:[/] {op}")
        except Exception as e:
            console.print(f"\n[bold red]Could not save report:[/] {e}")

    if args.html:
        try:
            recon.export_html(_out(args.html))
            console.print(f"[bold green]HTML report saved:[/] {_out(args.html)}")
        except Exception as e:
            console.print(f"[bold red]Could not save HTML report:[/] {e}")

    try:
        if getattr(args, 'repro', None):
            outp = recon.export_repro(_out(args.repro))
            console.print(f"[bold green]Repro pack saved:[/] {outp}")
    except Exception as e:
        console.print(f"[bold red]Failed to export repro:[/] {type(e).__name__} — {e}")

    if args.pdf:
        try:
            ok, msg = recon.export_pdf(_out(args.pdf))
            if ok:
                size = os.path.getsize(msg) // 1024 if os.path.exists(msg) else 0
                console.print(f"[bold green]PDF report saved:[/] {msg} [dim]({size} KB)[/]")
            else:
                console.print(f"[yellow]PDF skipped:[/] {msg}")
        except Exception as e:
            console.print(f"[bold red]Failed to export PDF:[/] {type(e).__name__} — {e}")

    if args.dashboard is not None and not out_suffix:
        serve_dashboard(port=int(args.dashboard))

    # summary for batch mode
    return {"target": target, "ok": True, "score": _batch_score(report),
            "report": report}


def _batch_score(report):
    """Derive the 0-100 exposure score from a finished report dict.

    Uses the same ``_risk_meter`` the CLI panel uses so the batch index agrees
    with what the operator saw on screen."""
    if not isinstance(report, dict):
        return None
    s = report.get("summary", {}) or {}
    try:
        score, _level, _color, verdict, _bar = _risk_meter(
            report.get("secrets", []) or [],
            len([h for h in (report.get("missing_security_headers") or []) if h != "content-encoding"]),
            [p for p in (report.get("paths") or []) if isinstance(p, dict) and p.get("flagged")],
        )
        return {"score": score, "verdict": verdict}
    except Exception:
        return {"score": s.get("exposure_score")}


if __name__ == "__main__":
    main()
