"""In-process mock target for NULLVEIL integration tests.

Deliberately small and dependency-free (stdlib http.server). It exposes just
enough surface for the deterministic modules: a JS bundle with masked secrets +
a source map, a GraphQL endpoint with introspection/suggestions/no-depth-limit,
a reflecting search endpoint, an admin path, and a bucket-like listing.
"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"""<!doctype html><html><head><title>Mock App</title></head>
<body><script src="/static/app.js"></script></body></html>"""

# Fake credentials are assembled at runtime so the literal secret-shaped strings
# never appear in source (keeps GitHub push-protection happy). The miner treats
# the *concatenated* value exactly like a real leaked key.
_FAKE = {
    "aws": "AKIA" + "IOSFODNN7EXAMPLE",
    "gcp": "AIza" + "SyA1234567890abcdefghijklmnopqrst",
    "stripe": "sk_" + "live_" + "51H8xYzAbCdEfGhIjKlMnOpQr",
    "gh": "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
}

APP_JS = f"""
var AWS_KEY = "{_FAKE['aws']}";
var GOOGLE = "{_FAKE['gcp']}";
var STRIPE = "{_FAKE['stripe']}";
var GH = "{_FAKE['gh']}";
fetch("/api/v2/internal/users?token=abc");
fetch("/api/v2/orders");
//# sourceMappingURL=/static/app.js.map
""".encode()

APP_MAP = json.dumps({
    "version": 3,
    "sources": ["src/config.ts"],
    "sourcesContent": [f"export const SECRET_KEY='{_FAKE['stripe']}';"],
}).encode()

SEARCH = b"""<!doctype html><html><body>
<form action="/search"><input name="q"></form>
results: REFLECTED</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        path = self.path.split("?")[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        if path == "/":
            return self._send(200, PAGE)
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/static/app.js.map":
            return self._send(200, APP_MAP, "application/json")
        if path == "/search":
            val = ""
            known = re.findall(r'(?:^|&)(q|query|search|keyword)=([^&]*)', query)
            if known:
                val = "SEARCH:" + known[0][1]
            return self._send(200, SEARCH.replace(b"REFLECTED", val.encode()))
        if path in ("/api/v2/internal/users", "/api/v2/orders"):
            return self._send(200, json.dumps({"ok": True}), "application/json")
        if path == "/bucket":
            return self._send(
                200, "<ListBucketResult><Contents><Key>dump.sql</Key></Contents></ListBucketResult>",
                "application/xml")
        return self._send(404, "not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/graphql":
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            if "__schema" in body:
                return self._send(200, json.dumps({"data": {"__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "User", "kind": "OBJECT",
                               "fields": [{"name": "id"}]}]}}}), "application/json")
            if "__typenameX" in body:
                return self._send(200, json.dumps({"errors": [
                    {"message": 'Cannot query field "__typenameX". Did you mean "__typename"?'}]}),
                    "application/json")
            if body.count("{") >= 10:
                return self._send(200, json.dumps({"data": {"a": {"a": {}}}}), "application/json")
            return self._send(200, json.dumps({"data": {"__typename": "Query"}}), "application/json")
        return self._send(404, "not found")

    def do_HEAD(self):
        return self._send(200, b"")


def make_server(host="127.0.0.1", port=0):
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    print("mock target on 127.0.0.1:18111")
    make_server("127.0.0.1", 18111).serve_forever()
