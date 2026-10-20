# Authenticated Scanning

Most valuable findings live **behind a login**. NULLVEIL can carry a session
into every module — including the katana / ffuf / nuclei subprocesses — so the
whole scan runs inside the same authenticated context.

> **Authorisation first.** Only ever scan systems you own or have **written
> permission** to test. Authenticated scanning reaches private data — the bar
> for authorisation is higher, not lower. See
> [`AUTHORIZATION.md`](AUTHORIZATION.md).

---

## Two ways to authenticate

### 1. Inject static session material

Pass a token, cookies and/or arbitrary headers directly. They are added to the
shared `httpx` client **and** to the header list handed to subprocess tools.

```bash
# Bearer token (adds Authorization: Bearer <token> to every request)
python3 nullveil_recon.py app.example.com -a all --auth-token eyJhbGciOi...

# Session cookie(s) — repeatable
python3 nullveil_recon.py app.example.com --auth-cookie 'session=abc123' \
                                          --auth-cookie 'csrf=xyz'

# Any header — repeatable, 'Name: Value'
python3 nullveil_recon.py app.example.com --auth-header 'X-Api-Key: K123'

# API-key shorthand (default header X-API-Key)
python3 nullveil_recon.py app.example.com --auth-api-key K123
python3 nullveil_recon.py app.example.com --auth-api-key K123 --auth-api-key-header 'X-Token'
```

### 2. Automated login

Point the engine at a login endpoint and it POSTs the credentials **once** at
scan start, captures the returned cookies / bearer token, and reuses them for
the rest of the run.

```bash
python3 nullveil_recon.py app.example.com -a all \
  --login-url https://app.example.com/api/login \
  --login-user you@example.com \
  --login-pass 's3cr3t'
```

| Flag | Purpose |
|------|---------|
| `--login-url URL` | Login endpoint (absolute, or a path relative to the target). |
| `--login-user` / `--login-pass` | Credentials. |
| `--login-user-field` / `--login-pass-field` | JSON/form field names (default `username` / `password`). |
| `--login-form` | Send fields as `application/x-www-form-urlencoded` instead of JSON. |
| `--login-body JSON` | Raw body template with `{user}` / `{pass}` placeholders (overrides field names). |
| `--login-token-path PATH` | Dot-path of the token in the login JSON (e.g. `data.access_token`). Auto-detects `access_token` / `token` / `jwt` … if omitted. |
| `--login-extra K=V` | Extra login body field (repeatable), e.g. `--login-extra device=web`. |

**Token auto-detection** tries the common shapes (`access_token`, `token`,
`jwt`, `id_token`, and the same under `data.*` / `result.*` / `auth.*`), then
falls back to an `Authorization` / `X-Auth-Token` **response header**. Captured
session cookies are added automatically.

---

## What the auth modules do

### Module 31 — `auth`: authenticated API scan

For every endpoint in the shared API pool it sends the request **with** and
**without** the session and reports the delta:

* `auth_gated: true` — reachable with the session but `401/403`/missing without
  it (proves the endpoint trusts your identity).
* size/status/transfer deltas that reveal hidden data.

### Multi-role profiling (`--role`)

Repeatable role profiles let you find what an **admin** sees that a **user**
does not:

```bash
python3 nullveil_recon.py app.example.com -a auth \
  --auth-token "$USER_TOKEN" \
  --role 'user=Cookie: sid=user123' \
  --role 'admin=Authorization: Bearer admin456'
```

Each role's SPEC can be:

* `Header: value` → a header override (`admin=Authorization: Bearer …`),
* `name=value` → a cookie shorthand (`user=session=abc`),
* `Cookie: a=1; b=2` → a full cookie jar,
* a bare string → treated as a bearer token.

The result includes a `role_matrix` (per-role status per endpoint) and a
`role_gated` list — endpoints a higher role can reach that a lower one cannot.

### Backend / admin API audit

The auth scan also probes a curated set of backend/admin API paths and flags
those that are **session-only** (reachable with a session) or **sensitive**
(returning user lists, tokens, config). Read-only, `GET`/`HEAD` only.

---

## Result shape (`auth_setup`)

```json
"auth_setup": {
  "active": true,
  "headers": ["Authorization"],
  "cookies": ["session"],
  "roles": ["user", "admin"],
  "login": {
    "url": "https://app.example.com/api/login",
    "status": 200,
    "captured": ["bearer token (json path: access_token)", "2 session cookie(s)"]
  }
}
```

`auth_setup.active` is `true` whenever any static material, captured cookie or
role profile is in play. If a login returns `4xx`/`5xx` the URL and status are
recorded in the top-level `errors` list — the scan still runs (unauthenticated)
rather than aborting.

---

## Good practice

* Prefer a **dedicated, least-privilege test account** over a personal login.
* Rotate any token you paste on the command line afterwards — it lands in your
  shell history. Prefer `--auth-cookie` / a token read from a file in CI.
* Keep an eye on `auth_setup.login.captured` to confirm a session was actually
  established before trusting the results.
* Combine with `--watch` (module 49) to alert when a previously
  public endpoint becomes auth-gated, or vice versa.
