"""Tests for the report/export contract and the diff engine.

Guards the JSON schema the dashboard, notifications and CI consumers rely on —
a broken export silently breaks every downstream integration.
"""
import json

import pytest


def test_export_dict_shape(nv, recon):
    rep = nv.WebsiteRecon.export_dict(recon)
    assert isinstance(rep, dict)
    for key in ("version", "target", "summary", "errors", "tool", "owner"):
        assert key in rep, key
    assert rep["version"] == nv.__version__
    # must be JSON-serialisable with the same default=str policy the tool uses
    json.dumps(rep, default=str)


def test_export_has_tier2_sections(nv, recon):
    rep = nv.WebsiteRecon.export_dict(recon)
    # Tier-2 keys exist even before the modules run (empty defaults)
    for key in ("cvss", "mitre_attack", "cve_intel", "takeover_v3", "watch",
                "scan_diff"):
        assert key in rep, f"missing export section: {key}"


def test_summary_counts_are_numeric(nv, recon):
    rep = nv.WebsiteRecon.export_dict(recon)
    # count-style keys must be numeric; a couple of keys legitimately hold lists
    non_count = {"tech_stack", "waf"}
    for k, v in rep["summary"].items():
        if k in non_count:
            continue
        assert isinstance(v, (int, float)), f"summary[{k}] is {type(v)}"


def test_collect_findings_handles_seeded_modules(nv, recon):
    recon.results["versions"] = [("nginx", "1.24.0", "header")]
    recon.results["cve_findings"] = [("HIGH", "CVE-2021-1234", "detail", "src")]
    rows = nv.WebsiteRecon._collect_findings(recon)
    assert isinstance(rows, list)
    for row in rows:
        assert len(row) == 4, row  # (severity, check, detail, source)


def test_compute_diff_first_scan(nv, recon):
    recon.no_history = False
    report = nv.WebsiteRecon.export_dict(recon)
    nv.WebsiteRecon._compute_diff(recon, report)
    d = recon.results.get("diff")
    assert d and d.get("available") is False
    assert "baseline" in d.get("note", "").lower()


def test_compliance_tls_evidence_names_only_accepted_versions(nv, recon):
    import asyncio
    recon.results["tls_matrix"] = [
        ("TLS 1.0", "yes", "ECDHE-RSA-AES128-SHA", "128"),
        ("TLS 1.1", "no", "-", "-"),
        ("TLS 1.2", "yes", "ECDHE-RSA-AES128-GCM-SHA256", "128"),
        ("TLS 1.3", "no", "-", "-"),
    ]
    recon.results["tls_findings"] = [
        ("HIGH", "TLS 1.0 enabled", "TLS 1.0 handshake accepted"),
        ("LOW", "No TLS 1.3", "TLS 1.3 not offered"),
    ]
    asyncio.run(nv.WebsiteRecon.compliance_map(recon))
    controls = []
    for fw in recon.results["compliance"]["frameworks"].values():
        controls.extend(fw.get("controls", []))
    tls_rows = [c for c in controls if c["ref"] in ("4.2.1", "A.8.24", "CC6.6")]
    assert tls_rows
    for row in tls_rows:
        assert "TLS 1.1" not in row["evidence"], row
        assert "TLS 1.0" in row["evidence"], row


def test_export_canonical_risk_compliance_and_inventory(nv, recon):
    recon.results["compliance"] = {
        "coverage_pct": 80, "assessment_completeness_pct": 80,
        "pass_rate_pct": 75, "total_controls": 10, "total_pass": 6,
        "total_partial": 2, "total_fail": 1, "evidence_required": 1,
        "frameworks": {},
    }
    recon.results["api_endpoints"] = [
        "http://127.0.0.1:1/api/v1/users/1",
        {"url": "/api/v1/users/2"},
    ]
    recon.results["admin_findings"] = [
        ("HIGH", "Admin panel exposed", "/admin reachable"),
        ("INFO", "Admin banner", "observed"),
        ("HIGH", "Admin panel exposed", "/admin reachable"),
    ]
    rep = nv.WebsiteRecon.export_dict(recon)
    assert rep["risk"]["score"] == rep["summary"]["risk_score"]
    assert rep["risk"]["label"] == "EXPOSURE RISK"
    assert rep["findings_total"] == len(rep["findings"])
    assert sum(rep["severity_counts"].values()) == rep["findings_total"]
    # /users/1 and /users/2 collapse to one normalised endpoint
    assert rep["summary"]["api_endpoints"] == len(rep["endpoint_inventory"]) == 1
    # duplicate admin finding collapses; INFO is not a finding
    assert rep["summary"]["admin_api_findings"] == 1
    assert len(rep["admin_api"]["findings"]) == 1
    # compliance keeps coverage and pass-rate as separate exported metrics
    comp = rep["compliance"]
    assert comp["pass_rate_pct"] == 75
    assert comp["assessment_completeness_pct"] == 80
    assert comp["total_pass"] == 6


def test_fingerprint_ignores_severity_and_source(nv, recon):
    a = nv.WebsiteRecon._finding_fingerprint(recon, "HIGH", "Same issue", "detail", "api")
    b = nv.WebsiteRecon._finding_fingerprint(recon, "LOW", "same issue", "detail", "other")
    assert a == b


def test_cvss_skips_info_and_pattern_only_secrets(nv, recon):
    import asyncio

    recon.results["tls_findings"] = [
        ("INFO", "TLS 1.0 not offered", "Status: PASS — not offered"),
    ]
    recon.results["js_secret"] = {"findings": [{
        "severity": "HIGH", "check": "JS secret — AWS Access Key",
        "detail": "AKIA…MPLE — pattern match, not proof the key is live",
    }]}
    asyncio.run(nv.WebsiteRecon.cvss_score_findings(recon))
    cvss = recon.results["cvss"]
    assert cvss["count"] == 0
    assert len(cvss["skipped"]) == 2


def test_poc_port_is_only_generated_for_observed_open_port(nv, recon):
    recon.results["ports"] = []
    cmds = recon._poc_commands_for("HIGH", "open port", "port 76 is exposed")
    assert not any("telnet://" in c["cmd"] for c in cmds)
    recon.results["ports"] = [80]
    cmds = recon._poc_commands_for("HIGH", "open port", "port 80 is exposed")
    assert any("telnet://" in c["cmd"] and ":80" in c["cmd"] for c in cmds)


def test_sri_remediation_does_not_recommend_waf(nv, recon):
    title, fix = recon._remediation_for(
        "HIGH", "No Subresource Integrity",
        "third-party executable resources lack SRI; CDN-hosted assets")
    assert "Subresource Integrity" in title
    assert "Front the edge" not in fix


def test_non_risk_markers_do_not_hide_real_findings(nv, recon):
    assert not recon._is_non_risk_text("SSRF bypass", "bypass via header")
    assert not recon._is_non_risk_text("MFA disabled", "account lockout disabled")
    assert not recon._is_non_risk_text("Metadata service", "cloud metadata reachable")
    assert recon._is_non_risk_text("TLS 1.0", "Status: PASS — not offered")
    assert recon._is_non_risk_text("Breach monitoring", "Status: NOT_CONFIGURED")


def test_canonical_root_findings_carry_child_metadata(nv, recon):
    detail = ("TLS 1.0 handshake accepted at https://example.com:443 — "
              "disable TLS 1.0 (CWE-326)")
    recon.results["tls_findings"] = [
        ("INFO", "TLS 1.0 not offered", "Status: PASS — not offered (CVSS N/A)"),
        ("HIGH", "TLS 1.0 enabled", detail),
    ]
    recon.results["diff_findings"] = [
        ("INFO", "new open port observed", "Status: OBSERVED — 1 new port: 8080"),
    ]
    recon.results["breach"] = {"findings": [
        ("INFO", "Breach Monitoring Not Configured",
         "Status: NOT_CONFIGURED — set HIBP_API_KEY"),
    ]}
    fp = recon._finding_fingerprint("HIGH", "TLS 1.0 enabled", detail, "tls")
    recon.results["patch"] = {"patches": [{
        "severity": "HIGH", "check": "TLS 1.0 enabled", "source": "tls",
        "finding": detail, "title": "Modernise TLS configuration",
        "remediation": "Disable TLS 1.0 and 1.1.", "fingerprint": fp,
    }]}
    recon.results["poc"] = {"pocs": [{
        "severity": "HIGH", "check": "TLS 1.0 enabled", "source": "tls",
        "finding": detail, "fingerprint": fp,
        "commands": [{"desc": "Read certificate", "cmd": "openssl s_client -connect example.com:443"}],
    }]}
    recon.results["cvss"] = {"count": 1, "register": [{
        "severity": "HIGH", "cvss_severity": "HIGH", "source_severity": "HIGH",
        "check": "TLS 1.0 enabled", "source": "tls", "detail": detail,
        "cvss4_score": 8.2, "cvss31_score": 7.4,
        "cvss4_vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N",
        "cvss31_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 8.2, "category": "tls_legacy", "cwe": "CWE-326",
        "cwe_name": "Inadequate Encryption Strength", "rebanded": None,
        "fingerprint": fp,
    }]}
    recon.results["attack_map"] = {"techniques": [{
        "id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access",
        "examples": [{"check": "TLS 1.0 enabled", "severity": "HIGH",
                      "detail": detail, "fingerprint": fp}],
    }]}

    rep = nv.WebsiteRecon.export_dict(recon)
    # PASS/NOT_CONFIGURED/OBSERVED stay in their module evidence, not counters.
    assert rep["findings_total"] == 1
    assert rep["severity_counts"]["HIGH"] == 1
    assert rep["severity_counts"]["INFO"] == 0
    assert rep["finding_index"]["count"] == len(rep["findings"]) == 1
    assert rep["root_findings"]
    f = rep["findings"][0]
    for field in ("title", "category", "status", "severity", "confidence", "cvss",
                  "evidence", "affected_assets", "poc", "remediation", "cwe",
                  "attack", "finding_id", "fingerprint"):
        assert field in f, field
    assert f["status"] == f["lifecycle"] == "OBSERVED"
    assert f["cvss"]["score"] == 8.2
    assert f["cvss"]["cwe"] == "CWE-326"
    assert f["cwe"] == "CWE-326"
    assert any("example.com" in a for a in f["affected_assets"])
    assert f["poc"] and "openssl" in f["poc"][0]["cmd"]
    assert f["remediation"]["title"] == "Modernise TLS configuration"
    assert f["attack"][0]["id"] == "T1040"
    assert not any(x["title"] in ("TLS 1.0 not offered", "new open port observed",
                                  "Breach Monitoring Not Configured")
                   for x in rep["findings"])


def test_regular_html_has_canonical_findings_and_counts(nv, recon):
    recon.results["tls_findings"] = [
        ("HIGH", "TLS 1.0 enabled", "TLS 1.0 handshake accepted at https://example.com:443"),
        ("INFO", "TLS 1.1 not offered", "Status: PASS — not offered (CVSS N/A)"),
    ]
    rep = nv.WebsiteRecon.export_dict(recon)
    html = nv.WebsiteRecon._render_html(rep)
    assert "EXPOSURE RISK" in html
    assert "Root Findings (1)" in html
    assert "TLS 1.0 enabled" in html
    assert "TLS 1.1 not offered" not in html
    assert "INFO: 0" in html
    assert "HIGH: 1" in html
    assert "TOTAL: 1" in html


def test_email_finding_triples_export_without_unpacking_error(nv, recon):
    recon.results["email_findings"] = [
        ("HIGH", "SPF uses '+all'", "Replace with -all and validate DMARC alignment"),
    ]
    rep = nv.WebsiteRecon.export_dict(recon)
    row = rep["email_security"]["findings"][0]
    assert row == {
        "severity": "HIGH",
        "check": "SPF uses '+all'",
        "detail": "Replace with -all and validate DMARC alignment",
    }
    assert rep["findings_total"] == 1
    assert rep["findings"][0]["title"] == "SPF uses '+all'"
    assert "Replace with -all" in rep["findings"][0]["evidence"]


def test_empty_canonical_list_suppresses_module_observations(nv, recon):
    recon.results["tls_findings"] = [
        ("INFO", "TLS 1.0 not offered", "Status: PASS — TLS 1.0 is not offered (CVSS N/A)"),
    ]
    rep = nv.WebsiteRecon.export_dict(recon)
    assert rep["findings_total"] == 0
    assert rep["findings"] == []
    html = nv.WebsiteRecon._render_html(rep)
    assert "TLS 1.0 not offered" not in html
    assert "INFO: 0" in html
    assert "TOTAL: 0" in html
    exec_html = recon.build_executive_html(rep)
    assert "TLS 1.0 not offered" not in exec_html


def test_enrichment_sections_are_not_finding_lists(nv, recon):
    recon.results["tls_findings"] = [
        ("HIGH", "TLS 1.0 enabled", "TLS 1.0 handshake accepted"),
    ]
    recon.results["cvss"] = {"count": 1, "register": [], "examples": [{"check": "x"}]}
    recon.results["attack_map"] = {"techniques": [], "examples": [{"check": "x"}]}
    rep = nv.WebsiteRecon.export_dict(recon)
    assert "findings" not in rep["cvss"]
    assert "findings" not in rep["mitre_attack"]
    assert rep["findings_total"] == len(rep["findings"]) == 1


def test_tls13_not_offered_remains_low_config_gap(nv, recon):
    recon.results["tls_findings"] = [
        ("LOW", "No TLS 1.3", "TLS 1.3 not offered — consider enabling modern TLS"),
    ]
    rep = nv.WebsiteRecon.export_dict(recon)
    assert rep["findings_total"] == 1
    assert rep["findings"][0]["title"] == "No TLS 1.3"
    assert rep["findings"][0]["severity"] == "LOW"


def test_cvss_does_not_autoraise_config_gaps(nv, recon):
    import asyncio

    recon.results["email_findings"] = [
        ("HIGH", "SPF uses '+all'", "Explicit permissive policy"),
        ("MEDIUM", "No DMARC record", "Publish a DMARC policy"),
        ("LOW", "No MTA-STS record", "Publish MTA-STS"),
    ]
    asyncio.run(nv.WebsiteRecon.cvss_score_findings(recon))
    rows = recon.results["cvss"]["register"]
    assert rows
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for row in rows:
        assert row["score"] < 9.0
        assert row["cvss_severity"] != "CRITICAL"
        assert rank[row["cvss_severity"]] <= rank[row["source_severity"]]


def test_threat_intel_match_keeps_low_requires_validation(nv, recon):
    recon.results["intel"] = {"findings": [(
        "LOW", "Threat Intelligence Match",
        "example.com appears in 2 OTX pulses · Status: REQUIRES_VALIDATION · "
        "confidence: MEDIUM · external third-party match, not evidence of compromise",
    )]}
    rep = nv.WebsiteRecon.export_dict(recon)
    assert rep["findings_total"] == 1
    assert rep["severity_counts"]["LOW"] == 1
    f = rep["findings"][0]
    assert f["severity"] == "LOW"
    assert f["status"] == "REQUIRES_VALIDATION"
    assert f["confidence"] == "MEDIUM"
    # A third-party listing is not scored/treated as a confirmed vulnerability.
    assert f["cvss"]["status"] == "N/A"
    assert f["cvss"]["score"] is None


def test_secret_redaction_is_idempotent_and_keeps_context(nv):
    masked = "JS secret (AWS Access Key) in https://x/app.js: AKIAIO…MPLE"
    assert nv._redact_secret(masked) == masked
    raw = "AKIAIOSFODNN7EXAMPLE"
    red = nv._redact_secret(f"AWS key: {raw}")
    assert raw not in red
    assert red.startswith("AWS key: ")


def test_url_redaction_masks_sensitive_query_and_userinfo(nv):
    assert (nv._redact_url("/api/users?token=abc&page=2")
            == "/api/users?token=REDACTED&page=2")
    assert nv._redact_url("https://user:pass@example.com/x?api_key=k") == \
        "https://user:REDACTED@example.com/x?api_key=REDACTED"
    assert nv._redact_url("https://example.com/a?page=2") == \
        "https://example.com/a?page=2"



def test_scope_validation_target_and_allowlist(nv):
    r = nv.WebsiteRecon("https://www.example.com",
                        allow_hosts=["partner.example.net"])
    assert r._in_scope_url("https://www.example.com/a")
    assert r._in_scope_url("https://api.www.example.com/a")
    assert r._in_scope_url("https://example.com/a")          # www -> apex
    assert r._in_scope_url("https://partner.example.net/x")  # explicit allowlist
    assert not r._in_scope_url("https://evil.example/x")
    assert not r._in_scope_url("https://example.com.evil.test/x")
    assert r._in_scope_url("https://otx.alienvault.com/api")
    assert not r._in_scope_url("https://otx.alienvault.com/api", redirect=True)


def test_scoped_client_blocks_out_of_scope_redirect(nv):
    import asyncio
    import httpx

    r = nv.WebsiteRecon("http://127.0.0.1")
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if req.url.path == "/redir":
            return httpx.Response(302, headers={"location": "https://evil.example/"},
                                  request=req)
        if req.url.path == "/hop":
            return httpx.Response(302, headers={"location": "/ok"}, request=req)
        return httpx.Response(200, text="ok", request=req)

    inner = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                              follow_redirects=True)
    client = nv.ScopedAsyncClient(inner, r._in_scope_url)

    async def go():
        with pytest.raises(httpx.ConnectError):
            await client.get("http://127.0.0.1/redir")
        ok = await client.get("http://127.0.0.1/hop")
        assert ok.status_code == 200 and ok.text == "ok"
        await inner.aclose()

    asyncio.run(go())
    assert all("evil.example" not in u for u in seen)


def test_scoped_client_rate_limits_requests(nv):
    import asyncio
    import time
    import httpx

    r = nv.WebsiteRecon("http://127.0.0.1")

    def handler(req):
        return httpx.Response(200, text="ok", request=req)

    inner = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = nv.ScopedAsyncClient(inner, r._in_scope_url, rps=20)

    async def go():
        started = time.monotonic()
        await asyncio.gather(*[client.get("http://127.0.0.1/") for _ in range(3)])
        elapsed = time.monotonic() - started
        await inner.aclose()
        return elapsed

    assert asyncio.run(go()) >= 0.08


def test_scoped_client_redirect_does_not_replay_query_params(nv):
    import asyncio
    import httpx

    r = nv.WebsiteRecon("http://127.0.0.1")
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if req.url.path == "/start":
            return httpx.Response(302, headers={"location": "/next?from=redirect"},
                                  request=req)
        return httpx.Response(200, text="ok", request=req)

    inner = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = nv.ScopedAsyncClient(inner, r._in_scope_url)

    async def go():
        resp = await client.get("http://127.0.0.1/start", params={"token": "secret"})
        assert resp.status_code == 200
        await inner.aclose()

    asyncio.run(go())
    assert seen[-1] == "http://127.0.0.1/next?from=redirect"
