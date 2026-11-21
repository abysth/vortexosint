"""Tests for the 7 new modules: web, emailsec, ioc, dork, github, decode, report."""

import argparse
import contextlib
import io
import json

from vortexosint.cli import VortexOSINT
from vortexosint.modules import (
    decode_module,
    dork_module,
    emailsec_module,
    github_module,
    ioc_module,
    report_module,
    web_module,
)


def test_web_security_headers_grading():
    good = web_module.audit_security_headers({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    })
    assert good["grade"] == "A"
    assert good["missing"] == []

    bad = web_module.audit_security_headers({"Server": "nginx"})
    assert bad["grade"] == "F"
    assert len(bad["missing"]) == 6


def test_emailsec_spf_and_dmarc_parsing():
    spf = emailsec_module.analyze_spf(["v=spf1 include:_spf.google.com -all"])
    assert spf["present"] is True
    assert "hardfail" in spf["policy"]

    dmarc = emailsec_module.analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])
    assert dmarc["present"] is True
    assert dmarc["policy"] == "reject"


def test_ioc_extract_and_defang_refang():
    raw = "Alert: hxxps://evil[.]com/login from 192.168.1.50 email admin[@]evil[.]com md5 d41d8cd98f00b204e9800998ecf8427e"
    assert ioc_module.defang("https://example.com") == "hxxps://example[.]com"
    assert ioc_module.refang("hxxps://evil[.]com") == "https://evil.com"

    res = ioc_module.extract_iocs(raw)
    assert "https://evil.com/login" in res["urls"]
    assert "192.168.1.50" in res["ipv4"]
    assert "admin@evil.com" in res["emails"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in res["md5"]


def test_dork_generator():
    dorks = dork_module.generate_dorks(domain="example.com", keyword="secret", engine="all")
    assert set(dorks.keys()) == {"google", "github", "shodan"}
    assert any("site:example.com" in item["query"] for item in dorks["google"])
    assert any("hostname:example.com" in item["query"] for item in dorks["shodan"])


def test_github_osint_mocked(monkeypatch):
    class FakeResp:
        def __init__(self, status_code, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    def fake_get(url, **kw):
        if url.endswith("/users/octocat"):
            return FakeResp(200, {"login": "octocat", "name": "The Octocat", "public_repos": 8, "followers": 100})
        if url.endswith("/orgs"):
            return FakeResp(200, [{"login": "github"}])
        if url.endswith("/repos"):
            return FakeResp(200, [{"name": "hello-world", "stargazers_count": 42, "language": "Python", "html_url": "https://github.com/octocat/hello-world"}])
        if url.endswith(".keys"):
            return FakeResp(200, text="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITEST\n")
        if url.endswith("/events/public"):
            return FakeResp(200, [{"type": "PushEvent", "payload": {"commits": [{"author": {"email": "octo@example.com"}}]}}])
        return FakeResp(404)

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    res = github_module.investigate_github_user("octocat")
    assert res["found"] is True
    assert res["organizations"] == ["github"]
    assert res["ssh_keys_count"] == 1
    assert "octo@example.com" in res["public_commit_emails"]


def test_decode_module_tools():
    assert decode_module.transform_base64("Vortex", encode=True) == "Vm9ydGV4"
    assert decode_module.transform_base64("Vm9ydGV4", encode=False) == "Vortex"
    assert decode_module.transform_hex("4142", encode=False) == "AB"
    assert decode_module.transform_rot13("Vortex") == "Ibegrk"

    # Minimal valid JWT (alg=HS256, sub=123)
    jwt_tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTAwMDAwMDAwMH0.sig"
    j = decode_module.decode_jwt(jwt_tok)
    assert j["header"]["alg"] == "HS256"
    assert j["payload"]["sub"] == "12345"
    assert j["expired"] is True

    h = decode_module.identify_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert "MD5" in h["candidates"]

    ts = decode_module.convert_timestamp("1700000000")
    assert ts["unix_seconds"] == 1700000000
    assert ts["utc_iso"].startswith("2023-11-14")

    cidr = decode_module.analyze_cidr("192.168.1.0/24")
    assert cidr["usable_hosts"] == 254


def test_report_module_html_and_markdown(tmp_path):
    src = tmp_path / "scan.json"
    src.write_text(json.dumps({"example.com": {"type": "web", "findings": {"grade": "A", "note": "<script>"}}}), encoding="utf-8")

    html_out = tmp_path / "report.html"
    r1 = report_module.generate_report([str(src)], str(html_out), title="Test Report")
    assert r1["format"] == "html"
    html_text = html_out.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html_text  # XSS-escaped

    md_out = tmp_path / "report.md"
    r2 = report_module.generate_report([str(src)], str(md_out), title="Test Report")
    assert r2["format"] == "markdown"
    assert "# Test Report" in md_out.read_text(encoding="utf-8")


def test_cli_routes_new_modules():
    app = VortexOSINT()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = app.run(["--no-banner", "--no-color", "decode", "--cidr", "10.0.0.0/24"])
    assert rc == 0
    assert "254" in buf.getvalue()
