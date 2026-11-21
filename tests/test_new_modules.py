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


def test_ssl_parse_cert_dict():
    from vortexosint.modules import ssl_module

    fake_cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "serialNumber": "1234ABCD",
    }
    parsed = ssl_module.parse_cert_dict(fake_cert, b"fake-der", protocol="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
    assert parsed["common_name"] == "example.com"
    assert parsed["san_count"] == 2
    assert parsed["expired"] is False
    assert parsed["tls_version"] == "TLSv1.3"
    assert len(parsed["sha256_fingerprint"]) == 64


def test_mac_module_analysis():
    from vortexosint.modules import mac_module

    pi = mac_module.analyze_mac("b8-27-eb-11-22-33", online=False)
    assert pi["valid"] is True
    assert pi["mac_colon"] == "B8:27:EB:11:22:33"
    assert pi["is_randomized"] is False
    assert "Raspberry Pi" in pi["vendor"]

    rand_mac = mac_module.analyze_mac("02:11:22:33:44:55", online=False)
    assert rand_mac["valid"] is True
    assert rand_mac["is_randomized"] is True

    bad = mac_module.analyze_mac("not-a-mac", online=False)
    assert bad["valid"] is False


def test_url_phishing_and_tracking_strip():
    from vortexosint.modules import url_module

    clean = url_module.clean_tracking_params("https://example.com/page?id=42&utm_source=x&fbclid=abc")
    assert clean["cleaned_url"] == "https://example.com/page?id=42"
    assert set(clean["removed_params"]) == {"utm_source", "fbclid"}

    risky = url_module.analyze_phishing_heuristics("http://192.168.1.1/login-verify-paypal")
    assert risky["risk_level"] == "HIGH"
    assert risky["risk_score"] >= 50

    safe = url_module.analyze_phishing_heuristics("https://example.com/about")
    assert safe["risk_level"] == "LOW"


def test_tech_fingerprint_response():
    from vortexosint.modules import tech_module

    headers = {"Server": "cloudflare", "X-Powered-By": "Express", "CF-Ray": "abc123"}
    html = "<html><head><title>Demo</title></head><body><script src='/wp-content/app.js'></script><script src='https://js.stripe.com/v3/'></script></body></html>"
    res = tech_module.fingerprint_response(headers, html, cookies=["PHPSESSID"])
    assert res["page_title"] == "Demo"
    assert "Cloudflare" in res["technologies"]["CDN/WAF"]
    assert "WordPress" in res["technologies"]["CMS"]
    assert "Stripe" in res["technologies"]["Payments"]
    assert "PHP" in res["technologies"]["Language"]


def test_breach_pwned_password_mocked(monkeypatch):
    import hashlib
    from vortexosint.modules import breach_module

    sha1 = hashlib.sha1(b"password123").hexdigest().upper()
    suffix = sha1[5:]

    class FakeResp:
        status_code = 200
        text = f"00000000000000000000000000000000000:1\n{suffix}:98765\n"

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    res = breach_module.check_pwned_password("password123")
    assert res["pwned"] is True
    assert res["occurrences"] == 98765


def test_dns_passive_subdomains_mocked(monkeypatch):
    from vortexosint.modules import dns_module

    class FakeResp:
        def __init__(self, status_code, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    def fake_get(url, **kw):
        if "crt.sh" in url:
            return FakeResp(200, [{"name_value": "*.api.example.com\nwww.example.com"}])
        if "hackertarget" in url:
            return FakeResp(200, text="mail.example.com,1.2.3.4\n")
        return FakeResp(404)

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    res = dns_module.enumerate_subdomains_passive("example.com")
    assert res["count"] == 3
    assert set(res["subdomains"]) == {"api.example.com", "www.example.com", "mail.example.com"}


def test_multipage_menu_and_quick_specs():
    from vortexosint.cli import MENU_PAGES, QUICK_SPECS, MODULE_HANDLERS

    assert len(MENU_PAGES) == 2
    app = VortexOSINT()
    idx = app._menu_index()
    # Every quick ref in MENU_PAGES exists in QUICK_SPECS (or o_wayback) and every module exists in MODULE_HANDLERS
    for _num, kind, ref, _label in idx:
        if kind == "module":
            assert ref in MODULE_HANDLERS
        else:
            assert ref == "o_wayback" or ref in QUICK_SPECS

    # CLI routing for a new offline module (mac)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = app.run(["--no-banner", "--no-color", "mac", "--mac", "B8:27:EB:AA:BB:CC", "--offline"])
    assert rc == 0
    assert "Raspberry Pi" in buf.getvalue()


def test_builtin_tutorial_covers_all_modules():
    from vortexosint.cli import MODULE_HANDLERS
    from vortexosint.core.tutorial import TUTORIALS

    assert set(MODULE_HANDLERS.keys()).issubset(set(TUTORIALS.keys()))
    app = VortexOSINT()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = app.run(["--no-banner", "--no-color", "tuto", "ssl"])
    assert rc == 0
    assert "crt.sh" in buf.getvalue()

    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        rc2 = app.run(["--no-banner", "--no-color", "tuto", "setup"])
    assert rc2 == 0
    assert "Python" in buf2.getvalue()
