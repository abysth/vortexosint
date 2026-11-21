"""Tests for OSINT, GEOSINT, Social modules and CLI integration."""

import argparse
import contextlib
import io

from vortexosint.cli import VortexOSINT
from vortexosint.modules import geosint_module, osint_module, social_module


def test_osint_email_and_phone_helpers():
    assert osint_module.validate_email_format("alice@example.com") is True
    assert osint_module.validate_email_format("not-an-email") is False

    deliv = osint_module.check_deliverability("admin@mailinator.com", mx_records=["10 mx.mailinator.com"])
    assert deliv["disposable"] is True
    assert deliv["role_account"] is True
    assert deliv["deliverable"] is False

    parsed = osint_module.parse_phone("+33 6 12 34 56 78")
    assert parsed["country_code"] == "+33"
    assert osint_module.lookup_phone_location("+33 6 12 34 56 78")["country"] == "France"
    assert osint_module.detect_line_type("+33 6 12 34 56 78") == "mobile"
    assert osint_module.detect_line_type("+33 1 23 45 67 89") == "landline"


def test_osint_wayback_mocked(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return [
                ["urlkey", "timestamp", "original"],
                ["com,example)/admin.php", "20240101", "https://example.com/admin.php"],
                ["com,example)/index.html", "20240101", "https://example.com/index.html"],
            ]

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    res = osint_module.get_wayback_urls("https://example.com/foo", limit=10)
    assert res["total"] == 2
    assert "https://example.com/admin.php" in res["interesting"]


def test_social_username_check_and_availability_mocked(monkeypatch):
    class FakeResp:
        def __init__(self, status_code, text=""):
            self.status_code = status_code
            self.text = text

    import requests
    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResp(200 if "github" in url else 404))

    gh = social_module.check_username_platform("octocat", "github")
    assert gh["found"] is True
    gl = social_module.check_username_platform("octocat", "gitlab")
    assert gl["found"] is False

    app = VortexOSINT()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = app.run([
            "--no-banner", "--no-color", "social",
            "--username", "octocat", "--platforms", "github,gitlab", "--check-availability",
        ])
    assert rc == 0


def test_geosint_coords_validation_and_folium_map(tmp_path):
    ns = argparse.Namespace(radius=500, output=str(tmp_path / "geo.json"), format="json", map=True)
    bad = geosint_module.analyze_coords("999,999", ns)
    assert "error" in bad

    results = {
        "Paris": {
            "type": "coords",
            "findings": {"coordinates": {"lat": 48.8566, "lon": 2.3522}},
        }
    }
    map_path = geosint_module.generate_map(results, ns)
    assert map_path.endswith("_map.html")
    assert (tmp_path / "geo_map.html").exists()
    assert "48.8566" in (tmp_path / "geo_map.html").read_text(encoding="utf-8")
