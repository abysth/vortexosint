"""Tests for vortexosint.modules.network_module."""

import pytest

from vortexosint.modules import network_module


def test_parse_ports_valid():
    assert network_module.parse_ports("80,443,80,8080-8082") == [80, 443, 8080, 8081, 8082]
    assert len(network_module.parse_ports("top100")) == 40
    assert len(network_module.parse_ports("top1000")) == 1000


@pytest.mark.parametrize("bad", ["", "   ", "abc", "0", "65536", "100-50", "1-2-3", "-80"])
def test_parse_ports_invalid(bad):
    with pytest.raises(ValueError):
        network_module.parse_ports(bad)


def test_is_safe_host():
    assert network_module._is_safe_host("8.8.8.8")
    assert network_module._is_safe_host("192.168.1.0/24")
    assert network_module._is_safe_host("example.com")
    assert not network_module._is_safe_host("")
    assert not network_module._is_safe_host("-n")
    assert not network_module._is_safe_host("--version")
    assert not network_module._is_safe_host("127.0.0.1;whoami")


def test_expand_targets_cidr():
    assert network_module._expand_targets("127.0.0.1") == ["127.0.0.1"]
    assert network_module._expand_targets("127.0.0.1/30") == ["127.0.0.1", "127.0.0.2"]
    assert len(network_module._expand_targets("10.0.0.0/22", max_hosts=10)) == 10


def test_lookup_asn_invalid_format():
    res = network_module.lookup_asn("NOT_AN_ASN")
    assert "error" in res


def test_lookup_asn_mocked(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {
                "data": {
                    "name": "GOOGLE",
                    "description_short": "Google LLC",
                    "country_code": "US",
                    "website": "https://google.com",
                    "rir_allocation": {"rir_name": "ARIN"},
                }
            }

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    res = network_module.lookup_asn("AS15169")
    assert res["asn"] == "AS15169"
    assert res["name"] == "GOOGLE"
    assert res["country"] == "US"
