"""Tests for vortexosint.modules.password_module."""

import argparse
import contextlib
import io
import json

from vortexosint.modules import password_module


def test_generate_excludes_ambiguous_chars():
    ns = argparse.Namespace(
        length=24, count=40, no_uppercase=False, no_digits=False,
        no_symbols=False, allow_ambiguous=False, output=None, format="json",
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = password_module.generate_mode(ns)
    assert rc == 0
    lines = [l.strip() for l in buf.getvalue().splitlines() if len(l.strip()) == 24 and " " not in l.strip()]
    assert len(lines) == 40
    for pw in lines:
        assert not any(c in password_module.AMBIGUOUS for c in pw)


def test_passphrase_word_count():
    ns = argparse.Namespace(words=6, separator="-", output=None, format="json")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = password_module.passphrase_mode(ns)
    assert rc == 0
    phrases = [l.strip() for l in buf.getvalue().splitlines() if l.strip().count("-") == 5 and " " not in l.strip()]
    assert len(phrases) == 1
    assert len(phrases[0].split("-")) == 6


def test_audit_common_vs_strong():
    weak = password_module._audit("password")
    assert weak["common"] is True
    assert weak["score"] == 0

    strong = password_module._audit("Tr0ub4dor&3!XyZ9#qW2")
    assert strong["common"] is False
    assert strong["score"] >= 4


def test_hash_mode_and_metadata_export(tmp_path):
    out = tmp_path / "hash.json"
    ns = argparse.Namespace(hash="MySecretPass!", algo="sha256", salt="fixedsalt", output=str(out), format="json")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = password_module.hash_mode(ns)
    assert rc == 0
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["algo"] == "sha256"
    assert saved["salt"] == "fixedsalt"
    assert len(saved["digest"]) == 64
    assert "MySecretPass!" not in out.read_text(encoding="utf-8")
