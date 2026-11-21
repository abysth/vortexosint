"""Tests for vortexosint.core.output."""

import argparse
import csv
import io
import json

from vortexosint.core import output


def test_csv_escaping_handles_quotes_commas_and_newlines():
    data = {
        "example.com": {
            "type": "domain",
            "findings": {"note": 'hello "world", line1\nline2'},
        }
    }
    raw_csv = output.format_results_csv(data, mode="target")
    rows = list(csv.reader(io.StringIO(raw_csv)))
    assert rows[0] == ["target", "type", "key", "value"]
    assert rows[1] == ["example.com", "domain", "note", 'hello "world", line1\nline2']


def test_output_results_writes_utf8_json_txt_csv(tmp_path):
    results = {
        "cible": {
            "type": "osint",
            "findings": {"ville": "Montréal", "accent": "éàü"},
        }
    }
    for fmt in ("json", "txt", "csv"):
        out_file = tmp_path / f"res.{fmt}"
        args = argparse.Namespace(output=str(out_file), format=fmt)
        output.output_results(results, args, mode="target")
        text = out_file.read_text(encoding="utf-8")
        assert "Montréal" in text
        if fmt == "json":
            parsed = json.loads(text)
            assert parsed["cible"]["findings"]["accent"] == "éàü"
