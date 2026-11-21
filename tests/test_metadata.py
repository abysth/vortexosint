"""Tests for vortexosint.modules.metadata_module."""

import hashlib
import zipfile
from pathlib import Path

from vortexosint.modules import metadata_module


def test_calculate_hashes_matches_hashlib(tmp_path):
    p = tmp_path / "sample.bin"
    payload = b"VortexOSINT-test-data" * 5000
    p.write_bytes(payload)

    hashes = metadata_module.calculate_hashes(p)
    assert hashes["md5"] == hashlib.md5(payload).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(payload).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(payload).hexdigest()


def test_extract_strings(tmp_path):
    p = tmp_path / "bin.dat"
    p.write_bytes(b"\x00\x01HelloWorld\x00\x02ab\x00VortexOSINT\x00")
    strings = metadata_module.extract_strings(p)
    assert "HelloWorld" in strings
    assert "VortexOSINT" in strings
    assert "ab" not in strings


def test_analyze_pdf_real_file(tmp_path):
    import PyPDF2

    pdf_path = tmp_path / "doc.pdf"
    writer = PyPDF2.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_metadata({"/Title": "Secret Report", "/Author": "Alice"})
    with open(pdf_path, "wb") as f:
        writer.write(f)

    info = metadata_module.analyze_pdf(pdf_path)
    assert info["pages"] == 1
    assert info["title"] == "Secret Report"
    assert info["author"] == "Alice"
    assert info["encrypted"] is False


def test_analyze_office_ooxml(tmp_path):
    docx_path = tmp_path / "sample.docx"
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        '<dc:title>Audit Doc</dc:title>'
        '<dc:creator>Bob</dc:creator>'
        '</cp:coreProperties>'
    )
    app_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>LibreOffice</Application>'
        '</Properties>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)

    info = metadata_module.analyze_office(docx_path)
    assert info["title"] == "Audit Doc"
    assert info["author"] == "Bob"
    assert info["application"] == "LibreOffice"


def test_extract_exif_on_plain_png(tmp_path):
    from PIL import Image

    img_path = tmp_path / "plain.png"
    Image.new("RGB", (10, 10), color="red").save(img_path)
    res = metadata_module.extract_exif(img_path)
    assert res["has_exif"] is False
