"""
Input validation and robustness tests for MAILTRACE AI.
Verifies safe handling of malformed MIME, script injection, fake URLs, and invalid file formats.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.forensics.parser import parse_email_bytes
from app.forensics.indicators import extract_indicators
from app.detection.classifier import strip_html_tags


@pytest.mark.asyncio
async def test_reject_non_eml_extensions():
    """Verify upload rejects executable and document extensions that are not .eml."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        disallowed_files = [
            ("malware.exe", b"MZ\x90\x00Binary"),
            ("script.js", b"alert(1);"),
            ("payload.sh", b"#!/bin/bash\nrm -rf /"),
            ("document.pdf", b"%PDF-1.4 Fake"),
            ("invoice.docx", b"PK\x03\x04Zip"),
        ]
        for fname, content in disallowed_files:
            files = {"file": (fname, content, "application/octet-stream")}
            res = await client.post("/api/cases/upload", files=files)
            assert res.status_code == 400
            assert "Only .eml files are accepted" in res.json()["detail"]


@pytest.mark.asyncio
async def test_reject_empty_file_upload():
    """Verify 0-byte upload is rejected gracefully."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("empty.eml", b"", "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 400
        assert "Uploaded file is empty" in res.json()["detail"]


def test_malformed_mime_handling():
    """Verify that malformed MIME structures parse without unhandled crashes."""
    malformed_inputs = [
        b"This is completely raw text without headers.\nSecond line.",
        b"From: <unclosed\nTo: \n\nBody",
        b"Subject: =?ISO-8859-1?Q?Malformed_Encoding=X?=\r\n\r\nHello",
        b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\nMalformed boundary",
    ]
    for raw in malformed_inputs:
        email_schema, attachments, headers = parse_email_bytes(raw)
        assert email_schema is not None
        assert isinstance(attachments, list)
        assert isinstance(headers, dict)


def test_html_script_tags_safely_stripped():
    """Verify HTML and JavaScript tags are sanitized and never executed."""
    malicious_html = """
    <html>
      <head><script>alert('pwned');</script></head>
      <body>
        <h1>Urgent Payment</h1>
        <p>Please click <a href="http://evil.example.com">here</a>.</p>
        <script src="http://evil.example.com/exploit.js"></script>
        <img src="x" onerror="stealCookies()" />
      </body>
    </html>
    """
    clean_text = strip_html_tags(malicious_html)
    assert "<script>" not in clean_text
    assert "stealCookies" not in clean_text
    assert "alert('pwned')" not in clean_text
    assert "Urgent Payment" in clean_text


def test_indicator_extraction_handles_extreme_inputs():
    """Verify indicator extractor safely handles long URLs, repeated strings, and malformed IP syntax."""
    extreme_text = (
        "Check http://safe.example.com and http://evil.com/path?arg=" + ("A" * 1000) +
        " and invalid IPs like 999.999.999.999 or 256.1.1.1 or 127.0.0.1"
    )
    indicators = extract_indicators(subject="Extreme test", body_text=extreme_text)
    assert isinstance(indicators, list)
    domains = [i.value for i in indicators if i.type == "domain"]
    assert "safe.example.com" in domains
    # 999.999.999.999 is invalid and must not be classified as a valid public IP
    ips = [i.value for i in indicators if i.type == "ip"]
    assert "999.999.999.999" not in ips
