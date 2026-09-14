"""
Tests for email forensic parsing, multipart handling, and attachment extraction.
"""

from pathlib import Path
import pytest

from app.forensics.parser import parse_email_bytes


def test_parse_real_bec_fixture():
    """Verify parsing on the authentic demo_bec_invoice.eml sample."""
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists(), "samples/bec/demo_bec_invoice.eml fixture must exist"

    raw_bytes = sample_path.read_bytes()
    email_schema, attachments, raw_headers = parse_email_bytes(raw_bytes)

    assert "cfo@acme-finance.com" in email_schema.from_address.lower()
    assert "accounts@acme.edu" in [addr.lower() for addr in email_schema.to_addresses]
    assert "acme.invoice.alert@gmail.com" in email_schema.reply_to.lower()
    assert "billing@notify-acme.co" in email_schema.return_path.lower()
    assert "urgent" in email_schema.subject.lower()
    assert email_schema.message_id is not None
    assert len(email_schema.received_headers) >= 2
    assert email_schema.body_html is not None
    assert "https://secure-acme-login.example/verify-invoice" in email_schema.body_html
    assert email_schema.attachment_count == 0


def test_parse_multipart_with_attachment_metadata():
    """Verify parsing a multipart message safely extracts attachment metadata without executing."""
    multipart_eml = (
        b"From: sender@company.com\r\n"
        b"To: recipient@company.com\r\n"
        b"Subject: Multipart Test with Attachment\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="boundary-123"\r\n'
        b"\r\n"
        b"--boundary-123\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n'
        b"\r\n"
        b"Please review the attached invoice PDF.\r\n"
        b"--boundary-123\r\n"
        b'Content-Type: application/pdf; name="invoice_september.pdf"\r\n'
        b'Content-Disposition: attachment; filename="invoice_september.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQKJcTl8uXrCg==\r\n"
        b"--boundary-123--\r\n"
    )

    email_schema, attachments, raw_headers = parse_email_bytes(multipart_eml)

    assert email_schema.from_address == "sender@company.com"
    assert email_schema.subject == "Multipart Test with Attachment"
    assert "Please review the attached invoice PDF." in email_schema.body_text
    assert email_schema.attachment_count == 1
    assert len(attachments) == 1
    assert attachments[0]["filename"] == "invoice_september.pdf"
    assert attachments[0]["content_type"] == "application/pdf"
    assert attachments[0]["size_bytes"] > 0


def test_parse_malformed_input_does_not_crash():
    """Verify parser handles broken / non-standard input gracefully."""
    broken_eml = b"This is not a valid email header format at all.\nJust arbitrary random text."
    email_schema, attachments, raw_headers = parse_email_bytes(broken_eml)
    assert email_schema is not None
    assert email_schema.attachment_count == 0


def test_parse_type_error():
    """Verify passing non-bytes raises TypeError."""
    with pytest.raises(TypeError):
        parse_email_bytes("string not bytes")
