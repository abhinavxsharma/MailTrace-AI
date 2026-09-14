"""
Email forensic MIME parser using Python standard library (email.parser.BytesParser).
Extracts RFC 5322 headers, multipart content, text/HTML bodies, and attachment metadata safely.
Never executes attachments, HTML, scripts, or network calls.
"""

import email
from email import policy
from email.parser import BytesParser
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.email import EmailSchema


def parse_email_bytes(raw_bytes: bytes) -> Tuple[EmailSchema, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Safely parse raw email bytes into a structured EmailSchema and metadata.

    Args:
        raw_bytes: Raw RFC 5322 byte sequence.

    Returns:
        Tuple of (EmailSchema, attachments_metadata, raw_headers_dict)

    Raises:
        ValueError: If parsing completely fails on non-email bytes.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise TypeError(f"parse_email_bytes expects bytes or bytearray, got {type(raw_bytes).__name__}")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        try:
            msg = email.message_from_bytes(raw_bytes)
        except Exception as e:
            raise ValueError(f"Malformed or unparseable email sequence: {str(e)}")

    # Extract single-value headers
    from_header = msg.get("From")
    reply_to_header = msg.get("Reply-To")
    return_path_header = msg.get("Return-Path")
    subject_header = msg.get("Subject")
    date_header = msg.get("Date")
    message_id_header = msg.get("Message-ID")

    # Extract multi-address headers (To, Cc)
    def parse_recipients(header_value: Optional[str]) -> List[str]:
        if not header_value:
            return []
        raw_str = str(header_value)
        return [addr.strip() for addr in raw_str.split(",") if addr.strip()]

    to_addresses = parse_recipients(msg.get("To"))
    cc_addresses = parse_recipients(msg.get("Cc"))

    # Received headers (can appear multiple times, preserving sequence)
    received_headers = [str(r).strip() for r in msg.get_all("Received", [])]

    # Extract bodies and attachment metadata safely
    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            # Check content disposition and filename
            disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            filename = part.get_filename()

            if disposition == "attachment" or (filename and disposition != "inline"):
                payload = part.get_payload(decode=True)
                size_bytes = len(payload) if payload else 0
                attachments.append({
                    "filename": str(filename) if filename else "unnamed_attachment",
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                })
            else:
                # Text or HTML content
                if content_type == "text/plain":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_text_parts.append(content)
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text_parts.append(payload.decode(errors="replace"))
                elif content_type == "text/html":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_html_parts.append(content)
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html_parts.append(payload.decode(errors="replace"))
    else:
        # Non-multipart single payload
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
            if isinstance(content, str):
                if content_type == "text/html":
                    body_html_parts.append(content)
                else:
                    body_text_parts.append(content)
        except Exception:
            payload = msg.get_payload(decode=True)
            if payload:
                text_content = payload.decode(errors="replace")
                if content_type == "text/html":
                    body_html_parts.append(text_content)
                else:
                    body_text_parts.append(text_content)

    body_text = "\n".join(body_text_parts) if body_text_parts else None
    body_html = "\n".join(body_html_parts) if body_html_parts else None

    # Construct normalized EmailSchema
    email_schema = EmailSchema(
        from_address=str(from_header).strip() if from_header else None,
        to_addresses=to_addresses,
        cc_addresses=cc_addresses,
        reply_to=str(reply_to_header).strip() if reply_to_header else None,
        return_path=str(return_path_header).strip() if return_path_header else None,
        subject=str(subject_header).strip() if subject_header else None,
        date=str(date_header).strip() if date_header else None,
        message_id=str(message_id_header).strip() if message_id_header else None,
        received_headers=received_headers,
        body_text=body_text,
        body_html=body_html,
        attachment_count=len(attachments),
    )

    # Collect raw headers dictionary (multi-value headers aggregated into lists)
    raw_headers: Dict[str, Any] = {}
    for key, val in msg.items():
        val_str = str(val).strip()
        if key in raw_headers:
            if isinstance(raw_headers[key], list):
                raw_headers[key].append(val_str)
            else:
                raw_headers[key] = [raw_headers[key], val_str]
        else:
            raw_headers[key] = val_str

    return email_schema, attachments, raw_headers
