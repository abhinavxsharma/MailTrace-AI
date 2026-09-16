# MAILTRACE AI — Security & Forensic Safety Architecture

## 1. Overview
MAILTRACE AI is designed with strict cybersecurity controls and forensic evidence handling principles. Because incoming emails during SOC triage and incident response are inherently untrusted and frequently weaponized, the platform enforces hard isolation, passive analysis, and cryptographic immutability at every stage.

---

## 2. Evidence Preservation & Cryptographic Immutability

### 2.1 SHA-256 Chain of Custody
- **Immediate Hashing**: As soon as a raw `.eml` payload is received at `/api/cases/upload`, its cryptographic SHA-256 digest is calculated directly from the raw byte stream before any parsing or processing occurs.
- **Dedicated Evidence Storage**: The raw payload is stored under `evidence/{case_id}/raw.eml`.
- **Integrity Verification**: The `/api/cases/{case_id}/verify` endpoint recalculates the SHA-256 hash of the on-disk file and compares it against the case metadata recorded in the database.
- **Tamper Detection**: If even a single byte of `raw.eml` is altered, verification fails immediately with a `TAMPERED` status and an immutable audit log entry is recorded.
- **Reporting Guarantee**: Both PDF and JSON forensic reports bind the calculated evidence SHA-256 and confirm that evidence bytes remained unaltered during the entire analysis workflow.

---

## 3. Passive Analysis & Isolation Guarantees

### 3.1 Attachment Non-Execution
- **Zero Execution**: MAILTRACE AI parses MIME structures solely to extract attachment names, sizes, MIME types, and computed hashes.
- **No Sandboxing/Execution**: Attachments are never executed, unpacked into executable memory, or passed to system shell interpreters.

### 3.2 URL Non-Execution & Safe Parsing
- **Zero HTTP Ingestion**: Extracted URLs from email headers, HTML anchor tags, and plain text bodies are **never** fetched, crawled, or pinged over HTTP/HTTPS.
- **Syntactic & Lexical Analysis**: URLs are only parsed via Python's standard `urllib.parse` and regex tokenizers to evaluate domain structure, IP-in-URL obfuscation, punycode/homoglyph risks, and entropy.
- **Display Sanitization**: Frontend views display URLs as raw sanitized strings, preventing inadvertent client-side browser navigation.

### 3.3 Safe Header & MIME Parsing
- Built on Python’s native standard library `email.parser.BytesParser` and `email.policy.default`.
- Defensively catches malformed RFC 5322 headers, recursive MIME bombs, and encoding anomalies without crashing the FastAPI backend.

---

## 4. Forensic Safety Language & Attribution Principles

In accordance with professional digital forensics and intelligence ethics:
- **Infrastructure Attribution**: Discovered IP addresses, autonomous systems (ASNs), and DNS records are described strictly as:
  > *"Observed Source Infrastructure"*
- **Campaign Attribution**: Cross-case cluster relationships sharing infrastructure, domains, or subjects are explicitly qualified as:
  > *"Potential Campaign Relationship"*
- **Attribution Guardrail**: The platform **NEVER** issues definitive claims of *"same attacker"*, as IP addresses and compromised SMTP relays are subject to multi-tenancy, spoofing, botnets, and DHCP reassignment.

---

## 5. Network Timeouts & Offline Resilience

- **Strict Network Timeouts**:
  - DNS resolutions (A, AAAA, MX, NS, TXT) via `dnspython` are bounded by a strict `2.0s` timeout.
  - RDAP queries are bounded by a strict `5.0s` timeout with graceful exception handling.
- **Graceful Degradation**: If network interfaces are offline, or if third-party RDAP/DNS services are unreachable:
  - Modules report `UNAVAILABLE` or `LOOKUP_FAILED` status.
  - Analysis pipelines proceed without interruption.
  - Fallback local GeoIP (MaxMind GeoLite2) is used if configured; otherwise returns standard offline status.
  - The risk scoring fusion engine gracefully isolates missing telemetry without raising uncaught exceptions.

---

## 6. API Hardening & Input Validation

- **Case ID Validation**: All endpoints enforce strict alphanumeric regex validation (`^[a-fA-F0-9_-]{1,64}$`) preventing directory traversal (`../`) and injection attacks.
- **Path Traversal Guards**: Filename sanitization strips relative path prefixes, Windows drive paths, and null bytes before any file operations.
- **File Upload Limits**: Ingestion enforces strict payload limits (15 MB default max) to prevent memory exhaustion and Denial of Service (DoS).
- **CORS Restraint**: CORS middleware is restricted to designated local origins (`http://127.0.0.1:5173`, `http://localhost:5173`) rather than open wildcards (`*`).
- **Structured Error Handling**: All HTTP exceptions return structured JSON payloads (`{"detail": "..."}`) without exposing internal Python tracebacks or framework internals.

---

## 7. Audit Trail & Chain of Custody

The database tracks non-destructive, timestamped audit events for every critical case operation:
- `UPLOAD`: Raw file ingested and hashed.
- `PARSED`: MIME headers and body extracted.
- `VERIFIED`: Cryptographic integrity confirmed.
- `ANALYZED`: AI classification and feature extraction complete.
- `INFRASTRUCTURE_ENRICHED`: DNS and RDAP intelligence gathered.
- `CAMPAIGN_CORRELATED`: Forensic graph relationships identified.
- `REPORT_GENERATED`: Cryptographically bound PDF/JSON exported.
