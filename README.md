# MAILTRACE AI
### AI-Powered Email Threat Detection & Forensic Intelligence Platform

[![Backend CI](https://img.shields.io/badge/Backend%20Tests-141%20Passed-emerald.svg)](#)
[![TypeScript CI](https://img.shields.io/badge/TypeScript-0%20Errors-blue.svg)](#)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](#)
[![React 18](https://img.shields.io/badge/React-18.3-61dafb.svg)](#)
[![Model](https://img.shields.io/badge/Model-DistilBERT%20(Dataset%203)-purple.svg)](#)

---

## 1. Problem Statement
Business Email Compromise (BEC), credential phishing, and sophisticated email spoofing attacks inflict billions of dollars in enterprise losses annually. Legacy secure email gateways (SEGs) frequently fail against zero-day social engineering attacks that employ pristine domain reputation or hijacked accounts. Furthermore, Security Operations Center (SOC) analysts and digital forensic investigators face massive alert fatigue and lack unified, explainable tooling to rapidly decompose headers, cryptographically preserve evidence, verify protocol alignment, correlate cross-case infrastructure, and generate courtroom-admissible forensic reports.

## 2. The Solution: MAILTRACE AI
**MAILTRACE AI** is an enterprise-grade digital forensics and threat investigation console designed for SOC analysts, incident response teams, and forensic specialists. It unifies deep RFC 5322 envelope parsing, cryptographic authentication verification, sequence-aware local AI threat detection, passive infrastructure enrichment, relationship graph visualization, cross-case campaign correlation, and automated forensic PDF/JSON reporting into an explainable 0–100 risk scoring framework.

---

## 3. High-Level Architecture

```
                 MAILTRACE AI Console (React 18 / Tailwind / Cytoscape)
                                      │ (REST APIs)
                                      ▼
                        FastAPI Forensic Core Engine
                                      │
       ┌──────────────────────────────┼──────────────────────────────┐
       │                              │                              │
   Email Forensics              AI Threat Detection            Threat Intelligence
       │                              │                              │
 RFC 5322 MIME Parser         DistilBERT CPU Model           Passive DNS (dnspython)
 Header Extractor             Forensic Feature Extraction    RDAP ASN/Org Registry
 Received Hop Analyzer        Linguistic Threat Signals      MaxMind GeoIP Telemetry
 SHA-256 Evidence Vault       Zero Metadata Leakage          Source Routing Tracer
       │                              │                              │
       └──────────────────────────────┼──────────────────────────────┘
                                      │
                             Evidence Fusion Engine
                                      │
                         Calibrated 0–100 Risk Score
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
          Relationship Graph    Forensic Timeline     Campaign Correlation
          (NetworkX/Cytoscape)  (Audit Trail Events)  (Cross-Case Observables)
                │                     │                     │
                └─────────────────────┼─────────────────────┘
                                      │
                        Automated Forensic Reporting
                        - Courtroom-Ready PDF (ReportLab)
                        - Deterministic Forensic JSON
```

---

## 4. Core Investigation Workflow

The platform guides investigators through an intuitive, 5-stage chronological workflow:

1. **UPLOAD (`/api/cases/upload`)**:
   - Ingests raw RFC 5322 `.eml` email files.
   - Computes deterministic SHA-256 cryptographic fingerprint immediately.
   - Preserves exact byte stream into the immutable evidence vault (`evidence/{case_id}/raw.eml`).
   - Parses MIME structures, body parts, and header hierarchies without executing attachments or scripts.

2. **VERIFY (`/api/cases/{case_id}/verify`)**:
   - Evaluates cryptographic email authentication protocols: **SPF**, **DKIM**, and **DMARC**.
   - Assesses strict and relaxed identifier alignment (`spf_alignment`, `dkim_alignment`, `overall_alignment`).
   - Cross-examines visible `From`, `Reply-To`, and envelope `Return-Path` domains for identity inconsistencies.

3. **ANALYZE (`/api/cases/{case_id}/analyze`)**:
   - Runs inference through fine-tuned **DistilBERT** model on CPU (predicting `BENIGN` vs. `MALICIOUS` with calibrated confidence).
   - Extracts deterministic forensic language signals (Urgency, Financial cues, Credential harvesting, Authority coercion, Secrecy, Action requests, Suspicious links).
   - Enriches observable source IPs and domains using safe external lookups (DNS, RDAP, GeoIP).
   - Fuses multi-source evidence into a calibrated 0–100 composite risk score with transparent contribution points.

4. **INVESTIGATE (`/api/cases/{case_id}/graph`, `/timeline`, `/correlation`)**:
   - Interactively explores the **Relationship Graph** linking emails, senders, domains, URLs, IPs, and hosting providers.
   - Traces the chronological **Forensic Timeline** from initial message dispatch to forensic correlation.
   - Analyzes **Potential Campaign Relationships** against historical database investigations sharing threat observables.

5. **REPORT (`/api/cases/{case_id}/report/pdf`, `/report/json`)**:
   - Exports multi-page, publication-quality forensic investigation reports in PDF format with running headers and chain-of-custody stamps.
   - Exports machine-readable, deterministic JSON packages for SIEM/SOAR ingestion.

---

## 5. Key Forensic Modules

### 5.1 Evidence Preservation & Chain of Custody
- Every uploaded artifact receives a **SHA-256 cryptographic hash** computed immediately upon receipt.
- Raw email bytes are stored in an append-only filesystem vault (`evidence/{case_id}/raw.eml`).
- Overwrite protection guarantees that evidence files cannot be silently altered or replaced.
- Immutable audit events record all case operations (`CASE_CREATED`, `UPLOADED`, `PARSED`, `VERIFIED`, `ANALYZED`, `INFRASTRUCTURE_ENRICHED`, `CAMPAIGN_CORRELATED`, `REPORT_GENERATED`).

### 5.2 Cryptographic Authentication Verification
- **SPF Verification**: Validates sender IP authorization against published domain SPF records.
- **DKIM Verification**: Inspects cryptographic domain signatures and public key assertions.
- **DMARC Policy Evaluation**: Evaluates domain DMARC policies (`none`, `quarantine`, `reject`) and verifies strict/relaxed alignment between envelope sender and visible `From` headers.
- **Identity Inconsistency Detector**: Surfaces spoofed display names, `Reply-To` mismatches, and `Return-Path` bounces.

### 5.3 AI Sequence Threat Detection
- **Model**: Custom fine-tuned `DistilBertForSequenceClassification` (`ml/models/dataset3_v1.0.0`).
- **Input**: Email Subject + Body text (truncated to 384 tokens).
- **Execution**: Optimized for fast local CPU inference (~50ms per email).
- **Zero Metadata Leakage**: Model inputs are strictly limited to email text content. Header data, IP intelligence, authentication results, and risk scores are never leaked into model inference, ensuring pure linguistic classification.

### 5.4 Explainable Evidence Fusion (0–100 Risk Score)
Risk points are aggregated from six capped evidence dimensions:
- **AI Threat Detection** (0–25 pts)
- **Identity Consistency** (0–20 pts)
- **Authentication & Alignment** (0–15 pts)
- **URL & Domain Analysis** (0–15 pts)
- **Observed Infrastructure** (0–15 pts)
- **Cross-Case Campaign Signals** (0–10 pts)

Every point added to the composite risk score includes a human-readable rule name and evidentiary justification ("Why This Score?").

---

## 6. Security Hardening & Safe Execution

- **Non-Execution Containment**: Email attachments are never executed, JavaScript/HTML tags are sanitized and stripped, and extracted URLs are never automatically fetched over HTTP.
- **Path Traversal Defense**: All case ID parameters are validated via strict regex (`^[A-Za-z0-9_-]{1,64}$`), and uploaded filenames are sanitized against directory traversal characters (`../`, null bytes).
- **Upload Guards**: 10 MB strict file size ceiling and rejection of non-`.eml` file extensions.
- **Restricted CORS**: Explicitly bounded to local development origins (`http://127.0.0.1:5173`, `http://localhost:5173`).
- **Bounded Timeouts**: DNS lookups time out at 2.0s and RDAP lookups at 5.0s to prevent hanging or thread starvation during offline testing.

---

## 7. Quick Start & Installation

### Prerequisites
- **Python**: 3.10 to 3.13
- **Node.js**: 18+ and npm
- **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/abhinavxsharma/MailTrace-AI.git
cd MailTrace-AI
```

### 2. Backend Setup
```powershell
# Create and activate Python virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install backend dependencies
pip install -r backend/requirements.txt
```

### 3. Frontend Setup
```bash
cd frontend
npm install
cd ..
```

### 4. Running the Platform Locally

**Terminal 1 — Backend:**
```powershell
.venv\Scripts\activate
.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```
API Documentation will be accessible at: `http://127.0.0.1:8000/docs`

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```
Open: `http://127.0.0.1:5173`

---

## 8. Verification & Test Suite

Run the full regression test suite (141 tests covering ingestion, authentication, AI inference, risk scoring, DNS, RDAP, GeoIP, graph topology, timeline, PDF/JSON reports, and security hardening):

```powershell
.venv\Scripts\pytest.exe -v
```
Expected: `141 passed in ~120s`

Run frontend production build verification:
```bash
cd frontend
npm run build
```
Expected: `0 TypeScript errors`, successful Vite production bundle.

---

## 9. API Overview

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status and version |
| `POST` | `/api/cases/upload` | Ingest `.eml`, preserve evidence, calculate SHA-256 |
| `POST` | `/api/cases/{case_id}/verify` | Run SPF, DKIM, DMARC, and identity verification |
| `POST` | `/api/cases/{case_id}/analyze` | Run AI model, feature extraction, and risk fusion |
| `GET` | `/api/cases/{case_id}` | Retrieve canonical case analysis details |
| `GET` | `/api/cases/{case_id}/authentication` | Retrieve detailed cryptographic auth schema |
| `GET` | `/api/cases/{case_id}/graph` | Retrieve Cytoscape relationship topology |
| `GET` | `/api/cases/{case_id}/timeline` | Retrieve chronological forensic event milestones |
| `GET` | `/api/cases/{case_id}/correlation` | Retrieve cross-case campaign correlation intel |
| `GET` | `/api/cases/{case_id}/report/json` | Download deterministic JSON forensic report |
| `GET` | `/api/cases/{case_id}/report/pdf` | Download courtroom-ready PDF forensic report |

---

## 10. Sample Investigation Scenarios

Three authentic, pre-packaged demonstration email fixtures are provided in `samples/`:

1. **Business Email Compromise (BEC)**: `samples/bec/demo_bec_invoice.eml`
   - Executive impersonation, fraudulent wire transfer request, urgent language, visible From mismatch (`acme-finance.com` vs `internal-executive-update.com`), DMARC FAIL.
   - Result: `MALICIOUS` (99.98%), Risk Score: `80 / 100` (`HIGH RISK`).

2. **Credential Phishing**: `samples/phishing/demo_credential_phishing.eml`
   - Brand impersonation (Microsoft Security), credential harvesting link (`https://microsoft-security-check.example/login`), fake account suspension threat.
   - Result: `MALICIOUS` (99.99%), Risk Score: `70 / 100` (`HIGH RISK`).

3. **Legitimate Corporate Email**: `samples/legitimate/demo_legitimate_report.eml`
   - Valid monthly expense report from internal finance department, valid SPF pass, valid DKIM pass, valid DMARC pass.
   - Result: `BENIGN` (99.91%), Risk Score: `15 / 100` (`LOW RISK`).

---

## 11. Ethical Forensics & System Limitations

- **Attribution Safeguard**: Observed source infrastructure reflects technical network routing artifacts. IP geolocation is approximate and does not prove human identity or exact physical location.
- **Correlation Language**: Cross-case campaign intelligence identifies *"Potential Campaign Relationships"* and shared infrastructure clusters. It never asserts definitive human actor identity ("same attacker").
- **Authentication Pass vs. Legitimacy**: A message passing SPF/DKIM/DMARC does not prove absence of malice (compromised accounts or attacker-owned registered domains can pass authentication).
- **Offline Mode**: When third-party DNS or RDAP services are unavailable, the platform degrades gracefully without crashing, surfacing explicit `UNAVAILABLE` telemetry status indicators.

---

## 12. License & Credits

Built for the **Smart India Hackathon (SIH)**. Developed by the MAILTRACE AI Engineering Team.
