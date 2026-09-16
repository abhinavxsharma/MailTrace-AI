# MAILTRACE AI — Technical Architecture Documentation

### Architecture Overview

MAILTRACE AI utilizes a layered, decoupled architecture designed for high information density, fast CPU inference, explainable scoring, and verifiable evidence preservation.

```
                      ┌─────────────────────────────────────────┐
                      │          React 18 + TypeScript          │
                      │    (Tailwind CSS + Cytoscape.js)        │
                      └────────────────────┬────────────────────┘
                                           │ HTTP / REST
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │          FastAPI Backend Engine         │
                      │   (Lifespan DB / Pydantic v2 / CORS)    │
                      └────────────────────┬────────────────────┘
                                           │
       ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
       ▼                   ▼                               ▼                   ▼
┌──────────────┐   ┌──────────────┐                ┌──────────────┐   ┌─────────────────┐
│Email Forensic│   │Cryptographic │                │AI Inference  │   │Threat Intel     │
│MIME Parser   │   │Authentication│                │Engine        │   │Enrichment       │
├──────────────┤   ├──────────────┤                ├──────────────┤   ├─────────────────┤
│- BytesParser │   │- SPF Parser  │                │- DistilBERT  │   │- dnspython      │
│- Header Extr.│   │- DKIM Verif. │                │  Dataset 3   │   │- RDAP Registry  │
│- Received Hop│   │- DMARC Policy│                │- 384 Max Tok.│   │- MaxMind GeoIP  │
│- Indicators  │   │- Alignment   │                │- Zero Leakage│   │- Hop Tracer     │
└──────┬───────┘   └──────┬───────┘                └──────┬───────┘   └────────┬────────┘
       │                  │                               │                    │
       └──────────────────┴───────────────┬───────────────┴────────────────────┘
                                          ▼
                      ┌─────────────────────────────────────────┐
                      │         Evidence Fusion Engine          │
                      │     (0–100 Explainable Risk Fusion)     │
                      └───────────────────┬─────────────────────┘
                                          │
       ┌──────────────────────────────────┼──────────────────────────────────┐
       ▼                                  ▼                                  ▼
┌──────────────┐                  ┌──────────────┐                   ┌──────────────┐
│Relationship  │                  │Forensic      │                   │Campaign      │
│Graph         │                  │Timeline      │                   │Correlation   │
├──────────────┤                  ├──────────────┤                   ├──────────────┤
│- NetworkX    │                  │- RFC 2822    │                   │- Jaccard &   │
│- Cytoscape.js│                  │- Audit Trail │                   │  Indicator   │
│- 8 Node Types│                  │  Milestones  │                   │  Clustering  │
└──────┬───────┘                  └──────┬───────┘                   └──────┬───────┘
       │                                 │                                  │
       └─────────────────────────────────┴──────────────────────────────────┘
                                         │
                                         ▼
                      ┌─────────────────────────────────────────┐
                      │       Database & Vault Storage          │
                      │  - SQLite (Cases, Evidence, Audit)      │
                      │  - File Vault (evidence/{case_id}/)     │
                      └──────────────────┬──────────────────────┘
                                         │
                                         ▼
                      ┌─────────────────────────────────────────┐
                      │       Forensic Reporting Engine         │
                      │  - ReportLab PDF (NumberedCanvas)       │
                      │  - Deterministic JSON Serializer        │
                      └─────────────────────────────────────────┘
```

---

### Layer Breakdown

#### 1. Presentation Layer (React 18 & TypeScript)
- **Framework**: React 18, TypeScript, Tailwind CSS, Vite 6.
- **UI Paradigm**: High-density Security Operations Center (SOC) console. No decorative graphics or cartoon icons; uses pure, clean typography (`Inter`, monospace metadata).
- **Topology Engine**: Cytoscape.js canvas with force-directed physics layout (`cose`) and interactive node inspection.

#### 2. Application API Layer (FastAPI)
- **Framework**: FastAPI (Python 3.13), Uvicorn ASGI server.
- **Validation**: Pydantic v2 schemas validating request inputs and enforcing response contracts.
- **CORS & Security**: Strict origins allowed (`http://127.0.0.1:5173`, `http://localhost:5173`), 10 MB upload ceiling, and regex-guarded case identifiers.

#### 3. Forensic Parsing & Extraction (`app/forensics/`)
- **Parser**: Standard library `email.parser.BytesParser` with `policy.default`.
- **Safety**: Treats email payloads strictly as inert data. Scripts and HTML are stripped; attachments are cataloged by metadata but never executed.
- **Indicators**: High-performance regex extraction of public IPv4 addresses, domains, and URLs without external network traffic.

#### 4. Cryptographic Authentication & Alignment (`app/forensics/authentication.py`)
- Evaluates declared `Authentication-Results` headers and active DNS verification.
- Calculates DMARC identifier alignment across From, Reply-To, and Return-Path headers under strict and relaxed modes.

#### 5. Local AI Threat Detection (`app/detection/`)
- **Model**: Custom fine-tuned `DistilBertForSequenceClassification` loaded from `ml/models/dataset3_v1.0.0`.
- **Execution**: Pure CPU tensor execution.
- **Linguistic Signals**: Rule-based keyword and phrase classifiers extracting signals across 7 forensic dimensions (Urgency, Financial, Credential, Authority, Secrecy, Action Request, Suspicious Link).

#### 6. Threat Intelligence & Routing Telemetry (`app/intelligence/`)
- **DNS**: Asynchronous lookups using `dnspython` for A, AAAA, MX, NS, and TXT records with a 2.0-second safety timeout.
- **RDAP**: Querying regional internet registries (ARIN, RIPE, APNIC) for ASN and network organization with a 5.0-second safety timeout.
- **GeoIP**: Local MaxMind GeoLite2 lookup with offline fallback.

#### 7. Evidence Fusion & Risk Scoring (`app/detection/risk_fusion.py`)
- Deterministic 0–100 risk scoring algorithm.
- Category caps prevent single dimensions from skewing results.
- Outputs human-readable evidence rules and contribution breakdowns.

#### 8. Relationship Graph & Campaign Correlation (`app/graph/`)
- **Graph Builder**: NetworkX backend building bi-directional entity graphs converted to Cytoscape JSON.
- **Correlation**: In-memory and SQL index matching comparing observables across historical cases. Computes campaign scores and outputs neutral attribution findings (*"Potential Campaign Relationship"*).

#### 9. Forensic Reporting (`app/reports/`)
- **ReportLab**: Generates multi-page courtroom-ready PDFs using a two-pass canvas (`NumberedCanvas`) with running headers, footers, page counts, and SHA-256 fingerprinting.
- **JSON**: Machine-readable, sorted, deterministic JSON reports for SIEM/SOAR integration.
