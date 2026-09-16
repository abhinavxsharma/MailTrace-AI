# MAILTRACE AI — SIH Live Demonstration Guide
### 3–5 Minute Judge Walkthrough Sequence

This guide provides the exact demonstration flow for presenting **MAILTRACE AI** to hackathon judges.

---

### Pre-Demo Checklist
1. Start FastAPI Backend:
   ```powershell
   .venv\Scripts\activate
   .venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000
   ```
2. Start React Frontend:
   ```bash
   cd frontend
   npm run dev
   ```
3. Open `http://127.0.0.1:5173` in Google Chrome or Microsoft Edge.
4. Verify the top right status badge reads: **Backend: Connected** (Green pulse dot).

---

### Step-by-Step 4-Minute Presentation Script

#### Step 1: Introduction (30 seconds)
- *"Judges, current email security solutions act as black boxes. When an organization suffers a Business Email Compromise or zero-day phishing attack, incident response teams waste hours trying to deconstruct headers, check SPF/DKIM alignment, and correlate attacker infrastructure. MAILTRACE AI solves this by serving as an end-to-end digital forensics and threat analysis platform that preserves cryptographic chain-of-custody, executes local AI threat detection, and provides 100% explainable evidence fusion."*

#### Step 2: Ingesting Evidence & Cryptographic Preservation (30 seconds)
- Click **Upload EML File** or drag-and-drop `samples/bec/demo_bec_invoice.eml`.
- Point out the **Case ID** (e.g. `MT-2026-000304`) and **Status Badge (`PARSED`)** in the fixed header.
- Point out the **Evidence Fingerprint** block on the left:
  - Explain that the SHA-256 hash (`f1ddc323fccbff94...`) was computed immediately upon upload and stored into the immutable vault.
  - Demonstrate clicking the **Copy SHA-256** button.
- Show the **Decoded Email Body** viewer and click **View Raw Headers** to show complete RFC 5322 header preservation without script execution risk.

#### Step 3: Verifying Cryptographic Authentication (45 seconds)
- Click the **Verify Email** button on the horizontal workflow bar.
- Point to the **Authentication Panel**:
  - `SPF: PASS` | `DKIM: PASS` | `DMARC: FAIL`
  - Highlight the **Identity Consistency** table below it:
    - Visible From: `acme-finance.com`
    - Reply-To: `internal-executive-update.com` (Red **MISMATCH** badge)
    - Return-Path: `bounce-handler.net` (Amber **MISMATCH** badge)
  - Explain to the judges: *"Even though SPF passed for the sender relay, DMARC failed because the envelope domain does not align with the visible From domain. This is classic executive spoofing."*

#### Step 4: AI Threat Detection & 0–100 Explainable Risk Scoring (60 seconds)
- Click the **Analyze Email** button.
- Watch the progress bar complete and showcase the **Risk Summary** on the right:
  - **Composite Score**: `80 / 100` (`HIGH RISK`).
  - **Six Contribution Dimensions**: Show the thin horizontal contribution bars (AI Threat: 25/25, Identity: 20/20, Authentication: 10/15, URL/Domain: 15/15, Infrastructure: 0/15, Campaign: 10/10).
- Point to the **AI Threat Detection** panel:
  - Model: `dataset3_v1.0.0` (Fine-tuned DistilBERT running locally on CPU).
  - Classification: `MALICIOUS` (Confidence: 99.98%).
  - Detected forensic signals: `Urgency`, `Financial`, `Authority`, `Secrecy`, `Action Request`, `Suspicious Link`.
- Point to the **"Why This Score?"** evidence list:
  - Explain: *"Unlike generic black-box AI, MAILTRACE AI details every single point: +25 for AI Threat, +12 for Reply-To mismatch, +10 for DMARC failure, +10 for Cross-Case Campaign correlation. Every point is auditable."*

#### Step 5: Observed Source Infrastructure & Attribution Safeguards (30 seconds)
- Point to the **Observed Source Infrastructure** card:
  - Source IP: `198.51.100.23`
  - Network / RDAP: `ACME-CLOUD-NET / AS64500`
  - IP Geolocation: `United States`
  - Show the **Forensic Disclaimer**: *"Observed source infrastructure reflects network routing artifacts. IP geolocation is approximate and does not prove human identity or exact physical location."* Emphasize compliance with digital forensics legal standards.

#### Step 6: Relationship Graph, Timeline, and Campaign Correlation (45 seconds)
- Switch to the **Relationship Graph** tab:
  - Demonstrate Cytoscape graph rendering 19 entities (Email, Sender, Reply-To, Domain, URL, IP, Infrastructure).
  - Click **Zoom In**, **Zoom Out**, and **Fit**. Click a node to open the inspector overlay.
- Switch to the **Forensic Timeline** tab:
  - Show the vertical chronological event trail from `EMAIL_RECEIVED` → `EVIDENCE_PRESERVED` → `AUTHENTICATION_VERIFIED` → `AI_THREAT_ANALYZED`.
- Switch to the **Campaign Correlation** tab:
  - Show **Potential Campaign Relationship** detecting shared IP and domains across active cases.

#### Step 7: Generating Courtroom-Ready Forensic Reports (30 seconds)
- Click **Generate PDF** in the Forensic Report panel.
- Open the generated PDF:
  - Show running headers, two-pass `NumberedCanvas` ("Page 1 of 4"), cryptographic evidence hash, complete findings, and chain-of-custody audit stamps.
- Click **Download JSON** to demonstrate machine-readable SIEM/SOAR export.

#### Step 8: Conclusion (15 seconds)
- *"MAILTRACE AI provides speed, mathematical rigor, and court-admissible explainability in one unified SOC platform. Thank you!"*
