# MAILTRACE AI — Machine Learning Model Documentation

### Overview
MAILTRACE AI incorporates a specialized, locally hosted transformer model fine-tuned specifically for detecting social engineering, business email compromise, and credential phishing narratives.

---

### Model Specification

- **Identifier**: `dataset3_v1.0.0`
- **Base Architecture**: `DistilBertForSequenceClassification` (Hugging Face Transformers)
- **Model Directory**: `ml/models/dataset3_v1.0.0/`
- **Artifacts**:
  - `config.json` (model hyperparameters and label mapping)
  - `tokenizer_config.json`, `vocab.txt`, `tokenizer.json` (WordPiece tokenizer)
  - `model.safetensors` (fine-tuned model weights, ~267.8 MB)
- **Input Modality**: Plaintext Email Subject + Body text
- **Maximum Sequence Length**: 384 tokens
- **Output Classes**:
  - `0`: `BENIGN`
  - `1`: `MALICIOUS`
- **Inference Runtime**: Local CPU execution via PyTorch (zero external GPU or cloud API dependencies required).

---

### Training Chain

The model was iteratively trained and refined across three progressive benchmark datasets:

1. **Dataset 1 (Baseline Lexical)**: Initial domain adaptation on public phishing corpora (Enron, SpamAssassin, Nazario) establishing fundamental spam vs. ham language boundaries.
2. **Dataset 2 (Advanced Phishing & Spearphishing)**: Enriched with targeted credential harvesting scenarios, modern cloud provider brand impersonation, and evasive HTML-obfuscated language.
3. **Dataset 3 (Fine-Tuned Production Model — v1.0.0)**: Trained on balanced Business Email Compromise (BEC), CEO fraud, urgent wire transfer requests, vendor invoice redirection, and benign high-frequency enterprise correspondence.

---

### Strict Prevention of Metadata Leakage

A critical requirement of forensic validity is ensuring that model predictions reflect **authentic linguistic patterns** rather than spurious correlations with technical headers.

**Strict Architectural Boundaries:**
- The model accepts **only Subject and Body text**.
- The model **never** receives:
  - SPF, DKIM, or DMARC verification results
  - IP reputation or geolocation data
  - Historical campaign correlation labels
  - Visible From or envelope Return-Path domain strings
  - The final 0–100 risk score

By isolating the transformer strictly to text sequence classification, the AI prediction serves as an independent, unbiased evidence dimension in the subsequent Evidence Fusion Engine.

---

### Inference Performance

- **Latency**: ~35–65ms per email on standard x86-64 multi-core CPU.
- **Memory Footprint**: ~400MB RAM when resident.
- **Preprocessing**: HTML tags, scripts, and non-printable control sequences are stripped via `strip_html_tags()` prior to tokenization.
