# Explainable AI Design

MAILTRACE AI is designed so that the final risk score is traceable back to observable evidence instead of being presented as an unexplained model verdict.

## Evidence-to-score flow

1. Raw message evidence is preserved and fingerprinted.
2. Forensic parsers extract headers, authentication results, domains, URLs, IPs and message structure.
3. NLP/ML produces semantic threat signals such as phishing intent, impersonation and BEC behavior.
4. Deterministic forensic rules produce structural signals such as Reply-To mismatch, authentication alignment failures and lookalike domains.
5. Infrastructure enrichment adds DNS, RDAP, GeoIP and optional reputation observations.
6. Evidence fusion combines the signals into a calibrated 0–100 investigation risk score.
7. The UI exposes the largest contributors and lets an investigator inspect the evidence behind each contributor.

## Example contribution model

The presentation prototype uses human-readable contributions such as:

- Reply-To mismatch: +18
- Suspicious domain: +15
- DMARC alignment failure: +12
- BEC intent: +21
- Infrastructure risk: +11

These values are a demonstration of the evidence-fusion interface. Production weights should be learned/evaluated on a held-out validation set and calibrated for the deployment environment.

## Production XAI path

For a trained text classifier, SHAP or Integrated Gradients can explain token/feature influence. For the hybrid evidence-fusion layer, feature-level SHAP plus rule provenance can expose which evidence families drove the final decision.

## Forensic safety

Explainability does not equal attribution. IP geolocation describes observed infrastructure and confidence; it does not prove a person's physical location or identity. Earlier email routing headers may have lower trust than records added at a trusted receiving boundary.
