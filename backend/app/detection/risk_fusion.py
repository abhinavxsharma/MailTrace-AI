"""
MAILTRACE AI - Explainable Evidence Fusion and Risk Scoring Engine.
Computes calibrated 0-100 forensic risk scores and transparent contribution breakdowns.
"""

from typing import Any, Dict, List, Optional

from app.schemas.risk import (
    RiskAssessment,
    RiskClassification,
    RiskDimensions,
    RiskReason,
    get_risk_classification,
)
from app.schemas.verification import AuthStatus, AuthenticationSchema, IdentitySchema


# Maximum contribution bounds per specification
MAX_AI_THREAT = 25
MAX_IDENTITY = 20
MAX_AUTHENTICATION = 15
MAX_URL_DOMAIN = 15
MAX_INFRASTRUCTURE = 15
MAX_CAMPAIGN = 10


def fuse_evidence(
    ai_prediction: Dict[str, Any],
    features: Dict[str, Any],
    authentication: Optional[AuthenticationSchema] = None,
    identity: Optional[IdentitySchema] = None,
    observed_source_ip: Optional[str] = None,
    infrastructure_intelligence: Optional[Dict[str, Any]] = None,
    campaign_correlation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Perform multi-factor evidence fusion and produce calibrated 0-100 risk score,
    category contributions, risk reasons, and explainable forensic statements.
    """
    reasons: List[RiskReason] = []
    explanations: List[str] = []

    # 1. AI Threat Category (0-25)
    ai_points = 0
    ai_label = ai_prediction.get("label", "BENIGN")
    ai_confidence = float(ai_prediction.get("confidence") or 0.0)
    ai_threat_score = ai_prediction.get("threat_score")

    if ai_label == "MALICIOUS" and ai_threat_score is not None:
        ai_points = min(MAX_AI_THREAT, max(0, round(float(ai_threat_score) * MAX_AI_THREAT)))
        reasons.append(
            RiskReason(
                rule="AI Threat Detection",
                points=f"+{ai_points}",
                description=f"DistilBERT model classified email content as MALICIOUS with {ai_confidence:.1%} confidence",
            )
        )
        explanations.append(f"AI model classified the email as MALICIOUS with {ai_confidence:.1%} confidence.")
    elif ai_prediction.get("status") == "MODEL_UNAVAILABLE":
        explanations.append("AI threat model was unavailable; inference skipped.")

    # 2. Identity Consistency Category (0-20)
    identity_points = 0
    reply_to_mismatch = features.get("reply_to_mismatch", False)
    return_path_mismatch = features.get("return_path_mismatch", False)

    if reply_to_mismatch:
        identity_points += 12
        reasons.append(
            RiskReason(
                rule="Reply-To Inconsistency",
                points="+12",
                description="Visible From domain differs from Reply-To destination domain",
            )
        )
        explanations.append("Visible From domain differs from Reply-To domain.")

    if return_path_mismatch:
        identity_points += 8
        reasons.append(
            RiskReason(
                rule="Return-Path Inconsistency",
                points="+8",
                description="Visible From domain differs from Return-Path envelope domain",
            )
        )
        explanations.append("Visible From domain differs from Return-Path domain.")

    identity_points = min(MAX_IDENTITY, identity_points)

    # 3. Authentication Category (0-15)
    auth_points = 0
    if authentication:
        # Check DMARC
        if authentication.dmarc == AuthStatus.FAIL:
            auth_points += 10
            reasons.append(
                RiskReason(
                    rule="DMARC Failure",
                    points="+10",
                    description="DMARC evaluation failed alignment with visible From domain",
                )
            )
            explanations.append("DMARC failed alignment.")
        elif authentication.dmarc in (AuthStatus.NONE, AuthStatus.UNKNOWN):
            auth_points += 3
            reasons.append(
                RiskReason(
                    rule="Missing DMARC Protection",
                    points="+3",
                    description="No valid DMARC policy protecting sender domain",
                )
            )

        # Check SPF
        if authentication.spf == AuthStatus.FAIL:
            auth_points += 3
            reasons.append(
                RiskReason(
                    rule="SPF Unauthorized",
                    points="+3",
                    description="Sending host is not authorized by SPF record",
                )
            )
            explanations.append("SPF verification failed for sending host.")

        # Check DKIM
        if authentication.dkim == AuthStatus.FAIL:
            auth_points += 2
            reasons.append(
                RiskReason(
                    rule="DKIM Verification Failed",
                    points="+2",
                    description="DKIM cryptographic signature verification failed",
                )
            )
            explanations.append("DKIM cryptographic signature verification failed.")

    auth_points = min(MAX_AUTHENTICATION, auth_points)

    # 4. URL / Domain Category (0-15)
    url_domain_points = 0
    suspicious_links = features.get("suspicious_links_detected", False)
    credentials_detected = features.get("credentials_detected", False)
    financial_detected = features.get("financial_detected", False)
    urgency_detected = features.get("urgency_detected", False)
    url_count = features.get("url_count", 0)

    if suspicious_links:
        url_domain_points += 10
        reasons.append(
            RiskReason(
                rule="Suspicious Link Keywords",
                points="+10",
                description="Observed URLs contain credential verification, login, or portal tokens",
            )
        )
        explanations.append("Email contains a credential verification request or suspicious portal link.")

    if url_count >= 2 or (credentials_detected and url_count >= 1):
        add_pts = 5 if url_domain_points < MAX_URL_DOMAIN else 0
        if add_pts > 0:
            url_domain_points += add_pts
            reasons.append(
                RiskReason(
                    rule="Credential Verification Target",
                    points=f"+{add_pts}",
                    description="Message directs recipient to external authentication/payment verification portal",
                )
            )

    url_domain_points = min(MAX_URL_DOMAIN, url_domain_points)

    # Linguistic cues (XAI explanations)
    if urgency_detected and financial_detected:
        explanations.append("Email contains urgent financial transfer language.")
    elif financial_detected:
        explanations.append("Email contains vendor invoice or payment transfer language.")
    elif urgency_detected:
        explanations.append("Email contains urgent or time-sensitive language.")

    # 5. Infrastructure Category (0-15)
    infra_points = 0
    if observed_source_ip:
        explanations.append(f"Observed Source Infrastructure: {observed_source_ip}")

    if infrastructure_intelligence:
        # Check GeoIP
        src_ip = infrastructure_intelligence.get("source_ip") or observed_source_ip
        geoip_data = infrastructure_intelligence.get("geoip", {}).get(src_ip, {})
        if geoip_data and geoip_data.get("status") == "AVAILABLE":
            country = geoip_data.get("country")
            city = geoip_data.get("city")
            if country:
                explanations.append(f"IP Geolocation indicates registration in {country}{f' ({city})' if city else ''}.")

        # Check RDAP
        rdap_data = infrastructure_intelligence.get("rdap", {}).get(src_ip, {})
        if rdap_data and rdap_data.get("status") == "AVAILABLE":
            org = rdap_data.get("organization") or rdap_data.get("network_name")
            if org:
                explanations.append(f"Observed Network / Registration Information: {org}.")

        # Check suspicious infrastructure signals
        suspicious_signals = infrastructure_intelligence.get("suspicious_signals", [])
        for sig in suspicious_signals:
            if "no valid Mail Exchanger" in sig:
                infra_points += 5
                reasons.append(
                    RiskReason(
                        rule="Sender Missing MX Records",
                        points="+5",
                        description=sig,
                    )
                )
                explanations.append(f"Infrastructure Evidence: {sig}.")
            elif "does not resolve" in sig:
                infra_points += 5
                reasons.append(
                    RiskReason(
                        rule="Unresolvable Sender Infrastructure",
                        points="+5",
                        description=sig,
                    )
                )
                explanations.append(f"Infrastructure Evidence: {sig}.")
            else:
                infra_points += 5
                reasons.append(
                    RiskReason(
                        rule="Suspicious Infrastructure Signal",
                        points="+5",
                        description=sig,
                    )
                )
                explanations.append(f"Infrastructure Evidence: {sig}.")

        infra_points = min(MAX_INFRASTRUCTURE, infra_points)

    # 6. Campaign Category (0-10)
    campaign_points = 0
    if campaign_correlation:
        campaign_points = min(MAX_CAMPAIGN, max(0, campaign_correlation.get("campaign_score", 0)))
        related_ids = campaign_correlation.get("related_case_ids", [])
        shared_inds = campaign_correlation.get("shared_indicators", [])
        reasons_list = campaign_correlation.get("correlation_reasons", [])

        if campaign_points > 0:
            reasons.append(
                RiskReason(
                    rule="Campaign Correlation",
                    points=f"+{campaign_points}",
                    description=f"Potential campaign relationship detected with {len(related_ids)} related case(s) sharing {len(shared_inds)} threat indicator(s)",
                )
            )
            for r_stmt in reasons_list:
                explanations.append(r_stmt)

    # Total score clamped strictly to 0-100
    total_score = ai_points + identity_points + auth_points + url_domain_points + infra_points + campaign_points
    risk_score = min(100, max(0, total_score))
    classification = get_risk_classification(risk_score)

    contributions = {
        "ai_threat": ai_points,
        "identity": identity_points,
        "authentication": auth_points,
        "url_domain": url_domain_points,
        "infrastructure": infra_points,
        "campaign": campaign_points,
    }

    # Deduplicate explanations while preserving order
    unique_explanations: List[str] = []
    for exp in explanations:
        if exp not in unique_explanations:
            unique_explanations.append(exp)

    risk_assessment = RiskAssessment(
        risk_score=risk_score,
        classification=classification,
        confidence=round(ai_confidence, 4) if ai_confidence else 0.85,
        dimensions=RiskDimensions(
            ai_threat=float(ai_points),
            authentication=float(auth_points),
            identity_consistency=float(identity_points),
            url_risk=float(url_domain_points),
            infrastructure_risk=float(infra_points),
            campaign_risk=float(campaign_points),
            bec_risk=float(ai_points + identity_points) if (financial_detected or urgency_detected) else 0.0,
        ),
        reasons=reasons,
    )

    return {
        "risk_score": risk_score,
        "risk_level": classification,
        "risk_assessment": risk_assessment,
        "risk_contributions": contributions,
        "infrastructure_score": infra_points,
        "campaign_score": campaign_points,
        "reasons": reasons,
        "explanations": unique_explanations,
    }
