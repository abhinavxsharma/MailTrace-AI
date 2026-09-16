"""
MAILTRACE AI - Chronological Forensic Timeline Reconstruction.
Constructs chronological timeline events from email metadata, audit events,
forensic verification milestones, and campaign correlation detections.
"""

from datetime import datetime, timezone
import email.utils
from typing import Any, Dict, List, Optional


def _parse_rfc2822_date(date_str: Optional[str]) -> Optional[str]:
    """Parse RFC 2822/5322 Date header into standard ISO 8601 string."""
    if not date_str:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return date_str.strip()


def build_case_timeline(
    case_data: Dict[str, Any],
    audit_events: Optional[List[Any]] = None,
    correlation_result: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Reconstruct chronological timeline events for a forensic case.
    Returns list of structured timeline event objects.
    """
    timeline: List[Dict[str, Any]] = []

    # 1. Email Message Header Timestamp (EMAIL_RECEIVED)
    email_dict = case_data.get("email", {})
    raw_date = email_dict.get("date")
    parsed_date = _parse_rfc2822_date(raw_date)
    if parsed_date:
        sender = email_dict.get("from_address") or "Sender"
        subj = email_dict.get("subject") or "Untitled"
        timeline.append({
            "timestamp": parsed_date,
            "event": "EMAIL_RECEIVED",
            "source": "RFC 5322 Date Header",
            "details": f"Email '{subj}' dispatched from {sender}",
        })

    # 2. Ingestion and Audit Events
    if audit_events:
        for ev in audit_events:
            ev_type = getattr(ev, "event_type", None) or (ev.get("event_type") if isinstance(ev, dict) else None)
            desc = getattr(ev, "description", None) or (ev.get("description") if isinstance(ev, dict) else "")
            ts = getattr(ev, "created_at", None) or (ev.get("created_at") if isinstance(ev, dict) else None)
            ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts or "")

            if not ts_str:
                ts_str = datetime.now(timezone.utc).isoformat()

            if ev_type == "EVIDENCE_PRESERVED":
                timeline.append({
                    "timestamp": ts_str,
                    "event": "EVIDENCE_PRESERVED",
                    "source": "Chain of Custody",
                    "details": desc or "Raw email preserved and SHA-256 fingerprint recorded",
                })
            elif ev_type == "VERIFIED":
                timeline.append({
                    "timestamp": ts_str,
                    "event": "AUTHENTICATION_VERIFIED",
                    "source": "SPF/DKIM/DMARC Service",
                    "details": desc or "SPF, DKIM, and DMARC alignment verification completed",
                })
            elif ev_type == "ANALYZED":
                timeline.append({
                    "timestamp": ts_str,
                    "event": "AI_THREAT_ANALYZED",
                    "source": "DistilBERT & Risk Fusion",
                    "details": desc or "AI sequence classification and forensic risk scoring completed",
                })

    # 3. Infrastructure Enrichment Event
    infra = case_data.get("infrastructure", {})
    source_ip = infra.get("source_ip")
    if source_ip:
        now_ts = datetime.now(timezone.utc).isoformat()
        country = infra.get("country")
        org = infra.get("organization")
        info_str = f"Observed Source IP {source_ip}"
        if country or org:
            info_str += f" ({org or ''}, {country or ''})".replace(", )", ")")
        timeline.append({
            "timestamp": now_ts,
            "event": "INFRASTRUCTURE_ENRICHED",
            "source": "Passive DNS / RDAP / GeoIP",
            "details": info_str,
        })

    # 4. Campaign Correlation Event
    corr = correlation_result or case_data.get("correlation", {})
    related_ids = corr.get("related_case_ids", [])
    if related_ids:
        now_ts = datetime.now(timezone.utc).isoformat()
        timeline.append({
            "timestamp": now_ts,
            "event": "CAMPAIGN_CORRELATED",
            "source": "Cross-Case Correlation",
            "details": f"Potential campaign relationship detected with {len(related_ids)} case(s): {', '.join(related_ids)}",
        })

    # Sort timeline events chronologically where possible
    def sort_key(item: Dict[str, Any]) -> str:
        return str(item.get("timestamp") or "")

    timeline.sort(key=sort_key)
    return timeline
