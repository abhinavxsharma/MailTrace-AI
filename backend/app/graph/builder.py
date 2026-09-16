"""
MAILTRACE AI - Forensic Relationship Graph Builder.
Constructs NetworkX-backed forensic relationship graphs connecting emails, senders,
domains, URLs, IPs, and infrastructure. Exports Cytoscape.js-compatible graph structures.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from app.schemas.graph import GraphResponse, GraphNode, GraphNodeData, GraphEdge, GraphEdgeData


def _normalize_email(email_str: Optional[str]) -> Optional[str]:
    """Normalize email address to clean lowercase string without display name."""
    if not email_str:
        return None
    match = re.search(r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}", email_str)
    if match:
        return match.group(0).lower().strip()
    return email_str.strip().lower()


def _normalize_domain(domain_str: Optional[str]) -> Optional[str]:
    """Normalize domain name to clean lowercase host."""
    if not domain_str:
        return None
    d = domain_str.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split(":", 1)[0].strip()
    return d.rstrip(".") if "." in d else None


def _normalize_url(url_str: Optional[str]) -> Optional[str]:
    """Normalize URL string."""
    if not url_str:
        return None
    return url_str.strip()


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain host from a URL string."""
    if not url or "://" not in url:
        return None
    try:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].strip().lower()
        return host.rstrip(".") if "." in host else None
    except Exception:
        return None


def build_case_graph(
    case_data: Dict[str, Any],
    case_id: str,
) -> Dict[str, Any]:
    """
    Construct a directed relationship graph from stored case forensic data.
    Uses NetworkX MultiDiGraph internally and exports Cytoscape.js compatible JSON.
    Never performs network lookups; functions fully offline.
    """
    G = nx.MultiDiGraph()

    # 1. Root Node: The Email Case
    email_dict = case_data.get("email", {})
    subject = email_dict.get("subject") or f"Case {case_id}"
    email_node_id = f"email:{case_id}"

    G.add_node(
        email_node_id,
        label=subject[:40] + ("..." if len(subject) > 40 else ""),
        type="email",
        value=case_id,
        extra={
            "case_id": case_id,
            "date": email_dict.get("date"),
            "subject": subject,
            "message_id": email_dict.get("message_id"),
        },
    )

    # Track unique added entities to ensure deduplication
    created_domains: Set[str] = set()
    created_ips: Set[str] = set()
    created_urls: Set[str] = set()

    # 2. Sender Node (EMAIL -> SENDER)
    from_raw = email_dict.get("from_address")
    sender_clean = _normalize_email(from_raw)
    if sender_clean:
        sender_node_id = f"sender:{sender_clean}"
        G.add_node(
            sender_node_id,
            label=f"From: {sender_clean}",
            type="sender",
            value=sender_clean,
            extra={"raw_header": from_raw},
        )
        G.add_edge(
            email_node_id,
            sender_node_id,
            id=f"edge:{email_node_id}->{sender_node_id}",
            label="SENT_FROM",
            relationship="EMAIL->SENDER",
            extra={"header": "From"},
        )

        # Connect Sender -> From Domain
        if "@" in sender_clean:
            from_dom = _normalize_domain(sender_clean.split("@", 1)[1])
            if from_dom:
                dom_node_id = f"domain:{from_dom}"
                if dom_node_id not in G:
                    G.add_node(dom_node_id, label=from_dom, type="domain", value=from_dom, extra={})
                    created_domains.add(from_dom)
                G.add_edge(
                    sender_node_id,
                    dom_node_id,
                    id=f"edge:{sender_node_id}->{dom_node_id}",
                    label="BELONGS_TO",
                    relationship="SENDER->DOMAIN",
                    extra={},
                )

    # 3. Reply-To Node (EMAIL -> REPLY_TO)
    reply_to_raw = email_dict.get("reply_to")
    reply_to_clean = _normalize_email(reply_to_raw)
    if reply_to_clean:
        reply_to_node_id = f"reply_to:{reply_to_clean}"
        G.add_node(
            reply_to_node_id,
            label=f"Reply-To: {reply_to_clean}",
            type="reply_to",
            value=reply_to_clean,
            extra={"raw_header": reply_to_raw},
        )
        G.add_edge(
            email_node_id,
            reply_to_node_id,
            id=f"edge:{email_node_id}->{reply_to_node_id}",
            label="REPLIES_TO",
            relationship="EMAIL->REPLY_TO",
            extra={"header": "Reply-To"},
        )
        if "@" in reply_to_clean:
            rt_dom = _normalize_domain(reply_to_clean.split("@", 1)[1])
            if rt_dom:
                dom_node_id = f"domain:{rt_dom}"
                if dom_node_id not in G:
                    G.add_node(dom_node_id, label=rt_dom, type="domain", value=rt_dom, extra={})
                    created_domains.add(rt_dom)
                G.add_edge(
                    reply_to_node_id,
                    dom_node_id,
                    id=f"edge:{reply_to_node_id}->{dom_node_id}",
                    label="BELONGS_TO",
                    relationship="REPLY_TO->DOMAIN",
                    extra={},
                )

    # 4. Return-Path Node (EMAIL -> RETURN_PATH)
    return_path_raw = email_dict.get("return_path")
    return_path_clean = _normalize_email(return_path_raw)
    if return_path_clean:
        return_path_node_id = f"return_path:{return_path_clean}"
        G.add_node(
            return_path_node_id,
            label=f"Return-Path: {return_path_clean}",
            type="return_path",
            value=return_path_clean,
            extra={"raw_header": return_path_raw},
        )
        G.add_edge(
            email_node_id,
            return_path_node_id,
            id=f"edge:{email_node_id}->{return_path_node_id}",
            label="RETURNS_TO",
            relationship="EMAIL->RETURN_PATH",
            extra={"header": "Return-Path"},
        )
        if "@" in return_path_clean:
            rp_dom = _normalize_domain(return_path_clean.split("@", 1)[1])
            if rp_dom:
                dom_node_id = f"domain:{rp_dom}"
                if dom_node_id not in G:
                    G.add_node(dom_node_id, label=rp_dom, type="domain", value=rp_dom, extra={})
                    created_domains.add(rp_dom)
                G.add_edge(
                    return_path_node_id,
                    dom_node_id,
                    id=f"edge:{return_path_node_id}->{dom_node_id}",
                    label="BELONGS_TO",
                    relationship="RETURN_PATH->DOMAIN",
                    extra={},
                )

    # 5. Indicators: URLs, Domains, IPs
    indicators = case_data.get("indicators", [])
    for ind in indicators:
        val = ind.get("value") if isinstance(ind, dict) else getattr(ind, "value", None)
        itype = ind.get("type") if isinstance(ind, dict) else getattr(ind, "type", None)
        if not val:
            continue

        if itype == "url":
            clean_u = _normalize_url(val)
            if clean_u and clean_u not in created_urls:
                url_node_id = f"url:{clean_u}"
                G.add_node(
                    url_node_id,
                    label=clean_u[:35] + ("..." if len(clean_u) > 35 else ""),
                    type="url",
                    value=clean_u,
                    extra={"url": clean_u},
                )
                created_urls.add(clean_u)
                G.add_edge(
                    email_node_id,
                    url_node_id,
                    id=f"edge:{email_node_id}->{url_node_id}",
                    label="CONTAINS_URL",
                    relationship="EMAIL->URL",
                    extra={},
                )

                # Connect URL -> Domain
                url_dom = _extract_domain_from_url(clean_u)
                if url_dom:
                    dom_node_id = f"domain:{url_dom}"
                    if dom_node_id not in G:
                        G.add_node(dom_node_id, label=url_dom, type="domain", value=url_dom, extra={})
                        created_domains.add(url_dom)
                    G.add_edge(
                        url_node_id,
                        dom_node_id,
                        id=f"edge:{url_node_id}->{dom_node_id}",
                        label="HOSTED_ON",
                        relationship="URL->DOMAIN",
                        extra={},
                    )

        elif itype == "domain":
            clean_d = _normalize_domain(val)
            if clean_d and clean_d not in created_domains:
                dom_node_id = f"domain:{clean_d}"
                G.add_node(dom_node_id, label=clean_d, type="domain", value=clean_d, extra={})
                created_domains.add(clean_d)
                G.add_edge(
                    email_node_id,
                    dom_node_id,
                    id=f"edge:{email_node_id}->{dom_node_id}",
                    label="REFERENCES_DOMAIN",
                    relationship="EMAIL->DOMAIN",
                    extra={},
                )

        elif itype == "ip":
            clean_ip = val.strip()
            if clean_ip and clean_ip not in created_ips:
                ip_node_id = f"ip:{clean_ip}"
                G.add_node(ip_node_id, label=clean_ip, type="ip", value=clean_ip, extra={})
                created_ips.add(clean_ip)
                G.add_edge(
                    email_node_id,
                    ip_node_id,
                    id=f"edge:{email_node_id}->{ip_node_id}",
                    label="RECEIVED_FROM",
                    relationship="EMAIL->IP",
                    extra={},
                )

    # 6. Source IP from Infrastructure (EMAIL -> IP)
    src_ip = case_data.get("infrastructure", {}).get("source_ip")
    if src_ip:
        clean_src = src_ip.strip()
        ip_node_id = f"ip:{clean_src}"
        if ip_node_id not in G:
            G.add_node(ip_node_id, label=clean_src, type="ip", value=clean_src, extra={"is_source": True})
            created_ips.add(clean_src)
        # Ensure edge exists
        if not G.has_edge(email_node_id, ip_node_id):
            G.add_edge(
                email_node_id,
                ip_node_id,
                id=f"edge:{email_node_id}->{ip_node_id}",
                label="OBSERVED_SOURCE",
                relationship="EMAIL->IP",
                extra={"source": "Received"},
            )

    # 7. DNS Resolution edges (DOMAIN -> IP)
    dns_data = case_data.get("dns", {})
    if isinstance(dns_data, dict):
        for dom, dinfo in dns_data.items():
            dom_clean = _normalize_domain(dom)
            if dom_clean:
                dom_node_id = f"domain:{dom_clean}"
                if dom_node_id in G and isinstance(dinfo, dict):
                    resolved_ips = dinfo.get("records", {}).get("A", [])
                    for rip in resolved_ips:
                        rip_clean = rip.strip()
                        rip_node_id = f"ip:{rip_clean}"
                        if rip_node_id not in G:
                            G.add_node(rip_node_id, label=rip_clean, type="ip", value=rip_clean, extra={})
                            created_ips.add(rip_clean)
                        if not G.has_edge(dom_node_id, rip_node_id):
                            G.add_edge(
                                dom_node_id,
                                rip_node_id,
                                id=f"edge:{dom_node_id}->{rip_node_id}",
                                label="RESOLVES_TO",
                                relationship="DOMAIN->IP",
                                extra={"dns_record": "A"},
                            )

    # 8. Infrastructure Nodes (IP -> INFRASTRUCTURE)
    rdap_data = case_data.get("rdap", {})
    geoip_data = case_data.get("geoip", {})

    for ip_val in created_ips:
        ip_node_id = f"ip:{ip_val}"
        org = None
        country = None

        if isinstance(rdap_data, dict) and ip_val in rdap_data:
            org = rdap_data[ip_val].get("organization") or rdap_data[ip_val].get("network_name")
            country = rdap_data[ip_val].get("country")
        if isinstance(geoip_data, dict) and ip_val in geoip_data:
            country = country or geoip_data[ip_val].get("country")

        if org or country:
            infra_label = org or f"Net ({country})"
            infra_node_id = f"infrastructure:{org or country}"
            if infra_node_id not in G:
                G.add_node(
                    infra_node_id,
                    label=infra_label[:30],
                    type="infrastructure",
                    value=org or country,
                    extra={"organization": org, "country": country},
                )
            if not G.has_edge(ip_node_id, infra_node_id):
                G.add_edge(
                    ip_node_id,
                    infra_node_id,
                    id=f"edge:{ip_node_id}->{infra_node_id}",
                    label="ROUTED_VIA",
                    relationship="IP->INFRASTRUCTURE",
                    extra={"organization": org, "country": country},
                )

    # 9. Format Cytoscape.js output
    nodes: List[Dict[str, Any]] = []
    for n in G.nodes:
        node_attrs = dict(G.nodes[n])
        nodes.append({
            "data": {
                "id": n,
                "label": node_attrs.get("label", n),
                "type": node_attrs.get("type", "unknown"),
                "value": node_attrs.get("value", n),
                "extra": node_attrs.get("extra", {}),
            }
        })

    edges: List[Dict[str, Any]] = []
    for u, v, k in G.edges:
        edge_attrs = dict(G.edges[u, v, k])
        edges.append({
            "data": {
                "id": edge_attrs.get("id", f"edge:{u}->{v}:{k}"),
                "source": u,
                "target": v,
                "label": edge_attrs.get("label", "CONNECTS_TO"),
                "relationship": edge_attrs.get("relationship", "GENERIC"),
                "extra": edge_attrs.get("extra", {}),
            }
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
