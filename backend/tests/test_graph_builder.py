"""
Tests for Phase 7 NetworkX forensic relationship graph builder.
"""

import pytest
from app.graph.builder import build_case_graph
from app.schemas.graph import GraphResponse


def test_graph_builder_full_case():
    """Verify node and edge generation for a complete forensic case."""
    case_data = {
        "email": {
            "subject": "URGENT: Change Vendor Bank Account Today",
            "from_address": "CFO <cfo@acme-finance.com>",
            "reply_to": "acme.invoice.alert@gmail.com",
            "return_path": "<billing@notify-acme.co>",
            "date": "Thu, 03 Sep 2026 10:19:12 +0000",
        },
        "indicators": [
            {"type": "url", "value": "https://secure-acme-login.example/verify-invoice"},
            {"type": "domain", "value": "secure-acme-login.example"},
            {"type": "ip", "value": "198.51.100.42"},
        ],
        "infrastructure": {"source_ip": "198.51.100.42"},
        "dns": {
            "acme-finance.com": {
                "records": {"A": ["198.51.100.42"]},
                "status": "AVAILABLE",
            }
        },
        "rdap": {
            "198.51.100.42": {"organization": "Cloud Host AS99", "country": "DE"}
        },
    }

    graph = build_case_graph(case_data, "MT-2026-000001")
    assert graph["node_count"] > 5
    assert graph["edge_count"] > 5

    # Check node types
    node_types = {n["data"]["type"] for n in graph["nodes"]}
    assert "email" in node_types
    assert "sender" in node_types
    assert "reply_to" in node_types
    assert "return_path" in node_types
    assert "domain" in node_types
    assert "url" in node_types
    assert "ip" in node_types
    assert "infrastructure" in node_types

    # Check edge relationships
    relationships = {e["data"]["relationship"] for e in graph["edges"]}
    assert "EMAIL->SENDER" in relationships
    assert "EMAIL->REPLY_TO" in relationships
    assert "EMAIL->RETURN_PATH" in relationships
    assert "EMAIL->URL" in relationships
    assert "URL->DOMAIN" in relationships
    assert "EMAIL->IP" in relationships

    # Validate against Pydantic schema
    response_obj = GraphResponse(nodes=graph["nodes"], edges=graph["edges"])
    assert len(response_obj.nodes) == graph["node_count"]
    assert len(response_obj.edges) == graph["edge_count"]


def test_graph_builder_duplicate_prevention():
    """Verify that multiple URLs sharing the same domain collapse into a single domain node."""
    case_data = {
        "email": {"subject": "Test"},
        "indicators": [
            {"type": "url", "value": "https://phish.example/login"},
            {"type": "url", "value": "https://phish.example/verify"},
            {"type": "url", "value": "https://phish.example/reset"},
            {"type": "domain", "value": "phish.example"},
        ],
    }

    graph = build_case_graph(case_data, "MT-2026-000002")
    domain_nodes = [n for n in graph["nodes"] if n["data"]["type"] == "domain" and n["data"]["value"] == "phish.example"]
    assert len(domain_nodes) == 1

    # Should have 3 URL nodes all pointing to the single domain node
    url_edges = [e for e in graph["edges"] if e["data"]["target"] == "domain:phish.example" and e["data"]["relationship"] == "URL->DOMAIN"]
    assert len(url_edges) == 3


def test_graph_builder_empty_case():
    """Verify minimal/empty case produces a valid graph without crashing."""
    graph = build_case_graph({}, "MT-2026-000003")
    assert graph["node_count"] == 1
    assert graph["nodes"][0]["data"]["type"] == "email"
    assert graph["edge_count"] == 0
