"""
Integration tests for Phase 7 Graph Intelligence, Cross-Case Correlation, and Timeline API workflows.
Verifies end-to-end execution of graph construction, timeline generation, correlation detection,
and dedicated REST endpoints.
"""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_full_phase7_analyze_and_graph_endpoints():
    """
    Test full lifecycle on BEC fixture and verify Phase 7 outputs:
    1. /analyze response includes graph, correlation, timeline, campaign_score.
    2. GET /api/cases/{case_id}/graph returns valid Cytoscape structure.
    3. GET /api/cases/{case_id}/timeline returns ordered events.
    4. GET /api/cases/{case_id}/correlation returns relationship summary.
    """
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload .eml
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]

        # 2. Verify
        verify_res = await client.post(f"/api/cases/{case_id}/verify")
        assert verify_res.status_code == 200

        # 3. Analyze
        analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert analyze_res.status_code == 200
        a_data = analyze_res.json()

        # Check Phase 7 fields in analyze response
        assert "graph" in a_data
        assert "correlation" in a_data
        assert "timeline" in a_data
        assert "campaign_score" in a_data
        assert 0 <= a_data["campaign_score"] <= 10

        # Check Graph payload structure
        graph = a_data["graph"]
        assert "nodes" in graph
        assert "edges" in graph
        assert graph["node_count"] > 0
        assert graph["edge_count"] > 0
        for node in graph["nodes"]:
            assert "data" in node
            assert "id" in node["data"]
            assert "type" in node["data"]
            assert "label" in node["data"]

        for edge in graph["edges"]:
            assert "data" in edge
            assert "id" in edge["data"]
            assert "source" in edge["data"]
            assert "target" in edge["data"]
            assert "relationship" in edge["data"]

        # Check Timeline payload structure
        timeline = a_data["timeline"]
        assert len(timeline) >= 3
        for ev in timeline:
            assert "timestamp" in ev
            assert "event" in ev
            assert "source" in ev
            assert "details" in ev

        # 4. GET /api/cases/{case_id}/graph endpoint
        graph_res = await client.get(f"/api/cases/{case_id}/graph")
        assert graph_res.status_code == 200
        g_data = graph_res.json()
        assert g_data["node_count"] == graph["node_count"]
        assert len(g_data["nodes"]) == len(graph["nodes"])

        # 5. GET /api/cases/{case_id}/timeline endpoint
        timeline_res = await client.get(f"/api/cases/{case_id}/timeline")
        assert timeline_res.status_code == 200
        t_data = timeline_res.json()
        assert len(t_data) == len(timeline)
        assert t_data[0]["event"] == "EMAIL_RECEIVED"

        # 6. GET /api/cases/{case_id}/correlation endpoint
        corr_res = await client.get(f"/api/cases/{case_id}/correlation")
        assert corr_res.status_code == 200
        c_data = corr_res.json()
        assert "related_case_ids" in c_data
        assert "shared_indicators" in c_data
        assert "relationship_strength" in c_data
        assert "correlation_reasons" in c_data
        assert "campaign_score" in c_data


@pytest.mark.asyncio
async def test_graph_endpoints_404_on_nonexistent():
    """Verify 404 behavior for all Phase 7 endpoints when querying invalid case IDs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.get("/api/cases/MT-2026-999999/graph")
        assert res1.status_code == 404

        res2 = await client.get("/api/cases/MT-2026-999999/timeline")
        assert res2.status_code == 404

        res3 = await client.get("/api/cases/MT-2026-999999/correlation")
        assert res3.status_code == 404
