from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from mcp_gateway import gateway, registry
from mcp_gateway.testing import TestClient


DEFAULT_ORIGIN_URL = "https://github.com/example/repo"
DEFAULT_ORIGIN_SHA = "a1b2c3d"
REGISTRY_UPSERT_SERVER = registry.upsert_server


def upsert_server(
    db,
    name,
    base_url,
    status="draft",
    *,
    origin_url=DEFAULT_ORIGIN_URL,
    origin_sha=DEFAULT_ORIGIN_SHA,
):
    return REGISTRY_UPSERT_SERVER(
        db,
        name,
        base_url,
        status,
        origin_url=origin_url,
        origin_sha=origin_sha,
    )


def _prep_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "mcp_gateway.db"
    db = registry.init_db(db_path)
    server_id = upsert_server(
        db, name="gateway-lab", base_url="http://gateway.lab", status="approved"
    )
    now = datetime.now(timezone.utc).isoformat()
    db["allowlist"].insert(
        {
            "server_id": server_id,
            "tools_exposed": "[]",
            "risk_level": "medium",
            "capabilities": "[]",
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }
    )
    registry.save_scan_result(
        db=db,
        server_id=server_id,
        run_id="run-1",
        scan_type="mcpsafety",
        status="warn",
        findings=[
            {
                "severity": "High",
                "category": "認証",
                "summary": "Token audience mismatch",
                "resource": "/gateway/tools",
                "owasp_llm_code": "LLM01",
                "owasp_llm_title": "Prompt injection",
                "evidence_source": "ci_evidence",
            }
        ],
    )
    registry.save_council_evaluation(
        db=db,
        server_id=server_id,
        run_id="council-1",
        scores={"security": 0.9, "utility": 0.2, "cost": 0.1},
        decision="allow",
        rationale="Looks safe enough",
    )
    return db_path


def test_dashboard_summary_no_db(tmp_path: Path) -> None:
    client = TestClient(gateway.app)
    missing_db = tmp_path / "missing.db"
    resp = client.get("/api/dashboard/summary", params={"db_path": str(missing_db)})
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowlist"] == {"total": 0, "active": 0, "deny": 0, "quarantine": 0}
    assert body["scans"]["total"] == 0
    assert body["scans"]["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    assert body["council"] == {"total": 0, "latest_decision": "", "latest_ts": ""}


def test_dashboard_summary_populates_counts(tmp_path: Path) -> None:
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/dashboard/summary", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    body = resp.json()

    assert body["allowlist"]["total"] == 1
    assert body["allowlist"]["active"] == 1
    assert body["allowlist"]["deny"] == 0
    assert body["allowlist"]["quarantine"] == 0

    assert body["scans"]["total"] == 1
    assert body["scans"]["latest_status"] == "warn"
    assert body["scans"]["latest_ts"]
    assert body["scans"]["severity_counts"]["high"] == 1

    assert body["council"]["total"] == 1
    assert body["council"]["latest_decision"] == "allow"
    assert body["council"]["latest_ts"]
