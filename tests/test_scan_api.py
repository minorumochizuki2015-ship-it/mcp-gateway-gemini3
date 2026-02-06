from __future__ import annotations

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


def _prep_db(
    tmp_path: Path, *, findings: list[dict] | None = None, run_id: str = "run-123"
):
    """テスト用の DB を初期化し、scan_results に1件追加する。"""
    db_path = tmp_path / "mcp_gateway.db"
    db = registry.init_db(db_path)
    server_id = upsert_server(db, name="gateway-lab", base_url="http://x")
    registry.save_scan_result(
        db=db,
        server_id=server_id,
        run_id=run_id,
        scan_type="mcpsafety",
        status="warn",
        findings=(
            findings
            if findings is not None
            else [
                {
                    "severity": "High",
                    "category": "認証",
                    "summary": "Token audience mismatch",
                    "resource": "/gateway/tools",
                    "owasp_llm_code": "LLM01",
                    "owasp_llm_title": "Prompt injection",
                    "evidence_source": "ci_evidence",
                }
            ]
        ),
    )
    return db_path


def test_list_scans(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/scans", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    item = data[0]
    assert item["id"] == "run-123"
    assert item["environment"] == "gateway-lab"
    assert item["severity_counts"]["high"] == 1


def test_get_scan_detail(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/scans/run-123", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan"]["status"] == "warn"
    assert data["findings"][0]["owasp_llm_code"] == "LLM01"


def test_get_scan_detail_not_found(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/scans/absent", params={"db_path": str(db_path)})
    assert resp.status_code == 404


def test_list_scans_empty_findings(tmp_path: Path):
    db_path = _prep_db(tmp_path, findings=[], run_id="run-empty")
    client = TestClient(gateway.app)
    resp = client.get("/api/scans", params={"db_path": str(db_path)})
    data = resp.json()
    item = next(i for i in data if i["id"] == "run-empty")
    assert item["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def test_list_scans_no_db(tmp_path: Path):
    db_path = tmp_path / "mcp_gateway.db"
    registry.init_db(db_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/scans", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    assert resp.json() == []
