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
        run_id="run-allow-1",
        scan_type="mcpsafety",
        status="pass",
        findings=[],
    )
    return db_path


def test_allowlist_list(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/allowlist", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    item = data[0]
    assert item["name"] == "gateway-lab"
    assert item["base_url"] == "http://gateway.lab"
    assert item["status"] == "active"
    assert item["last_scan_ts"]


def test_allowlist_detail(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/allowlist/1", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["server_id"] == 1
    assert data["name"] == "gateway-lab"
    assert data["last_scan_ts"]


def test_allowlist_detail_not_found(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/allowlist/999", params={"db_path": str(db_path)})
    assert resp.status_code == 404


def test_mcp_detail(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    db = registry.init_db(db_path)
    db["allowlist"].update(1, {"risk_level": "high", "capabilities": '["sampling","network_write"]'})
    registry.save_scan_result(db=db, server_id=1, run_id="run-latest", scan_type="mcpsafety", status="warn", findings=[])

    client = TestClient(gateway.app)
    resp = client.get("/api/mcp/1", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["server"]["name"] == "gateway-lab"
    assert data["allowlist"]["risk_level"] == "high"
    assert "network_write" in data["allowlist"]["capabilities"]
    assert data["scan"]["run_id"] == "run-latest"


def test_allowlist_status(tmp_path: Path):
    db_path = _prep_db(tmp_path)
    client = TestClient(gateway.app)
    resp = client.get("/api/allowlist/status", params={"db_path": str(db_path)})
    assert resp.status_code == 200
    body = resp.json()
    for key in (
        "shadow_audit_chain_ok",
        "policy_bundle_hash_ok",
        "policy_bundle_present_ok",
        "policy_bundle_sha256",
        "policy_bundle_signature_status",
    ):
        assert key in body
    assert body["policy_bundle_hash_ok"] == body["policy_bundle_present_ok"]
