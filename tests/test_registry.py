"""Tests for registry module."""

from pathlib import Path

import pytest

from src.mcp_gateway import registry


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


def test_init_db(tmp_path: Path):
    """Test database initialization creates all tables."""
    db_file = tmp_path / "test.db"

    db = registry.init_db(db_file)

    assert db_file.exists()
    assert "mcp_servers" in db.table_names()
    assert "scan_results" in db.table_names()
    assert "council_evaluations" in db.table_names()
    assert "allowlist" in db.table_names()


def test_upsert_and_get_server(tmp_path: Path):
    """Test upserting and getting a server."""
    db = registry.init_db(tmp_path / "test.db")

    # Insert new server
    server_id = upsert_server(db, "test-server", "http://example.com", "draft")
    assert server_id > 0

    # Get server
    server = registry.get_server(db, server_id)
    assert server is not None
    assert server["name"] == "test-server"
    assert server["base_url"] == "http://example.com"
    assert server["status"] == "draft"

    # Update existing server
    server_id2 = upsert_server(
        db, "test-server", "http://example2.com", "approved"
    )
    assert server_id2 == server_id  # Same ID

    server = registry.get_server(db, server_id)
    assert server["base_url"] == "http://example2.com"
    assert server["status"] == "approved"


def test_upsert_server_requires_origin(tmp_path: Path):
    db = registry.init_db(tmp_path / "test.db")

    with pytest.raises(ValueError, match="origin_url and origin_sha"):
        registry.upsert_server(db, "missing-origin", "http://example.com", "draft")


def test_list_servers(tmp_path: Path):
    """Test listing servers with optional status filter."""
    db = registry.init_db(tmp_path / "test.db")

    upsert_server(db, "server1", "http://s1.com", "draft")
    upsert_server(db, "server2", "http://s2.com", "approved")
    upsert_server(db, "server3", "http://s3.com", "approved")

    # List all
    all_servers = registry.list_servers(db)
    assert len(all_servers) == 3

    # List by status
    approved = registry.list_servers(db, status="approved")
    assert len(approved) == 2


def test_save_scan_result(tmp_path: Path):
    """Test saving scan results."""
    db = registry.init_db(tmp_path / "test.db")

    server_id = upsert_server(db, "test", "http://test.com", "pending_scan")

    findings = [{"code": "test", "severity": "low"}]
    result_id = registry.save_scan_result(
        db, server_id, "run-123", "static", "pass", findings
    )

    assert result_id > 0

    # Verify saved
    results = list(db["scan_results"].rows_where("server_id = ?", [server_id]))
    assert len(results) == 1
    assert results[0]["run_id"] == "run-123"
    assert results[0]["scan_type"] == "static"


def test_save_council_evaluation(tmp_path: Path):
    """Test saving council evaluations."""
    db = registry.init_db(tmp_path / "test.db")

    server_id = upsert_server(db, "test", "http://test.com", "pending_scan")

    scores = {"security": 0.9, "utility": 0.8, "cost": 0.7}
    eval_id = registry.save_council_evaluation(
        db, server_id, "run-456", scores, "allow", "All checks passed"
    )

    assert eval_id > 0

    # Verify saved
    evals = list(db["council_evaluations"].rows_where("server_id = ?", [server_id]))
    assert len(evals) == 1
    assert evals[0]["decision"] == "allow"


def test_allowlist_snapshot(monkeypatch, tmp_path: Path):
    """Test getting allowlist snapshot."""
    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    db = registry.init_db(tmp_path / "test.db")

    server1 = upsert_server(db, "s1", "http://s1.com", "approved")
    server2 = upsert_server(db, "s2", "http://s2.com", "approved")

    # Add allowlist entries
    import json

    db["allowlist"].insert(
        {
            "server_id": server1,
            "tools_exposed": json.dumps([{"name": "tool1"}]),
            "status": "active",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )
    db["allowlist"].insert(
        {
            "server_id": server2,
            "tools_exposed": json.dumps([{"name": "tool2"}]),
            "status": "proposed",  # Not active
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )

    snapshot = registry.get_allowlist_snapshot(db)

    # Only active entries
    assert len(snapshot) == 1
    assert server1 in snapshot
    assert snapshot[server1] == [{"name": "tool1"}]


def test_allowlist_entries_pins_tools_manifest_hash(
    monkeypatch, tmp_path: Path
):
    """active entry の tools_manifest_hash が未設定なら TOFU で pinning する。"""
    import json

    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    db = registry.init_db(tmp_path / "test.db")
    server_id = upsert_server(db, "s1", "http://s1.com", "approved")
    tools = [{"name": "tool1", "args": {"x": 1}}]
    db["allowlist"].insert(
        {
            "server_id": server_id,
            "tools_exposed": json.dumps(tools),
            "status": "active",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )

    entries = registry.get_allowlist_entries(db)
    assert len(entries) == 1
    assert entries[0]["tools_manifest_hash"]
    row = db["allowlist"].get(entries[0]["id"])
    assert row["tools_manifest_hash"] == entries[0]["tools_manifest_hash"]

    event = json.loads(evidence_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["event"] == "tool_manifest_changed"
    assert event["change_type"] == "pinned"


def test_allowlist_entries_revokes_on_manifest_drift(monkeypatch, tmp_path: Path):
    """active entry の tools_manifest_hash が drift したら revoke する。"""
    import json

    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    db = registry.init_db(tmp_path / "test.db")
    server_id = upsert_server(db, "s1", "http://s1.com", "approved")
    tools = [{"name": "tool1", "args": {"x": 1}}]
    row_id = db["allowlist"].insert(
        {
            "server_id": server_id,
            "tools_exposed": json.dumps(tools),
            "status": "active",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    ).last_pk
    db["allowlist"].update(row_id, {"tools_manifest_hash": "0" * 64})

    entries = registry.get_allowlist_entries(db)
    assert entries == []
    row = db["allowlist"].get(row_id)
    assert row["status"] == "revoked"

    event = json.loads(evidence_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["event"] == "tool_manifest_changed"
    assert event["change_type"] == "drift"
    assert event["action"] == "revoked"


def test_allowlist_entries_merge_tool_risk_and_caps(monkeypatch, tmp_path: Path):
    """tools_exposed の risk/capabilities を allowlist に反映する。"""
    import json

    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    db = registry.init_db(tmp_path / "test.db")
    server_id = upsert_server(db, "s1", "http://s1.com", "approved")
    tools = [
        {"name": "tool1", "risk_level": "high", "capabilities": ["network_write", "sampling"]}
    ]
    db["allowlist"].insert(
        {"server_id": server_id, "tools_exposed": json.dumps(tools), "risk_level": "medium", "capabilities": "[]", "status": "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}
    )

    entries = registry.get_allowlist_entries(db)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["risk_level"] == "high"
    assert "network_write" in entry["capabilities"]
    row = db["allowlist"].get(entry["id"])
    assert row["risk_level"] == "high"
    assert "network_write" in json.loads(row["capabilities"])
