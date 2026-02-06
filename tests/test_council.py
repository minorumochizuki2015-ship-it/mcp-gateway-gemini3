"""Tests for AI Council module."""

import json
from pathlib import Path

import pytest

from src.mcp_gateway import ai_council, registry

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




@pytest.fixture(autouse=True)
def _patch_shadow_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Shadow Audit の書き込み先をテスト用に差し替える。"""
    import src.mcp_gateway.evidence as ev
    from jobs import retest_queue
    from src.mcp_gateway import ai_council

    manifest = tmp_path / "shadow_manifest.jsonl"
    chain = tmp_path / "shadow_manifest.sha256"
    monkeypatch.setattr(ev, "SHADOW_MANIFEST", manifest)
    monkeypatch.setattr(ev, "SHADOW_CHAIN", chain)
    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    monkeypatch.setattr(retest_queue, "EVIDENCE_PATH", evidence_path)
    monkeypatch.setattr(ai_council, "EVIDENCE_PATH", evidence_path)


def test_evaluate_deny_on_critical_findings(tmp_path: Path):
    """Test that council denies when critical findings are present."""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    # Patch evidence
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    ev.append = lambda event, path="": original_append(event, evidence_file)

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )

        # Create scan with critical finding
        findings = [
            {
                "code": "critical_vuln",
                "severity": "critical",
                "message": "Critical issue",
            }
        ]
        registry.save_scan_result(db, server_id, "run-1", "static", "fail", findings)

        result = ai_council.evaluate(db, server_id)

        assert result["decision"] == "deny"
        assert result["scores"]["security"] == 0.0
    finally:
        ev.append = original_append


@pytest.mark.parametrize(
    "decision_status,scan_status,findings",
    [
        ("allow", "pass", [{"code": "info", "severity": "info"}]),
        ("deny", "fail", [{"code": "critical", "severity": "critical", "message": "bad"}]),
        ("quarantine", "warn", [{"code": "warn", "severity": "warning", "message": "warn"}]),
    ],
)
def test_allowlist_updates_on_council_decision(
    tmp_path: Path, decision_status: str, scan_status: str, findings: list[dict]
):
    """decision に応じて proposed→active 昇格または active revoke が行われる。"""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    ev.append = lambda event, path="": original_append(event, evidence_file)

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )
        tools_active = [{"name": "existing"}]
        db["allowlist"].insert(
            {
                "server_id": server_id,
                "tools_exposed": json.dumps(tools_active),
                "status": "active",
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z",
            }
        )
        tools_proposed = [{"name": "new_tool", "description": "ok"}]
        if decision_status == "allow":
            db["allowlist"].insert(
                {
                    "server_id": server_id,
                    "tools_exposed": json.dumps(tools_proposed),
                    "status": "proposed",
                    "created_at": "2025-01-02T00:00:00Z",
                    "updated_at": "2025-01-02T00:00:00Z",
                }
            )
        registry.save_scan_result(db, server_id, "run-1", "static", scan_status, findings)

        ai_council.evaluate(db, server_id)

        rows = list(db["allowlist"].rows_where("server_id = ?", [server_id]))
        active_rows = [r for r in rows if r["status"] == "active"]
        revoked_rows = [r for r in rows if r["status"] == "revoked"]
        if decision_status == "allow":
            assert len(active_rows) == 1
            assert json.loads(active_rows[0]["tools_exposed"]) == tools_proposed
            assert revoked_rows, "existing active rows should be revoked"
            snapshot = registry.get_allowlist_snapshot(db)
            assert snapshot == {server_id: tools_proposed}
        else:
            assert not active_rows
            assert revoked_rows
            snapshot = registry.get_allowlist_snapshot(db)
            assert server_id not in snapshot
    finally:
        ev.append = original_append


def test_evaluate_allow_on_no_findings(tmp_path: Path):
    """Test that council allows when no critical findings."""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    # Patch evidence
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    ev.append = lambda event, path="": original_append(event, evidence_file)

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )

        # Create scan with info findings only
        findings = [{"code": "info", "severity": "info", "message": "Info message"}]
        registry.save_scan_result(db, server_id, "run-1", "static", "pass", findings)

        result = ai_council.evaluate(db, server_id)

        assert result["decision"] == "allow"
        assert result["scores"]["security"] == 1.0
    finally:
        ev.append = original_append


def test_evaluate_quarantine_on_warnings(tmp_path: Path):
    """Test that council quarantines on warnings."""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    # Patch evidence
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    ev.append = lambda event, path="": original_append(event, evidence_file)

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )

        # Create scan with warning
        findings = [
            {"code": "warn", "severity": "warning", "message": "Warning message"}
        ]
        registry.save_scan_result(db, server_id, "run-1", "static", "warn", findings)

        result = ai_council.evaluate(db, server_id)

        assert result["decision"] == "quarantine"
        assert result["scores"]["security"] == 0.5
    finally:
        ev.append = original_append


def test_evaluate_emits_evidence(tmp_path: Path):
    """Test that evaluate emits mcp_council_run evidence."""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    # Patch evidence
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    events = []

    def mock_append(event, path=""):
        events.append(event)
        return original_append(event, evidence_file)

    ev.append = mock_append

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )
        findings = [{"code": "info", "severity": "info"}]
        registry.save_scan_result(db, server_id, "run-1", "static", "pass", findings)

        ai_council.evaluate(db, server_id)

        # Find council event
        council_events = [e for e in events if e.get("event") == "mcp_council_run"]
        assert len(council_events) == 1
        assert council_events[0]["server_id"] == server_id
        assert "scores" in council_events[0]
        assert "decision" in council_events[0]
        assert "meta_judge" in council_events[0]["scores"]
        assert "meta_judge" in council_events[0]["weights"]
        assert "meta_judge" in council_events[0]["profiles_used"]
        cfg = council_events[0]["deterministic_config"]
        assert cfg["meta_prompt_id"] == ai_council.META_PROMPT_ID
        assert cfg["seed"] == ai_council.META_SEED
        assert cfg["temperature"] == ai_council.META_TEMPERATURE
        assert cfg["max_tokens"] == ai_council.META_MAX_TOKENS
    finally:
        ev.append = original_append


def test_quarantine_schedules_retest(tmp_path: Path):
    """Test that quarantine decision schedules a retest."""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    # Patch evidence
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    events = []

    def mock_append(event, path=""):
        events.append(event)
        return original_append(event, evidence_file)

    ev.append = mock_append

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )

        # Create scan with warnings (will trigger quarantine)
        findings = [{"code": "warn", "severity": "warning", "message": "Warning"}]
        registry.save_scan_result(db, server_id, "run-1", "static", "warn", findings)

        ai_council.evaluate(db, server_id)

        # Find retest_scheduled event
        retest_events = [e for e in events if e.get("event") == "retest_scheduled"]
        assert retest_events
        assert retest_events[0]["server_id"] == server_id
        assert retest_events[0]["reason"].startswith("council_quarantine:")
        shadow = (
            (tmp_path / "shadow_manifest.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert shadow
        shadow_record = json.loads(shadow[-1])
        assert shadow_record["event"] == "council_retest"
        assert shadow_record["decision"] == "quarantine"
        assert shadow_record["reason"].startswith("council_quarantine:")
    finally:
        ev.append = original_append


def test_evaluate_denies_on_tool_risk_level(tmp_path: Path):
    """Tool-level critical risk should force deny."""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"
    import src.mcp_gateway.evidence as ev
    original_append = ev.append
    ev.append = lambda event, path="": original_append(event, evidence_file)

    try:
        server_id = upsert_server(db, "test", "http://test.com", "pending_scan")
        registry.save_scan_result(db, server_id, "run-1", "static", "pass", [])
        db["allowlist"].insert(
            {"server_id": server_id, "tools_exposed": json.dumps([{"name": "tool1", "risk_level": "critical"}]), "risk_level": "medium", "capabilities": "[]", "status": "proposed", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}
        )

        result = ai_council.evaluate(db, server_id)

        assert result["decision"] == "deny"
    finally:
        ev.append = original_append


def test_quarantine_emits_backlog_evidence(tmp_path: Path, monkeypatch):
    """Retest enqueue emits backlog Evidence when quarantine occurs (Redis未設定)。"""
    db = registry.init_db(tmp_path / "test.db")

    # Capture retest_queue evidence events
    from jobs import retest_queue

    retest_events = []
    if not hasattr(retest_queue, "evidence"):
        import src.mcp_gateway.evidence as ev

        retest_queue.evidence = ev
    monkeypatch.setattr(
        retest_queue.evidence,
        "append",
        lambda event, path="": retest_events.append(event),
    )

    # Patch council evidence to temp file
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    ev.append = lambda event, path="": original_append(
        event, tmp_path / "evidence.jsonl"
    )

    try:
        server_id = upsert_server(
            db, "test", "http://test.com", "pending_scan"
        )
        findings = [{"code": "warn", "severity": "warning", "message": "Warning"}]
        registry.save_scan_result(db, server_id, "run-1", "static", "warn", findings)

        ai_council.evaluate(db, server_id)

        queued = [
            e
            for e in retest_events
            if e.get("event") in ("retest_queue_unavailable", "retest_scheduled")
        ]
        assert queued, "retest evidence not emitted"
        reasons = [e.get("reason", "") for e in queued]
        assert any(r.startswith("council_quarantine:") for r in reasons)
    finally:
        ev.append = original_append
