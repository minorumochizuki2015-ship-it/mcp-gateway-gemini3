"""scanner モジュールのテスト。"""

from __future__ import annotations

import json
import unittest.mock as mock
from pathlib import Path

import httpx
import pytest

from src.mcp_gateway import registry, scanner


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


def _valid_manifest() -> dict:
    return {
        "name": "my-mcp",
        "version": "1.0.0",
        "description": "sample",
        "endpoints": [
            {"name": "default", "url": "https://example.com/mcp", "protocol": "https"}
        ],
        "tools": [
            {
                "name": "list_files",
                "description": "list files",
                "inputs_schema": {},
                "outputs_schema": {},
            }
        ],
        "metadata": {"owner": "team", "tags": ["file"]},
    }


def test_validate_manifest_success():
    manifest = _valid_manifest()
    validated = scanner.validate_manifest(manifest)
    assert validated["endpoints"][0]["auth"]["type"] == "none"


def test_validate_manifest_missing_required():
    manifest = _valid_manifest()
    manifest.pop("name")
    with pytest.raises(ValueError):
        scanner.validate_manifest(manifest)


def test_validate_manifest_invalid_protocol():
    manifest = _valid_manifest()
    manifest["endpoints"][0]["protocol"] = "ftp"
    with pytest.raises(ValueError):
        scanner.validate_manifest(manifest)


def test_static_scan_passes_with_valid_manifest():
    server = {
        "name": "test",
        "base_url": "http://test.com",
        "origin_url": "https://github.com/org/repo",
        "origin_sha": "a1b2c3d",
    }
    response = httpx.Response(200, json=_valid_manifest())
    with mock.patch("src.mcp_gateway.scanner.httpx.get", return_value=response):
        result = scanner.static_scan(server)

    assert result["status"] == "pass"
    assert result["scan_type"] == "static"
    assert len(result["findings"]) == 0


def test_static_scan_fails_when_manifest_missing():
    server = {
        "name": "test",
        "base_url": "http://test.com",
        "origin_url": "https://github.com/org/repo",
        "origin_sha": "a1b2c3d",
    }
    response = httpx.Response(404, content=b"")
    with mock.patch("src.mcp_gateway.scanner.httpx.get", return_value=response):
        result = scanner.static_scan(server)

    assert result["status"] == "fail"
    assert result["scan_type"] == "static"
    assert result["findings"]
    assert result["reason"].startswith("manifest_fetch_failed")


def test_static_scan_prefers_github_origin():
    server = {
        "name": "test",
        "base_url": "http://test.com",
        "origin_url": "https://github.com/org/repo",
        "origin_sha": "a1b2c3d",
    }
    response = httpx.Response(200, json=_valid_manifest())

    def fake_get(url, timeout):
        if url.startswith("https://raw.githubusercontent.com/org/repo/a1b2c3d/"):
            return response
        return httpx.Response(404, content=b"")

    with mock.patch("src.mcp_gateway.scanner.httpx.get", side_effect=fake_get):
        result = scanner.static_scan(server)

    assert result["status"] == "pass"
    assert result["scan_type"] == "static"


def test_static_scan_rejects_missing_origin_sha():
    server = {
        "name": "test",
        "base_url": "http://test.com",
        "origin_url": "https://github.com/org/repo",
    }

    result = scanner.static_scan(server)

    assert result["status"] == "fail"
    assert result["reason"] == "origin_missing"


def test_safety_scan_handles_unavailable_tool():
    """mcpsafety が無い場合 skip する。"""
    with mock.patch("shutil.which", return_value=None):
        result = scanner.safety_scan({"base_url": "http://test.com"})

        assert result["status"] == "skip"
        assert "not found in PATH" in result["reason"]
        assert result["scan_type"] == "mcpsafety"
        assert len(result["findings"]) == 0


def test_safety_scan_blocks_p0_and_saves_artifact(tmp_path: Path):
    """P0 を検知したら fail し、artifact を保存する。"""
    fake_out = {
        "vulnerabilities": [
            {"rule_id": "VULN-1", "severity": "high", "message": "p0", "location": "x"}
        ],
        "summary": {"handshake": "ok", "latency_ms": 123, "command_surface": ["run"]},
    }

    class DummyResult:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = json.dumps(fake_out)
            self.stderr = ""

    with mock.patch("shutil.which", return_value="mcpsafety"), mock.patch(
        "subprocess.run", return_value=DummyResult()
    ):
        run_id = "run-1"
        artifacts_root = tmp_path / "artifacts"
        result = scanner.safety_scan(
            {"base_url": "http://test.com"},
            run_id=run_id,
            artifacts_root=artifacts_root,
        )

        assert result["status"] == "fail"
        assert result["blocked_by"] == "P0"
        assert result["counts"]["p0"] == 1
        assert result["report_path"]
        assert result["report_sha256"]
        assert Path(result["report_path"]).exists()


def test_run_scan_saves_to_registry_and_emits_evidence(tmp_path: Path):
    """static scan の Evidence を確認する。"""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

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
        response = httpx.Response(200, json=_valid_manifest())
        with mock.patch("src.mcp_gateway.scanner.httpx.get", return_value=response):
            result = scanner.run_scan(db, server_id, scan_types=["static"])

        assert "run_id" in result
        assert result["server_id"] == server_id

        scan_events = [e for e in events if e.get("event") == "mcp_scan_run"]
        # static_scan() 自身も Evidence を emit するため、2 イベントになる
        assert len(scan_events) == 2
        # run_scan() が emit したイベント（2つ目）を検証
        assert scan_events[1]["server_id"] == server_id

        snapshot_events = [e for e in events if e.get("event") == "registry_snapshot"]
        assert snapshot_events
        snapshot = snapshot_events[-1]
        assert snapshot["active_servers"] == 0
        assert snapshot["revoked_servers"] == 0
        assert snapshot.get("snapshot_id")
    finally:
        ev.append = original_append


def test_run_scan_mcpsafety_emits_artifact_and_counts(tmp_path: Path):
    """mcpsafety 実行時に artifact と Evidence を出力する。"""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    events = []

    def mock_append(event, path=""):
        events.append(event)
        return original_append(event, evidence_file)

    ev.append = mock_append

    fake_out = {
        "vulnerabilities": [
            {"rule_id": "VULN-1", "severity": "medium", "message": "p1", "location": ""}
        ],
        "summary": {"handshake": "ok", "latency_ms": 50, "command_surface": ["ls"]},
    }

    class DummyResult:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = json.dumps(fake_out)
            self.stderr = ""

    try:
        with mock.patch("shutil.which", return_value="mcpsafety"), mock.patch(
            "subprocess.run", return_value=DummyResult()
        ):
            server_id = upsert_server(
                db, "test", "http://test.com", "pending_scan"
            )
            result = scanner.run_scan(
                db,
                server_id,
                scan_types=["mcpsafety"],
                artifacts_root=tmp_path / "artifacts",
            )

            scan_events = [e for e in events if e.get("event") == "mcp_scan_run"]
            # safety_scan() と run_scan() の両方が Evidence を emit するため、2 イベント
            assert len(scan_events) == 2
            # run_scan() が emit したイベント（2つ目）に report_path がある
            assert scan_events[1]["p1"] == 1
            assert scan_events[1]["status"] == "fail"
            assert scan_events[1]["report_path"]
            assert Path(scan_events[1]["report_path"]).exists()
            assert Path(result["results"][0]["report_path"]).exists()
    finally:
        ev.append = original_append


def test_schedule_retest_emits_evidence(tmp_path: Path):
    """retest_scheduled Evidence を確認する。"""
    db = registry.init_db(tmp_path / "test.db")
    evidence_file = tmp_path / "evidence.jsonl"

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

        run_id = scanner.schedule_retest(db, server_id, "test_reason", delay_hours=48)

        assert run_id is not None

        retest_events = [e for e in events if e.get("event") == "retest_scheduled"]
        assert len(retest_events) == 1
        assert retest_events[0]["server_id"] == server_id
        assert retest_events[0]["reason"] == "test_reason"
        assert retest_events[0]["delay_hours"] == 48
        assert "scheduled_at" in retest_events[0]
    finally:
        ev.append = original_append


def test_semantic_scan_skips_without_api_key(monkeypatch):
    """GOOGLE_API_KEY 未設定時は skip する。"""
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    result = scanner.semantic_scan({"name": "test"}, manifest=_valid_manifest())
    assert result["status"] == "skip"
    assert result["scan_type"] == "semantic"
    assert result["eval_method"] == "skipped"


def test_semantic_scan_skips_without_tools(monkeypatch):
    """tools が空の manifest では skip する。"""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    result = scanner.semantic_scan(
        {"name": "test"},
        manifest={"name": "x", "version": "1.0.0", "tools": []},
    )
    assert result["status"] == "skip"
    assert result["reason"] == "no_tools_to_analyze"


def test_semantic_scan_skips_no_manifest():
    """manifest が None の場合 skip する。"""
    result = scanner.semantic_scan({"name": "test"}, manifest=None)
    assert result["status"] == "skip"


def test_semantic_scan_returns_gemini_result(monkeypatch):
    """Gemini API 正常応答時にセマンティック分析結果を返す。"""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")

    fake_response_json = json.dumps(
        {
            "overall_risk": "medium",
            "tool_analyses": [
                {
                    "tool_name": "exec_command",
                    "risk_level": "high",
                    "threat_type": "command_injection",
                    "description": "Tool allows arbitrary command execution",
                    "confidence": 0.95,
                }
            ],
            "summary": "One high-risk tool detected with command injection potential.",
            "recommended_action": "quarantine",
        }
    )

    class FakeResponse:
        text = fake_response_json

    class FakeModels:
        def generate_content(self, **kwargs):
            return FakeResponse()

    class FakeClient:
        def __init__(self, **kwargs):
            self.models = FakeModels()

    monkeypatch.setattr("google.genai.Client", FakeClient)

    result = scanner.semantic_scan(
        {"name": "suspicious-server"},
        manifest={
            "tools": [
                {
                    "name": "exec_command",
                    "description": "Execute system commands",
                    "inputs_schema": {"type": "object"},
                    "outputs_schema": {"type": "object"},
                }
            ]
        },
    )

    assert result["status"] == "fail"
    assert result["scan_type"] == "semantic"
    assert result["eval_method"] == "gemini"
    assert result["overall_risk"] == "medium"
    assert result["recommended_action"] == "quarantine"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][0]["code"] == "semantic_command_injection"


def test_semantic_scan_pass_on_safe_tools(monkeypatch):
    """安全なツールのみの場合 pass を返す。"""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")

    fake_response_json = json.dumps(
        {
            "overall_risk": "safe",
            "tool_analyses": [
                {
                    "tool_name": "list_files",
                    "risk_level": "safe",
                    "threat_type": "none",
                    "description": "Safe file listing operation",
                    "confidence": 0.99,
                }
            ],
            "summary": "All tools appear safe.",
            "recommended_action": "allow",
        }
    )

    class FakeResponse:
        text = fake_response_json

    class FakeModels:
        def generate_content(self, **kwargs):
            return FakeResponse()

    class FakeClient:
        def __init__(self, **kwargs):
            self.models = FakeModels()

    monkeypatch.setattr("google.genai.Client", FakeClient)

    result = scanner.semantic_scan(
        {"name": "safe-server"}, manifest=_valid_manifest()
    )

    assert result["status"] == "pass"
    assert len(result["findings"]) == 0


def test_semantic_scan_handles_gemini_error(monkeypatch):
    """Gemini API エラー時は skip する。"""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")

    class FakeModels:
        def generate_content(self, **kwargs):
            raise RuntimeError("API quota exceeded")

    class FakeClient:
        def __init__(self, **kwargs):
            self.models = FakeModels()

    monkeypatch.setattr("google.genai.Client", FakeClient)

    result = scanner.semantic_scan(
        {"name": "test"}, manifest=_valid_manifest()
    )

    assert result["status"] == "skip"
    assert "gemini_error" in result["reason"]
    assert result["eval_method"] == "error"


def test_semantic_scan_pydantic_models():
    """Pydantic モデルが正しくパースされることを検証。"""
    analysis = scanner.ToolThreatAnalysis(
        tool_name="test",
        risk_level="high",
        threat_type="command_injection",
        description="Test threat",
        confidence=0.9,
    )
    assert analysis.tool_name == "test"
    assert analysis.confidence == 0.9

    scan_result = scanner.SemanticScanResult(
        overall_risk="medium",
        tool_analyses=[analysis],
        summary="Test",
        recommended_action="quarantine",
    )
    assert len(scan_result.tool_analyses) == 1
    assert scan_result.recommended_action == "quarantine"


def test_static_scan_emits_evidence(tmp_path, monkeypatch):
    """static_scan が mcp_scan_run Evidence を記録することを検証する。"""
    evidence_file = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_file))

    server = {
        "server_id": "test-server",
        "name": "Test Server",
        "base_url": "http://test.com",
        "origin_url": "https://github.com/org/repo",
        "origin_sha": "a1b2c3d",
    }
    response = httpx.Response(200, json=_valid_manifest())
    with mock.patch("src.mcp_gateway.scanner.httpx.get", return_value=response):
        result = scanner.static_scan(server)

    assert result["status"] == "pass"
    assert result["scan_type"] == "static"

    # Evidence ファイルが作成されていることを確認
    assert evidence_file.exists()

    # Evidence 内容を検証
    lines = evidence_file.read_text().strip().split("\n")
    assert len(lines) == 1

    event = json.loads(lines[0])
    assert event["event"] == "mcp_scan_run"
    assert event["actor"] == "scanner"
    assert event["trigger_source"] == "static_scan"
    assert event["server_id"] == "test-server"
    assert event["scan_type"] == "static"
    assert event["status"] == "pass"
    assert event["findings_count"] == 0
    assert "ts" in event
    assert "run_id" in event
