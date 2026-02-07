"""Tests for gateway module."""

import asyncio
import json
import os
from pathlib import Path

import httpx
import pytest
import sqlite_utils  # type: ignore[import-not-found]
from fastapi import Response

import src.mcp_gateway.gateway as gateway
from src.mcp_gateway import registry

# isort: off
from src.mcp_gateway.gateway import (
    RATE_LIMIT_BURST,
    REQUEST_TIMEOUT_S,
    RESPONSE_SIZE_CAP_BYTES,
    app,
    disable_rate_limit,
    enable_rate_limit,
    reset_rate_limit,
)

# isort: on
from src.mcp_gateway.testing import TestClient

DEFAULT_ORIGIN_URL = "https://github.com/example/repo"
DEFAULT_ORIGIN_SHA = "a1b2c3d"
REGISTRY_UPSERT_SERVER = registry.upsert_server

os.environ.setdefault("MCP_GATEWAY_PROXY_TOKEN", "test-token")


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
def _set_evidence_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Evidence の出力先をテスト用に固定する。"""
    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    import src.mcp_gateway.evidence as ev

    original_append = ev.append
    default_path = Path("observability/policy/ci_evidence.jsonl")
    monkeypatch.setattr(gateway, "SNAPSHOT_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(gateway, "DIFF_DIR", tmp_path / "diffs")

    def _patched_append(event, path=default_path):
        if Path(path) == default_path:
            path = evidence_path
        return original_append(event, path)

    monkeypatch.setattr(ev, "append", _patched_append)

    async def _inline_to_thread(func, /, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(gateway.asyncio, "to_thread", _inline_to_thread)


@pytest.fixture(autouse=True)
def _reset_rate_limit_autouse():
    """各テスト前にレートリミット状態をクリアする。"""
    reset_rate_limit()
    disable_rate_limit()
    yield
    reset_rate_limit()
    disable_rate_limit()


@app.get("/_large_test")
async def _large_test() -> Response:
    """レスポンスサイズが制限を超えるテスト用エンドポイント。"""
    return Response(content="x" * (RESPONSE_SIZE_CAP_BYTES + 1))


@app.get("/_slow_test")
async def _slow_test() -> dict:
    """タイムアウトを誘発するテスト用エンドポイント。"""
    await asyncio.sleep(REQUEST_TIMEOUT_S + 0.5)
    return {"status": "slow"}


def test_health_endpoint():
    """Test /health endpoint returns 200 OK."""
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_emits_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Health 叩きで Evidence が 1 行追加される。"""
    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert evidence_path.exists()
    lines = evidence_path.read_text(encoding="utf-8").splitlines()
    assert lines
    event = json.loads(lines[-1])
    assert event["event"] == "health_check"
    assert event["status"] == "ok"
    assert event["path"] == "/health"


def test_health_emits_evidence_twice(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """/health を複数回叩くとその回数分 health_check が追記される。"""
    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    client.get("/health")
    client.get("/health")

    assert evidence_path.exists()
    lines = evidence_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2
    last_two = [json.loads(lines[-2]), json.loads(lines[-1])]
    for event in last_two:
        assert event["event"] == "health_check"
        assert event["status"] == "ok"
        assert event["path"] == "/health"


def test_health_emits_evidence_to_default_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """ENV 未設定時はデフォルトの ci_evidence に health_check が追記される。"""
    monkeypatch.delenv("MCP_GATEWAY_EVIDENCE_PATH", raising=False)
    default_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setattr(gateway, "DEFAULT_EVIDENCE_PATH", default_path)

    client = TestClient(app)
    client.get("/health")

    assert default_path.exists()
    lines = default_path.read_text(encoding="utf-8").splitlines()
    assert lines
    event = json.loads(lines[-1])
    assert event["event"] == "health_check"
    assert event["status"] == "ok"
    assert event["path"] == "/health"


def test_tools_endpoint_empty_when_no_db(tmp_path: Path):
    """Test /tools returns empty list when no database exists."""
    client = TestClient(app)

    # Use non-existent DB path
    fake_db = tmp_path / "nonexistent.db"
    response = client.get(f"/tools?db_path={fake_db}")

    assert response.status_code == 200
    assert response.json() == []


def test_tools_endpoint_returns_active_tools(tmp_path: Path):
    """Test /tools returns tools from active allowlist."""
    import json

    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)

    # Create server and allowlist entry
    server_id = upsert_server(db, "test", "http://test.com", "approved")

    tools = [{"name": "tool1", "args": {}}, {"name": "tool2", "args": {}}]
    db["allowlist"].insert(
        {
            "server_id": server_id,
            "tools_exposed": json.dumps(tools),
            "tools_manifest_hash": registry.compute_tools_manifest_hash(tools),
            "status": "active",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )
    _insert_scan_result(db, server_id, status="pass")

    client = TestClient(app)
    response = client.get(f"/tools?db_path={db_file}")

    assert response.status_code == 200
    result = response.json()
    assert len(result) == 2
    assert {"name": "tool1", "args": {}} in result
    assert {"name": "tool2", "args": {}} in result


def test_mcp_tools_list_and_describe(tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "test", "http://test.com", "approved")
    _insert_allowlist(db, server_id, [{"name": "tool1", "args": {}}])
    _insert_scan_result(db, server_id, status="pass")

    client = TestClient(app)
    list_resp = client.post(
        f"/mcp?db_path={db_file}",
        json={"jsonrpc": "2.0", "id": "1", "method": "tools/list", "params": {}},
    )
    assert list_resp.status_code == 200
    list_body = list_resp.json()
    assert list_body["result"][0]["name"] == "tool1"
    assert list_body["result"][0]["server_id"] == server_id

    describe_resp = client.post(
        f"/mcp?db_path={db_file}",
        json={
            "jsonrpc": "2.0",
            "id": "2",
            "method": "tools/describe",
            "params": {"names": ["tool1"]},
        },
    )
    assert describe_resp.status_code == 200
    describe_body = describe_resp.json()
    assert describe_body["result"][0]["name"] == "tool1"
    assert describe_body["result"][0]["server_id"] == server_id


def test_tools_endpoint_denies_unpinned_manifest(tmp_path: Path):
    """tools_manifest_hash が未設定なら /tools は空配列を返す。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "test", "http://test.com", "approved")
    tools = [{"name": "tool1", "args": {}}]
    _insert_allowlist(db, server_id, tools, tools_manifest_hash="")

    client = TestClient(app)
    response = client.get(f"/tools?db_path={db_file}")

    assert response.status_code == 200
    assert response.json() == []

    evidence_path = tmp_path / "ci_evidence.jsonl"
    events = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
    ]
    guard_events = [
        event for event in events if event.get("event") == "tool_manifest_guard"
    ]
    assert guard_events
    event = guard_events[-1]
    assert event["decision"] == "deny"
    assert event["reason"] == "uninitialized"
    assert event["server_id"] == server_id
    assert event["expected_hash"] == ""
    assert event["observed_hash"] == registry.compute_tools_manifest_hash(tools)
    assert event["tool_count"] == 1


def test_mcp_tools_call_proxies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])
    _insert_scan_result(db, server_id, status="pass")

    called: dict = {}

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            called["url"] = url
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"echo": json})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/mcp?db_path={db_file}",
        json={
            "jsonrpc": "2.0",
            "id": "3",
            "method": "tools/call",
            "params": {
                "server_id": server_id,
                "name": "echo",
                "arguments": {"foo": "bar"},
            },
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["status"] == "ok"
    assert body["result"]["result"]["echo"]["arguments"] == {"foo": "bar"}
    assert called["url"] == "http://backend/run"


def test_rate_limit_exceeded(monkeypatch: pytest.MonkeyPatch):
    """一定回数を超えると 429 になる。"""
    reset_rate_limit()
    enable_rate_limit()
    import src.mcp_gateway.gateway as gateway_mod

    monkeypatch.setattr(gateway_mod, "RATE_LIMIT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(gateway_mod.evidence, "append", lambda *args, **kwargs: None)
    client = TestClient(app)
    for _ in range(RATE_LIMIT_BURST):
        assert client.get("/health").status_code == 200
    resp = client.get("/health")
    assert resp.status_code == 429


def test_response_size_cap_blocks():
    """レスポンスサイズが上限超過で 413 となる。"""
    reset_rate_limit()
    client = TestClient(app)
    resp = client.get("/_large_test")
    assert resp.status_code == 413


def test_request_timeout_returns_504():
    """長時間処理で 504 を返す。"""
    reset_rate_limit()
    client = TestClient(app)
    resp = client.get("/_slow_test")
    assert resp.status_code == 504


def test_tools_sanitization(tmp_path: Path):
    """tool name/description がサニタイズされる。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "test", "http://test.com", "approved")
    tools = [{"name": "<b>tool\x01</b>", "description": "desc<script>bad</script>"}]
    _insert_allowlist(db, server_id, tools)
    _insert_scan_result(db, server_id, status="pass")
    client = TestClient(app)
    resp = client.get(f"/tools?db_path={db_file}")
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["name"] == "tool"
    assert body[0]["description"] == "descbad"


def test_gateway_update_snapshot_written(tmp_path: Path):
    """gateway_update がスナップショットと sha を残す。"""
    gateway.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    gateway.DIFF_DIR.mkdir(parents=True, exist_ok=True)
    # クリーンな状態
    for f in gateway.SNAPSHOT_DIR.glob("gateway_config_*.json"):
        f.unlink()
    for f in gateway.DIFF_DIR.glob("gateway_diff_*.json"):
        f.unlink()

    import hashlib
    import json

    from src.mcp_gateway.gateway import _emit_gateway_update

    evidence_path = tmp_path / "ci_evidence.jsonl"
    _emit_gateway_update(evidence_path=evidence_path)
    files = sorted(gateway.SNAPSHOT_DIR.glob("gateway_config_*.json"))
    assert len(files) == 1
    content = files[0].read_text(encoding="utf-8")
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    # Evidenceファイルにイベントが書かれていることを確認
    events = evidence_path.read_text(encoding="utf-8").splitlines()
    gw_updates = [
        json.loads(e) for e in events if json.loads(e).get("event") == "gateway_update"
    ]
    assert gw_updates
    assert gw_updates[-1]["snapshot_sha"] == sha
    assert gw_updates[-1]["config"]["sanitization_enabled"] is True
    # 2回目を実行し、diff が生成されることを確認
    _emit_gateway_update(evidence_path=evidence_path)
    events2 = evidence_path.read_text(encoding="utf-8").splitlines()
    gw_updates2 = [
        json.loads(e) for e in events2 if json.loads(e).get("event") == "gateway_update"
    ]
    last = gw_updates2[-1]
    if last.get("diff_path"):
        assert Path(last["diff_path"]).exists()
        assert last.get("diff_sha")


def _insert_allowlist(
    db,
    server_id: int,
    tools: list[dict],
    *,
    risk_level: str | None = None,
    capabilities=None,
    tools_manifest_hash: str | None = None,
) -> None:
    import json

    if capabilities is None:
        capabilities = []
    if tools_manifest_hash is None:
        tools_manifest_hash = registry.compute_tools_manifest_hash(
            [t for t in tools if isinstance(t, dict)]
        )

    db["allowlist"].insert(
        {
            "server_id": server_id,
            "tools_exposed": json.dumps(tools),
            "risk_level": risk_level or "medium",
            "capabilities": json.dumps(capabilities),
            "tools_manifest_hash": tools_manifest_hash,
            "status": "active",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )


def _insert_scan_result(
    db,
    server_id: int,
    *,
    status: str,
    scan_types: tuple[str, ...] = ("static", "mcpsafety"),
    started_at: str | None = None,
    ended_at: str | None = None,
) -> None:
    from datetime import datetime, timezone

    if ended_at is None:
        ended_at = datetime.now(timezone.utc).isoformat()
    if started_at is None:
        started_at = ended_at
    for scan_type in scan_types:
        db["scan_results"].insert(
            {
                "server_id": server_id,
                "run_id": "scan-run",
                "scan_type": scan_type,
                "status": status,
                "findings": "[]",
                "started_at": started_at,
                "ended_at": ended_at,
            }
        )


def _insert_council_evaluation(db, server_id: int, *, decision: str) -> None:
    db["council_evaluations"].insert(
        {
            "server_id": server_id,
            "run_id": "council-run",
            "scores": json.dumps({"security": 0}),
            "decision": decision,
            "rationale": "",
            "created_at": "2025-01-03T00:00:00Z",
        }
    )


def test_run_proxies_allowed_tool(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """AllowList 登録済み tool だけを背後に転送する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])
    _insert_scan_result(db, server_id, status="pass")

    called: dict = {}

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            called["url"] = url
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"echo": json})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {"foo": "bar"}},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["result"]["echo"]["arguments"] == {"foo": "bar"}
    assert body["source_tag"] == "trusted"
    assert resp.headers.get("X-MCP-Source-Tag") == "trusted"
    assert called["url"] == "http://backend/run"


def test_run_denies_manifest_drift(tmp_path: Path):
    """tools_manifest_hash の drift は /run を deny する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    tools = [{"name": "echo"}]
    _insert_allowlist(db, server_id, tools, tools_manifest_hash="0" * 64)

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"

    evidence_path = tmp_path / "ci_evidence.jsonl"
    events = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
    ]
    guard_events = [
        event for event in events if event.get("event") == "tool_manifest_guard"
    ]
    assert guard_events
    event = guard_events[-1]
    assert event["decision"] == "deny"
    assert event["reason"] == "drift"
    assert event["server_id"] == server_id
    assert event["expected_hash"] == "0" * 64
    assert event["observed_hash"] == registry.compute_tools_manifest_hash(tools)
    assert event["tool_count"] == 1


def test_run_proxies_mcp_streamable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """MCP streamable-http (JSON-RPC) へ tools/call を委譲する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend/mcp", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])
    _insert_scan_result(db, server_id, status="pass")

    called: dict = {}

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            called["url"] = url
            called["json"] = json
            return type(
                "Resp",
                (),
                {
                    "status_code": 200,
                    "json": staticmethod(
                        lambda: {
                            "jsonrpc": "2.0",
                            "id": json["id"],
                            "result": {"ok": True},
                        }
                    ),
                },
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {"foo": "bar"}},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["result"] == {"ok": True}
    assert called["url"] == "http://backend/mcp"
    assert called["json"]["method"] == "tools/call"
    assert called["json"]["params"] == {"name": "echo", "arguments": {"foo": "bar"}}


def test_run_source_tag_reflects_scan_fail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])
    _insert_scan_result(db, server_id, status="fail")

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert body["error"] == "untrusted source"
    assert any("scan_status:fail" in r for r in body["source_reasons"])


def test_run_source_tag_reflects_scan_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert body["error"] == "untrusted source"
    assert any("scan_missing" in r for r in body["source_reasons"])


def test_run_source_tag_reflects_scan_stale(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])
    _insert_scan_result(db, server_id, status="pass", ended_at="2000-01-01T00:00:00Z")

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert body["error"] == "untrusted source"
    assert any("scan_stale" in r for r in body["source_reasons"])


def test_run_source_tag_reflects_council_deny(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])
    _insert_council_evaluation(db, server_id, decision="deny")

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert body["error"] == "untrusted source"
    assert any("council_decision:deny" in r for r in body["source_reasons"])


@pytest.mark.parametrize(
    "payload,expected_status",
    [
        ({"server_id": 1, "tool_name": "unknown", "arguments": {}}, 403),
        ({"server_id": 999, "tool_name": "echo", "arguments": {}}, 404),
    ],
)
def test_run_rejects_invalid(tmp_path: Path, payload: dict, expected_status: int):
    """AllowList 不整合やサーバ不在は拒否する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}])

    client = TestClient(app)
    resp = client.post(f"/run?db_path={db_file}", json=payload)

    assert resp.status_code == expected_status


def test_run_blocks_high_risk(tmp_path: Path):
    """risk_level=high はデフォルトで拒否する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "echo"}], risk_level="high")

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert body["error"] == "tool blocked by policy"
    assert body["risk_level"] == "high"


def test_run_blocks_blocked_capabilities(tmp_path: Path):
    """capabilities に network_write が含まれる場合は拒否する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "echo"}],
        capabilities=["network_write"],
    )

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "echo", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert body["error"] == "tool blocked by policy"
    assert "network_write" in body.get("capabilities", [])


def test_run_blocks_untrusted_to_restricted_sink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """untrusted SOURCE で restricted sink を持つツールは拒否する。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "nettool", "arguments": {}},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"
    assert "untrusted" in body["error"]


def test_run_allows_untrusted_with_approval(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """環境許可と approvals_row_id があれば untrusted→restricted を許可し Evidence に記録。"""
    monkeypatch.setenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "1")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )
    # approvals ledger を差し替え
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "\n".join(
            [
                "| id | task_id | scope | op | status | requested_by | approver | approver_role | ts_req | ts_dec | manual_verification | signed_by | expiry_utc | evidence | server_id | tool_name | capabilities |",
                "|----|---------|-------|----|--------|--------------|----------|---------------|--------|--------|---------------------|-----------|------------|----------|-----------|-----------|--------------|",
                f"| APP-123 | T1 | scope | Apply | approved | requester | approver | OWNER | 2025-12-17T00:00:00Z | 2025-12-17T00:05:00Z | YES | user | 2099-12-31T23:59:59Z | commit:abc | {server_id} | nettool | network_write |",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "rules").mkdir()
    rules_path = tmp_path / "rules" / "APPROVALS.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "version: 1",
                f'ledger: "{approvals_path}"',
                "two_person_rule: true",
                "forbid_self_approval: true",
                "required_fields:",
                "  - id",
                "  - status",
                "  - requested_by",
                "  - approver",
                "  - expiry_utc",
                "  - server_id",
                "  - tool_name",
                "  - capabilities",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.mcp_gateway.gateway.APPROVALS_RULES_PATH", rules_path)

    called: dict = {}

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            called["url"] = url
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={
            "server_id": server_id,
            "tool_name": "nettool",
            "arguments": {},
            "approvals_row_id": "APP-123",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["source_tag"] == "untrusted"
    assert resp.headers.get("X-MCP-Source-Tag") == "untrusted"
    assert "source_reasons" in body
    assert called["url"] == "http://backend/run"

    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records[-1]["event"] == "source_sink_check"
    assert records[-1]["decision"] == "allow_with_approval"
    assert records[-1]["approvals_row_id"] == "APP-123"


def test_run_uses_policy_profile_db_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """db_path の policy profile を untrusted→restricted 判定に使う。"""
    monkeypatch.delenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", raising=False)
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    gateway._ensure_control_tables(db)
    db[gateway.CONTROL_POLICY_PROFILE_TABLE].insert(
        {
            "profile_name": "development",
            "restricted_sinks_additions": "[]",
            "allow_untrusted_with_approvals": 1,
            "change_reason": "test",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "\n".join(
            [
                "| id | task_id | scope | op | status | requested_by | approver | approver_role | ts_req | ts_dec | manual_verification | signed_by | expiry_utc | evidence | server_id | tool_name | capabilities |",
                "|----|---------|-------|----|--------|--------------|----------|---------------|--------|--------|---------------------|-----------|------------|----------|-----------|-----------|--------------|",
                f"| APP-123 | T1 | scope | Apply | approved | requester | approver | OWNER | 2025-12-17T00:00:00Z | 2025-12-17T00:05:00Z | YES | user | 2099-12-31T23:59:59Z | commit:abc | {server_id} | nettool | network_write |",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "rules").mkdir()
    rules_path = tmp_path / "rules" / "APPROVALS.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "version: 1",
                f'ledger: "{approvals_path}"',
                "two_person_rule: true",
                "forbid_self_approval: true",
                "required_fields:",
                "  - id",
                "  - status",
                "  - requested_by",
                "  - approver",
                "  - expiry_utc",
                "  - server_id",
                "  - tool_name",
                "  - capabilities",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.mcp_gateway.gateway.APPROVALS_RULES_PATH", rules_path)

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={
            "server_id": server_id,
            "tool_name": "nettool",
            "arguments": {},
            "approvals_row_id": "APP-123",
        },
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_run_rejects_expired_approval(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "1")
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "\n".join(
            [
                "| id | task_id | scope | op | status | requested_by | approver | approver_role | ts_req | ts_dec | manual_verification | signed_by | expiry_utc | evidence | server_id | tool_name | capabilities |",
                "|----|---------|-------|----|--------|--------------|----------|---------------|--------|--------|---------------------|-----------|------------|----------|-----------|-----------|--------------|",
                f"| APP-999 | T1 | scope | Apply | approved | requester | approver | OWNER | 2025-12-17T00:00:00Z | 2025-12-17T00:05:00Z | YES | user | 2000-01-01T00:00:00Z | commit:abc | {server_id} | nettool | network_write |",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "rules").mkdir()
    rules_path = tmp_path / "rules" / "APPROVALS.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "version: 1",
                f'ledger: "{approvals_path}"',
                "two_person_rule: true",
                "forbid_self_approval: true",
                "required_fields:",
                "  - id",
                "  - status",
                "  - requested_by",
                "  - approver",
                "  - expiry_utc",
                "  - server_id",
                "  - tool_name",
                "  - capabilities",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.mcp_gateway.gateway.APPROVALS_RULES_PATH", rules_path)

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={
            "server_id": server_id,
            "tool_name": "nettool",
            "arguments": {},
            "approvals_row_id": "APP-999",
        },
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"


def test_run_rejects_partial_approval_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "1")
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "\n".join(
            [
                "| id | task_id | scope | op | status | requested_by | approver | approver_role | ts_req | ts_dec | manual_verification | signed_by | expiry_utc | evidence | server_id | tool_name | capabilities |",
                "|----|---------|-------|----|--------|--------------|----------|---------------|--------|--------|---------------------|-----------|------------|----------|-----------|-----------|--------------|",
                f"| APP-123 | T1 | scope | Apply | approved | requester | approver | OWNER | 2025-12-17T00:00:00Z | 2025-12-17T00:05:00Z | YES | user | 2099-12-31T23:59:59Z | commit:abc | {server_id} | nettool | network_write |",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "rules").mkdir()
    rules_path = tmp_path / "rules" / "APPROVALS.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "version: 1",
                f'ledger: "{approvals_path}"',
                "two_person_rule: true",
                "forbid_self_approval: true",
                "required_fields:",
                "  - id",
                "  - status",
                "  - requested_by",
                "  - approver",
                "  - expiry_utc",
                "  - server_id",
                "  - tool_name",
                "  - capabilities",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.mcp_gateway.gateway.APPROVALS_RULES_PATH", rules_path)

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={
            "server_id": server_id,
            "tool_name": "nettool",
            "arguments": {},
            "approvals_row_id": "APP-12",
        },
    )

    assert resp.status_code == 403
    body = resp.json()
    assert body["status"] == "forbidden"


def test_run_rejects_self_approval(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "1")
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(tmp_path / "evidence.jsonl"))

    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "\n".join(
            [
                "| id | task_id | scope | op | status | requested_by | approver | approver_role | ts_req | ts_dec | manual_verification | signed_by | expiry_utc | evidence | server_id | tool_name | capabilities |",
                "|----|---------|-------|----|--------|--------------|----------|---------------|--------|--------|---------------------|-----------|------------|----------|-----------|-----------|--------------|",
                f"| APP-777 | T1 | scope | Apply | approved | same | same | OWNER | 2025-12-17T00:00:00Z | 2025-12-17T00:05:00Z | YES | user | 2099-12-31T23:59:59Z | commit:abc | {server_id} | nettool | network_write |",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "rules").mkdir()
    rules_path = tmp_path / "rules" / "APPROVALS.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "version: 1",
                f'ledger: "{approvals_path}"',
                "two_person_rule: true",
                "forbid_self_approval: true",
                "required_fields:",
                "  - id",
                "  - status",
                "  - requested_by",
                "  - approver",
                "  - expiry_utc",
                "  - server_id",
                "  - tool_name",
                "  - capabilities",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.mcp_gateway.gateway.APPROVALS_RULES_PATH", rules_path)

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={
            "server_id": server_id,
            "tool_name": "nettool",
            "arguments": {},
            "approvals_row_id": "APP-777",
        },
    )

    assert resp.status_code == 403
    assert resp.json()["status"] == "forbidden"


def test_run_rejects_missing_required_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "1")
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "nettool", "capabilities": ["network_write"]}],
        capabilities=["sampling"],
    )
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "\n".join(
            [
                "| id | status | requested_by | approver | expiry_utc | server_id | tool_name | capabilities |",
                "|----|--------|--------------|----------|-----------|-----------|-----------|--------------|",
                f"| APP-555 | approved | requester | approver | 2099-12-31T23:59:59Z | {server_id} | nettool | network_write |",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "src.mcp_gateway.gateway.APPROVALS_RULES_PATH",
        tmp_path / "rules" / "APPROVALS.yaml",
    )
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "APPROVALS.yaml").write_text(
        "\n".join(
            [
                "version: 1",
                f'ledger: "{approvals_path}"',
                "two_person_rule: true",
                "forbid_self_approval: true",
                "required_fields:",
                "  - id",
                "  - status",
                "  - requested_by",
                "  - approver",
                "  - expiry_utc",
                "  - task_id",
                "  - server_id",
                "  - tool_name",
                "  - capabilities",
            ]
        ),
        encoding="utf-8",
    )

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {"status_code": 200, "json": staticmethod(lambda: {"ok": True})},
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={
            "server_id": server_id,
            "tool_name": "nettool",
            "arguments": {},
            "approvals_row_id": "APP-555",
        },
    )

    assert resp.status_code == 403
    assert resp.json()["status"] == "forbidden"


def test_run_emits_dlp_detect(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    approvals_path = tmp_path / "APPROVALS.md"
    approvals_path.write_text(
        "| id | status |\n| APP-123 | approved |\n", encoding="utf-8"
    )
    monkeypatch.setattr("src.mcp_gateway.gateway.APPROVALS_LEDGER", approvals_path)

    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "nettool"}])
    _insert_scan_result(db, server_id, status="pass")

    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {
                    "status_code": 200,
                    "json": staticmethod(
                        lambda: {
                            "ok": True,
                            "payload": "contact admin@example.com for help",
                        }
                    ),
                },
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "nettool", "arguments": {}},
    )

    assert resp.status_code == 200
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        rec.get("event") == "dlp_detected" and "email" in rec.get("findings", [])
        for rec in records
    )


def test_run_blocks_on_dlp_deny_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv", "http://backend", "approved")
    _insert_allowlist(db, server_id, [{"name": "nettool"}])
    _insert_scan_result(db, server_id, status="pass")

    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    monkeypatch.setenv("MCP_GATEWAY_DLP_MODE", "deny")

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict):
            return type(
                "Resp",
                (),
                {
                    "status_code": 200,
                    "json": staticmethod(
                        lambda: {"ok": True, "payload": "email admin@example.com"}
                    ),
                },
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        f"/run?db_path={db_file}",
        json={"server_id": server_id, "tool_name": "nettool", "arguments": {}},
    )

    assert resp.status_code == 403
    assert resp.json()["status"] == "forbidden"
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        rec.get("event") == "dlp_detected" and rec.get("decision") == "deny"
        for rec in records
    )


def test_tools_endpoint_skips_blocked_entries(tmp_path: Path):
    """ブロック対象は /tools に出さない。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id_1 = upsert_server(db, "srv1", "http://backend1", "approved")
    server_id_2 = upsert_server(db, "srv2", "http://backend2", "approved")
    _insert_allowlist(db, server_id_1, [{"name": "safe"}])
    _insert_scan_result(db, server_id_1, status="pass")
    _insert_allowlist(
        db,
        server_id_2,
        [{"name": "blocked"}],
        risk_level="critical",
        capabilities=["network_write"],
    )
    _insert_scan_result(db, server_id_2, status="pass")

    client = TestClient(app)
    resp = client.get(f"/tools?db_path={db_file}")
    assert resp.status_code == 200
    tool_names = {t["name"] for t in resp.json()}
    assert "safe" in tool_names
    assert "blocked" not in tool_names


def test_allowlist_api_includes_source_info(tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}], risk_level="critical")

    client = TestClient(app)
    resp = client.get(f"/api/allowlist?db_path={db_file}")
    assert resp.status_code == 200
    data = resp.json()
    assert data[0]["source_tag"] == "untrusted"
    assert any("risk_level:critical" in r for r in data[0]["source_reasons"])

    resp = client.get(f"/api/allowlist/{server_id}?db_path={db_file}")
    assert resp.status_code == 200
    entry = resp.json()
    assert entry["source_tag"] == "untrusted"


def test_mcp_detail_includes_source_info(tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(
        db,
        server_id,
        [{"name": "safe"}],
        capabilities=["sampling"],
    )

    client = TestClient(app)
    resp = client.get(f"/api/mcp/{server_id}?db_path={db_file}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["allowlist"]["source_tag"] == "untrusted"


def test_mcp_list_includes_last_decision_ts(tmp_path: Path):
    """GET /api/mcp がlast_scan_ts/last_decision_tsを含むことを確認（P1-1）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])
    db["scan_results"].insert({
        "server_id": server_id,
        "run_id": "scan-1",
        "scan_type": "static",
        "status": "pass",
        "findings": "[]",
        "started_at": "2025-01-04T00:00:00Z",
        "ended_at": "2025-01-04T00:00:00Z",
    })
    db["council_evaluations"].insert({
        "server_id": server_id,
        "run_id": "council-1",
        "scores": json.dumps({"security": 0}),
        "decision": "quarantine",
        "rationale": "policy",
        "created_at": "2025-01-05T00:00:00Z",
    })

    client = TestClient(app)
    resp = client.get(f"/api/mcp?db_path={db_file}")
    assert resp.status_code == 200
    items = resp.json()
    item = next(i for i in items if i["server_id"] == server_id)
    assert item["last_scan_ts"] == "2025-01-04T00:00:00Z"
    assert item["last_decision_ts"] == "2025-01-05T00:00:00Z"
    assert item["status"] == "quarantine"


def test_mcp_detail_includes_council_evidence_and_severity_counts(tmp_path: Path):
    """GET /api/mcp/{id}がcouncil/evidence/severity_countsを含むことを確認（P1-2）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])
    findings = [
        {"severity": "high"},
        {"severity": "low"},
        {"severity": "high"},
    ]
    registry.save_scan_result(
        db=db,
        server_id=server_id,
        run_id="scan-1",
        scan_type="static",
        status="warn",
        findings=findings,
    )
    db["council_evaluations"].insert({
        "server_id": server_id,
        "run_id": "council-1",
        "scores": json.dumps({"security": 1}),
        "decision": "deny",
        "rationale": "test rationale",
        "created_at": "2025-01-06T00:00:00Z",
    })

    client = TestClient(app)
    resp = client.get(f"/api/mcp/{server_id}?db_path={db_file}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["scan"]["severity_counts"]["high"] == 2
    assert detail["scan"]["severity_counts"]["low"] == 1
    assert detail["council"]["decision"] == "deny"
    assert detail["council"]["rationale"] == "test rationale"
    assert detail["council"]["run_id"] == "council-1"
    assert detail["council"]["ts"] == "2025-01-06T00:00:00Z"
    assert detail["evidence"]["scan_run_id"] == "scan-1"
    assert detail["evidence"]["council_run_id"] == "council-1"


# --- P1-3: History API Tests ---


def test_mcp_history_returns_scan_and_council(tmp_path: Path):
    """GET /api/mcp/{id}/history がscan/council履歴を統合返却することを確認（P1-3）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])

    # Insert multiple scan results
    db["scan_results"].insert({
        "server_id": server_id,
        "run_id": "scan-1",
        "scan_type": "static",
        "status": "pass",
        "findings": json.dumps([{"severity": "high"}]),
        "started_at": "2025-01-01T00:00:00Z",
        "ended_at": "2025-01-01T00:00:00Z",
    })
    db["scan_results"].insert({
        "server_id": server_id,
        "run_id": "scan-2",
        "scan_type": "mcpsafety",
        "status": "warn",
        "findings": json.dumps([{"severity": "medium"}, {"severity": "low"}]),
        "started_at": "2025-01-02T00:00:00Z",
        "ended_at": "2025-01-02T00:00:00Z",
    })

    # Insert council evaluation
    db["council_evaluations"].insert({
        "server_id": server_id,
        "run_id": "council-1",
        "scores": json.dumps({"security": 0.5}),
        "decision": "quarantine",
        "rationale": "needs review",
        "created_at": "2025-01-03T00:00:00Z",
    })

    client = TestClient(app)

    # All types
    resp = client.get(f"/api/mcp/{server_id}/history?db_path={db_file}")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 3
    # Sorted by created_at desc
    assert data["items"][0]["type"] == "council"
    assert data["items"][0]["ref_id"] == "council-1"
    assert data["items"][1]["type"] == "scan"
    assert data["items"][2]["type"] == "scan"

    # Scan only
    resp = client.get(f"/api/mcp/{server_id}/history?db_path={db_file}&type=scan")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert all(i["type"] == "scan" for i in data["items"])

    # Council only
    resp = client.get(f"/api/mcp/{server_id}/history?db_path={db_file}&type=council")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["type"] == "council"

    # Severity counts in scan items
    scan_item = next(i for i in resp.json()["items"] if i["type"] == "council")
    assert scan_item["severity"]["critical"] == 0


def test_mcp_history_pagination(tmp_path: Path):
    """GET /api/mcp/{id}/history のページネーション確認（P1-3）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])

    # Insert 5 scan results
    for i in range(5):
        db["scan_results"].insert({
            "server_id": server_id,
            "run_id": f"scan-{i}",
            "scan_type": "static",
            "status": "pass",
            "findings": "[]",
            "started_at": f"2025-01-0{i+1}T00:00:00Z",
            "ended_at": f"2025-01-0{i+1}T00:00:00Z",
        })

    client = TestClient(app)

    # Limit 2, offset 0
    resp = client.get(f"/api/mcp/{server_id}/history?db_path={db_file}&limit=2&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["next_offset"] == 2

    # Limit 2, offset 4
    resp = client.get(f"/api/mcp/{server_id}/history?db_path={db_file}&limit=2&offset=4")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["next_offset"] is None


def test_mcp_history_not_found(tmp_path: Path):
    """GET /api/mcp/{id}/history が存在しないサーバで404を返すことを確認（P1-3）。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)

    client = TestClient(app)
    resp = client.get(f"/api/mcp/99999/history?db_path={db_file}")
    assert resp.status_code == 404


# --- P1-4: Council Run API Tests ---


def test_mcp_council_run_requires_auth(tmp_path: Path):
    """POST /api/mcp/{id}/council が認証を要求することを確認（P1-4）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])

    client = TestClient(app)
    resp = client.post(
        f"/api/mcp/{server_id}/council?db_path={db_file}",
        json={"question": "test", "mode": ""},
    )
    # 認証なしは401または503
    assert resp.status_code in (401, 503)


def test_mcp_council_run_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """POST /api/mcp/{id}/council が正常動作することを確認（P1-4）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])
    # Scan results are required for council
    registry.save_scan_result(
        db=db,
        server_id=server_id,
        run_id="scan-1",
        scan_type="static",
        status="pass",
        findings=[],
    )

    client = TestClient(app)
    resp = client.post(
        f"/api/mcp/{server_id}/council?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={"question": "is it safe?", "mode": "quick"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert "run_id" in data
    assert "decision" in data
    assert data["artifacts_ref"].startswith("artifacts/council/")

    # Evidence確認
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    council_events = [r for r in records if r.get("event") == "council_run"]
    assert len(council_events) >= 1
    assert council_events[-1]["server_id"] == server_id


def test_mcp_council_run_no_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """POST /api/mcp/{id}/council がscan未実行で400を返すことを確認（P1-4）。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")

    server_id = upsert_server(db, "srv1", "http://backend1", "approved")
    _insert_allowlist(db, server_id, [{"name": "safe"}])
    # No scan results

    client = TestClient(app)
    resp = client.post(
        f"/api/mcp/{server_id}/council?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={},
    )
    assert resp.status_code == 400
    assert "scan" in resp.json()["detail"].lower()


# --- P1-5: MCP Server Registration API Tests ---


def test_mcp_register_requires_auth(tmp_path: Path):
    """POST /api/mcp が認証を要求することを確認（P1-5）。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)

    client = TestClient(app)
    resp = client.post(
        f"/api/mcp?db_path={db_file}",
        json={
            "name": "test-server",
            "server_url": "https://example.com",
            "origin_url": "https://github.com/test/repo",
            "origin_sha": "abc1234",
        },
    )
    assert resp.status_code in (401, 503)


def test_mcp_register_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """POST /api/mcp が正常動作することを確認（P1-5）。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    client = TestClient(app)
    resp = client.post(
        f"/api/mcp?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "name": "test-server",
            "server_url": "https://example.com/mcp",
            "origin_url": "https://github.com/test/repo",
            "origin_sha": "abc1234def5678",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "server_id" in data
    assert data["status"] == "created"

    # 2回目はupdated
    resp2 = client.post(
        f"/api/mcp?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "name": "test-server",
            "server_url": "https://example2.com/mcp",
            "origin_url": "https://github.com/test/repo",
            "origin_sha": "def7890abc1234",
        },
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "updated"

    # Evidence確認
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    reg_events = [r for r in records if r.get("event") == "mcp_server_registered"]
    assert len(reg_events) >= 2


def test_mcp_register_validates_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """POST /api/mcp がURL検証することを確認（P1-5 SSRF対策）。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")

    client = TestClient(app)

    # Invalid server_url
    resp = client.post(
        f"/api/mcp?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "name": "test",
            "server_url": "not-a-url",
            "origin_url": "https://github.com/test/repo",
            "origin_sha": "abc1234",
        },
    )
    assert resp.status_code == 400
    assert "server_url" in resp.json()["detail"]

    # Invalid origin_sha (not hex)
    resp = client.post(
        f"/api/mcp?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "name": "test",
            "server_url": "https://example.com",
            "origin_url": "https://github.com/test/repo",
            "origin_sha": "not-hex!",
        },
    )
    assert resp.status_code == 400
    assert "origin_sha" in resp.json()["detail"]

    # origin_sha too short
    resp = client.post(
        f"/api/mcp?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "name": "test",
            "server_url": "https://example.com",
            "origin_url": "https://github.com/test/repo",
            "origin_sha": "abc",
        },
    )
    assert resp.status_code == 400
    assert "origin_sha" in resp.json()["detail"]


# --- Step7 UI/Scan API Tests ---


def test_post_scans_rejects_unregistered_server(tmp_path: Path):
    """POST /api/scans が未登録server_idを拒否（SSRF対策）。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)

    client = TestClient(app)
    resp = client.post(
        f"/api/scans?db_path={db_file}",
        json={"server_id": 99999, "profile": "quick"},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_post_scans_triggers_scan_with_ui_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """POST /api/scans がスキャンを実行し、actor/trigger_source=uiをEvidenceに記録。"""
    db_file = tmp_path / "test.db"
    evidence_file = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_file))
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "test_server", "http://localhost:9999", "draft")

    client = TestClient(app)
    resp = client.post(
        f"/api/scans?db_path={db_file}",
        json={"server_id": server_id, "profile": "quick"},
    )
    assert resp.status_code == 200
    result = resp.json()
    assert result["status"] == "success"
    assert "run_id" in result

    # Check Evidence (UI-triggered scan status matches summary)
    if evidence_file.exists():
        lines = evidence_file.read_text().strip().split("\n")
        ui_events = [
            json.loads(line)
            for line in lines
            if line.strip()
            and json.loads(line).get("actor") == "ui"
            and json.loads(line).get("event") == "mcp_scan_run"
        ]
        assert len(ui_events) > 0
        assert any(e.get("trigger_source") == "ui" for e in ui_events)

        detail = client.get(f"/api/scans/{result['run_id']}?db_path={db_file}")
        assert detail.status_code == 200
        summary_status = detail.json()["scan"]["status"]
        assert summary_status
        assert summary_status == "fail"

        ui_event = ui_events[-1]
        assert ui_event.get("status") == summary_status


def test_get_report_json_includes_audit_fields(tmp_path: Path):
    """GET /api/scans/{run_id}/report.json が監査資料レベルの情報を含む。"""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "test_server", "http://localhost:9999", "draft")

    # Insert scan result
    run_id = "test_run_123"
    registry.save_scan_result(
        db,
        server_id=server_id,
        run_id=run_id,
        scan_type="static",
        status="pass",
        findings=[{"code": "test", "severity": "low", "message": "test finding"}],
    )

    client = TestClient(app)
    resp = client.get(f"/api/scans/{run_id}/report.json?db_path={db_file}")
    assert resp.status_code == 200
    report = resp.json()

    # Check audit-level fields
    assert "report_metadata" in report
    assert report["report_metadata"]["tool_name"] == "MCP Gateway"
    assert report["report_metadata"]["run_id"] == run_id
    assert "summary" in report
    assert "findings" in report
    assert "recommendations" in report


def test_get_report_pdf_generates_pdf(tmp_path: Path):
    """GET /api/scans/{run_id}/report.pdf がPDFを生成（シークレット除外）。"""
    try:
        import reportlab  # noqa: F401
    except ImportError:
        pytest.skip("reportlab not installed")

    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = upsert_server(db, "test_server", "http://localhost:9999", "draft")

    run_id = "test_run_pdf"
    registry.save_scan_result(
        db,
        server_id=server_id,
        run_id=run_id,
        scan_type="static",
        status="pass",
        findings=[{"code": "test", "severity": "low", "message": "test finding"}],
    )

    client = TestClient(app)
    resp = client.get(f"/api/scans/{run_id}/report.pdf?db_path={db_file}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert len(resp.content) > 100  # PDF header/minimal size check


def test_settings_environments_crud(tmp_path: Path):
    """Settings環境CRUD: 保存→取得で has_secret=True, シークレット自体は返却されない。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)

    client = TestClient(app)

    # Create
    resp = client.post(
        f"/api/settings/environments?db_path={db_file}",
        json={
            "name": "prod",
            "endpoint_url": "http://prod.example.com",
            "status": "active",
            "memo": "Production",
            "secret": "secret123",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"

    # List
    resp = client.get(f"/api/settings/environments?db_path={db_file}")
    assert resp.status_code == 200
    envs = resp.json()
    assert len(envs) == 1
    assert envs[0]["name"] == "prod"
    assert envs[0]["has_secret"] is True
    assert "secret" not in envs[0]  # Secret not returned


def test_settings_profiles_crud(tmp_path: Path):
    """Settingsプロファイルcrud: 保存→取得。"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)

    client = TestClient(app)

    # Create
    resp = client.post(
        f"/api/settings/profiles?db_path={db_file}",
        json={
            "name": "full",
            "check_categories": ["static", "mcpsafety", "council"],
            "is_default": True,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"

    # List
    resp = client.get(f"/api/settings/profiles?db_path={db_file}")
    assert resp.status_code == 200
    profiles = resp.json()
    assert len(profiles) == 1
    assert profiles[0]["name"] == "full"
    assert profiles[0]["is_default"] is True
    assert "mcpsafety" in profiles[0]["check_categories"]


def test_control_session_exchange(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    client = TestClient(app)

    resp = client.post(
        "/api/control/session", headers={"Authorization": "Bearer admin-token"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert gateway.ADMIN_SESSION_COOKIE_NAME in resp.cookies

    resp = client.get(f"/api/control/upstream?db_path={db_file}")
    assert resp.status_code == 200

    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        json={
            "base_url": "http://upstream",
            "api_key": "secret",
            "provider": "test",
            "models_allowlist": ["model-a"],
        },
    )
    assert resp.status_code == 403

    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Origin": "http://testserver"},
        json={
            "base_url": "http://upstream",
            "api_key": "secret",
            "provider": "test",
            "models_allowlist": ["model-a"],
        },
    )
    assert resp.status_code == 200


def test_control_upstream_put_get(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "base_url": "http://upstream",
            "api_key": "secret",
            "provider": "test",
            "models_allowlist": ["model-a"],
        },
    )
    assert resp.status_code == 200

    data = client.get(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
    ).json()
    assert data["base_url"] == "http://upstream"
    assert data["api_key"] == "{REDACTED}"

    event = json.loads(evidence_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["trigger_source"] == "ui"


def test_infer_upstream_provider() -> None:
    assert (
        gateway._infer_upstream_provider(
            "https://generativelanguage.googleapis.com/v1beta", ""
        )
        == "gemini"
    )
    assert gateway._infer_upstream_provider("http://example", "OpenAI_Compatible") == (
        "openai_compatible"
    )
    assert gateway._infer_upstream_provider("http://example", "") == ""


def test_build_upstream_test_request() -> None:
    url, headers = gateway._build_upstream_test_request(
        "https://generativelanguage.googleapis.com/v1beta", "gemini", "k"
    )
    assert url.endswith("/v1beta/models?key=k")
    assert headers is None

    url2, headers2 = gateway._build_upstream_test_request(
        "https://generativelanguage.googleapis.com", "gemini", "k2"
    )
    assert url2.endswith("/v1beta/models?key=k2")
    assert headers2 is None

    url3, headers3 = gateway._build_upstream_test_request(
        "http://127.0.0.1:4000", "openai_compatible", ""
    )
    assert url3 == "http://127.0.0.1:4000/v1/models"
    assert headers3 is None

    url4, headers4 = gateway._build_upstream_test_request(
        "http://127.0.0.1:11434/v1", "openai_compatible", "tok"
    )
    assert url4 == "http://127.0.0.1:11434/v1/models"
    assert headers4 == {"Authorization": "Bearer tok"}


def test_control_upstream_test_emits_provider_and_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "ci_evidence.jsonl"
    client = TestClient(app)

    calls: list[tuple[str, dict | None]] = []

    class DummyAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url: str, headers: dict | None = None):
            calls.append((url, headers))
            request = httpx.Request("GET", url)
            return httpx.Response(200, request=request)

    monkeypatch.setattr(gateway.httpx, "AsyncClient", DummyAsyncClient)

    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "base_url": "https://generativelanguage.googleapis.com/v1beta",
            "api_key": "secret",
            "models_allowlist": ["models/gemini-flash-latest"],
        },
    )
    assert resp.status_code == 200

    resp = client.post(
        f"/api/control/upstream/test?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["provider"] == "gemini"
    assert calls
    assert calls[0][0].endswith("/v1beta/models?key=secret")
    assert calls[0][1] is None

    event = json.loads(evidence_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["event"] == "upstream_test"
    assert event["provider"] == "gemini"
    assert event["test_url"].endswith("/v1beta/models?key=REDACTED")


def test_control_diagnostics_redacts_upstream_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    client = TestClient(app)

    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "base_url": "http://upstream",
            "api_key": "secret",
            "provider": "openai_compatible",
            "models_allowlist": ["test-model"],
        },
    )
    assert resp.status_code == 200

    resp = client.post(
        f"/api/control/tokens?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={"env_id": 1, "expires_at": "2099-01-01T00:00:00Z", "note": "diag"},
    )
    assert resp.status_code == 200

    resp = client.get(
        f"/api/control/diagnostics?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["db_present"] is True
    assert data["upstream"]["configured"] is True
    assert data["upstream"]["base_url"] == "http://upstream"
    assert data["upstream"]["has_api_key"] is True
    assert "api_key" not in data["upstream"]
    assert data["tokens"]["total"] == 1
    assert data["tokens"]["by_status"]["active"] == 1


def test_control_policy_profile_overrides(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    monkeypatch.delenv("MCP_GATEWAY_RESTRICTED_SINKS", raising=False)
    monkeypatch.delenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", raising=False)
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    resp = client.put(
        f"/api/control/policy-profile?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "profile_name": "strict",
            "restricted_sinks_additions": ["clipboard"],
            "allow_untrusted_with_approvals": True,
            "change_reason": "rollout",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["profile_name"] == "strict"
    assert data["allow_untrusted_with_approvals"] is True
    sinks = set(data["restricted_sinks_effective"])
    assert {
        "network_write",
        "file_write",
        "restricted",
        "sampling",
        "clipboard",
    } <= sinks

    assert "clipboard" in gateway._restricted_sinks()
    assert gateway._allow_untrusted_with_approvals() is True

    event = json.loads(evidence_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["event"] == "control_policy_profile_updated"
    assert event["trigger_source"] == "ui"

    # evidence_id が返却されることを確認
    assert "evidence_id" in data


def test_control_policy_profile_presets(monkeypatch: pytest.MonkeyPatch):
    """P1-4: プリセット一覧APIテスト"""
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    client = TestClient(app)

    resp = client.get(
        "/api/control/policy-profile/presets",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "presets" in data
    assert "core_rules" in data
    preset_names = [p["name"] for p in data["presets"]]
    assert "standard" in preset_names
    assert "strict" in preset_names
    assert "development" in preset_names
    # コアルールは無効化不可
    assert "network_write" in data["core_rules"]["restricted_sinks"]
    assert "file_write" in data["core_rules"]["restricted_sinks"]


def test_control_policy_profile_preview(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """P1-4: プレビューAPIテスト"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    client = TestClient(app)

    # 初期状態でプレビュー（standard→strict への変更）
    resp = client.post(
        f"/api/control/policy-profile/preview?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "profile_name": "strict",
            "restricted_sinks_additions": ["clipboard"],
            "change_reason": "preview test",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "current" in data
    assert "proposed" in data
    assert "changes" in data
    assert "has_changes" in data
    assert data["proposed"]["profile_name"] == "strict"
    assert "clipboard" in data["proposed"]["restricted_sinks_additions"]
    # プレビューはDBを変更しない（GET で確認）
    resp2 = client.get(
        f"/api/control/policy-profile?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp2.json()["profile_name"] == "standard"  # 変更されていない


def test_proxy_uses_control_upstream(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    db = sqlite_utils.Database(db_file)
    gateway._ensure_control_tables(db)
    db[gateway.CONTROL_UPSTREAM_TABLE].insert(
        {
            "base_url": "http://db-upstream",
            "provider": "test",
            "api_key": "db-key",
            "models_allowlist": json.dumps(["db-model", "db-model-2"]),
            "status": "ok",
            "last_tested": "2025-01-01T00:00:00Z",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "proxy-token")
    monkeypatch.setenv("MCP_GATEWAY_PROXY_MODELS", "env-model")
    monkeypatch.setenv("MCP_GATEWAY_UPSTREAM_BASE_URL", "http://env-upstream")
    monkeypatch.setenv("MCP_GATEWAY_UPSTREAM_API_KEY", "env-key")
    client = TestClient(app)

    resp = client.get("/v1/models", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401
    resp = client.get("/v1/models", headers={"Authorization": "Bearer proxy-token"})
    assert resp.status_code == 200
    model_ids = [item["id"] for item in resp.json()["data"]]
    assert model_ids == ["db-model", "db-model-2"]

    upstream_base, upstream_key = gateway._upstream_config()
    assert upstream_base == "http://db-upstream"
    assert upstream_key == "db-key"


def test_proxy_blocks_on_dlp_deny_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("MCP_GATEWAY_DLP_MODE", "deny")
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "proxy-token")
    monkeypatch.setenv("MCP_GATEWAY_PROXY_MODELS", "test-model")
    monkeypatch.setenv("MCP_GATEWAY_UPSTREAM_BASE_URL", "http://upstream")
    monkeypatch.setenv("MCP_GATEWAY_UPSTREAM_API_KEY", "upstream-key")
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", tmp_path / "missing.db")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict, headers: dict):
            return type(
                "Resp",
                (),
                {
                    "status_code": 200,
                    "json": staticmethod(
                        lambda: {"reply": "contact admin@example.com"}
                    ),
                },
            )()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    client = TestClient(app)
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer proxy-token"},
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert resp.status_code == 403
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        rec.get("event") == "proxy_dlp_detected" and rec.get("decision") == "deny"
        for rec in records
    )
    assert any(
        rec.get("event") == "openai_proxy_block" and rec.get("reason") == "dlp detected"
        for rec in records
    )


def test_control_token_proxy_auth(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    resp = client.post(
        f"/api/control/tokens?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={"env_id": 1, "expires_at": "2099-01-01T00:00:00Z", "note": "test"},
    )
    assert resp.status_code == 200
    token_payload = resp.json()
    token = token_payload["token"]
    token_id = token_payload["id"]

    resp = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    db = sqlite_utils.Database(db_file)
    rows = list(db["control_tokens"].rows_where("id = ?", [token_id]))
    assert rows
    assert rows[0]["last_used_at"]

    resp = client.post(
        f"/api/control/tokens/{token_id}/revoke?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200

    resp = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_control_audit_returns_events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "good-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={"base_url": "http://upstream", "api_key": "secret", "provider": "test"},
    )
    assert resp.status_code == 200

    block_resp = client.get("/v1/models", headers={"Authorization": "Bearer bad-token"})
    assert block_resp.status_code == 401
    evidence_id = block_resp.json()["evidence_id"]

    audit_resp = client.get(
        "/api/control/audit", headers={"Authorization": "Bearer admin-token"}
    )
    assert audit_resp.status_code == 200
    items = audit_resp.json()
    assert any(item["type"] == "control_upstream_updated" for item in items)
    assert any(item["evidence_id"] == evidence_id for item in items)


# --- Batch1a: Secrets Operations Tests ---


def test_read_secret_prefers_file_over_env(tmp_path, monkeypatch, caplog):
    """ファイル経由のsecret読み込みがenv直接設定より優先されることを確認"""
    from src.mcp_gateway import gateway

    # ファイルにsecretを書き込み
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-secret-value")

    # 両方設定した場合、ファイルが優先される
    monkeypatch.setenv("TEST_SECRET", "env-secret-value")
    monkeypatch.setenv("TEST_SECRET_FILE", str(secret_file))

    result = gateway._read_secret("TEST_SECRET", "TEST_SECRET_FILE")
    assert result == "file-secret-value"
    # ファイル経由なら警告は出ない
    assert "instead of file" not in caplog.text


def test_read_secret_warns_on_env_usage(monkeypatch, caplog):
    """env直接設定時に警告ログが出ることを確認（秘密情報は含まれない）"""
    import logging

    from src.mcp_gateway import gateway

    caplog.set_level(logging.WARNING)

    # ファイル設定なし、envのみ設定
    monkeypatch.delenv("TEST_SECRET_FILE", raising=False)
    monkeypatch.setenv("TEST_SECRET", "my-secret-value")

    result = gateway._read_secret("TEST_SECRET", "TEST_SECRET_FILE")
    assert result == "my-secret-value"
    # 警告が出る
    assert "instead of file" in caplog.text
    assert "TEST_SECRET" in caplog.text
    assert "TEST_SECRET_FILE" in caplog.text
    # 秘密情報は含まれない
    assert "my-secret-value" not in caplog.text


def test_read_secret_warns_on_missing_file(tmp_path, monkeypatch, caplog):
    """ファイルが存在しない場合に警告ログが出ることを確認"""
    import logging

    from src.mcp_gateway import gateway

    caplog.set_level(logging.WARNING)

    # 存在しないファイルパスを設定
    monkeypatch.setenv("TEST_SECRET_FILE", str(tmp_path / "nonexistent.txt"))

    result = gateway._read_secret("TEST_SECRET", "TEST_SECRET_FILE")
    assert result == ""
    # ファイルが見つからない警告が出る
    assert "Secret file not found" in caplog.text


# --- Batch1b: Admin Token非返却契約 + CSRF ---


def test_control_session_response_does_not_expose_admin_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """セッション認証レスポンスにAdmin Tokenが含まれないことを確認（非返却契約）"""
    admin_token = "super-secret-admin-token-12345"
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", admin_token)
    client = TestClient(app)

    resp = client.post(
        "/api/control/session",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200

    # レスポンスボディにAdmin Tokenが含まれていないこと
    body = resp.json()
    assert "status" in body
    assert "expires_at" in body
    assert admin_token not in str(body)
    # Cookie経由でもAdmin Token自体は返さない（セッショントークンは別物）
    session_cookie = resp.cookies.get(gateway.ADMIN_SESSION_COOKIE_NAME)
    assert session_cookie is not None
    assert admin_token not in session_cookie


def test_csrf_guard_requires_origin_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """CSRFガードがOriginヘッダーを要求することを確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    client = TestClient(app)

    # セッション取得
    resp = client.post(
        "/api/control/session",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200

    # セッション認証でOriginなしPUT → 403
    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        json={
            "base_url": "http://test",
            "api_key": "key",
            "provider": "p",
            "models_allowlist": [],
        },
    )
    assert resp.status_code == 403
    assert "csrf" in resp.json().get("detail", "").lower()

    # セッション認証で正しいOrigin付きPUT → 200
    resp = client.put(
        f"/api/control/upstream?db_path={db_file}",
        headers={"Origin": "http://testserver"},
        json={
            "base_url": "http://test",
            "api_key": "key",
            "provider": "p",
            "models_allowlist": [],
        },
    )
    assert resp.status_code == 200


# --- Batch2a: ワンボタンフロー ---


def test_control_setup_one_button_flow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """ワンボタンフロー: Save→Test→Issue を一括実行 + Evidence発行確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    # upstreamテストをモック（成功ケース）
    class DummyResponse:
        status_code = 200
        text = "ok"

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def get(self, *a, **k):
            return DummyResponse()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: DummyClient())

    resp = client.post(
        f"/api/control/setup?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "base_url": "http://upstream.local",
            "api_key": "test-key",
            "provider": "openai",
            "models_allowlist": ["gpt-4"],
            "issue_token": True,
            "token_env_id": 1,
            "token_expires_at": "2027-01-01T00:00:00Z",
            "token_note": "setup test",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["upstream"]["test_status"] == "ok"
    assert data["token"] is not None
    assert "token" in data["token"]

    # Evidence確認
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    setup_events = [r for r in records if r.get("event") == "setup_completed"]
    assert len(setup_events) == 1
    assert setup_events[0]["test_status"] == "ok"
    assert setup_events[0]["token_issued"] is True


def test_control_setup_upstream_fail_no_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """upstream失敗時はtoken発行されないことを確認（status=partial）"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    # upstreamテストをモック（失敗ケース: 500エラー）
    class FailResponse:
        status_code = 500
        text = "error"

    class FailClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def get(self, *a, **k):
            return FailResponse()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: FailClient())

    resp = client.post(
        f"/api/control/setup?db_path={db_file}",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "base_url": "http://upstream.local",
            "api_key": "test-key",
            "provider": "openai",
            "models_allowlist": ["gpt-4"],
            "issue_token": True,
            "token_env_id": 1,
            "token_expires_at": "2027-01-01T00:00:00Z",
            "token_note": "setup test",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "partial"
    assert data["upstream"]["test_status"] == "error"
    # upstream失敗時はtokenは発行されない
    assert data["token"] is None

    # Evidence確認
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    setup_events = [r for r in records if r.get("event") == "setup_completed"]
    assert len(setup_events) == 1
    assert setup_events[0]["test_status"] == "error"
    assert setup_events[0]["token_issued"] is False


# --- Batch2b: LLM Security Hub (fail-closed allowlist) ---


def test_proxy_models_empty_allowlist_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """空allowlist時にfail-closed（全モデル拒否）となることを確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    # 明示的にenvをクリア
    monkeypatch.delenv("MCP_GATEWAY_PROXY_MODELS", raising=False)
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "test-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    client = TestClient(app)

    # upstreamを設定（models_allowlist空）
    db = sqlite_utils.Database(db_file)
    gateway._ensure_control_tables(db)
    db["control_upstream"].insert(
        {
            "base_url": "http://upstream",
            "api_key": "key",
            "provider": "test",
            "models_allowlist": "[]",  # 空リスト
            "status": "ok",
            "last_tested": "",
        }
    )

    # models_allowlistが空なので、全モデル拒否
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer test-token"},
        json={"model": "any-model", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 403
    assert (
        "model not allowed" in resp.json().get("error", {}).get("message", "").lower()
    )


# --- Batch3a: Explainability共通化 ---


def test_block_response_includes_evidence_id_and_trace_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """ブロックレスポンスにevidence_id, trace_id, reason_codeが含まれることを確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "test-token")
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))

    # 空allowlistを設定（全モデル拒否）
    db = sqlite_utils.Database(db_file)
    gateway._ensure_control_tables(db)
    db["control_upstream"].insert(
        {
            "base_url": "http://upstream",
            "api_key": "key",
            "provider": "test",
            "models_allowlist": "[]",
            "status": "ok",
            "last_tested": "",
        }
    )

    client = TestClient(app)

    # X-Request-IDヘッダーを指定
    custom_trace_id = "custom-trace-12345"
    resp = client.post(
        "/v1/chat/completions",
        headers={
            "Authorization": "Bearer test-token",
            "X-Request-ID": custom_trace_id,
        },
        json={"model": "any-model", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert resp.status_code == 403
    data = resp.json()
    # レスポンスボディにevidence_idとtrace_idが含まれる
    assert "evidence_id" in data
    assert "trace_id" in data
    # trace_idはリクエストヘッダーの値が使われる
    assert data["trace_id"] == custom_trace_id
    # ヘッダーにも含まれる
    assert resp.headers.get("X-MCP-Evidence-Id") == data["evidence_id"]
    assert resp.headers.get("X-MCP-Trace-Id") == data["trace_id"]

    # Evidenceにもtrace_idとreason_codeが記録される
    records = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    block_events = [r for r in records if r.get("event") == "openai_proxy_block"]
    assert len(block_events) >= 1
    assert block_events[-1].get("trace_id") == custom_trace_id
    assert "reason_code" in block_events[-1]


# --- Batch3b: Smoke Coverage Gate ---


def test_smoke_endpoints_health_and_models(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """CI smokeで必須のエンドポイント（/health, /v1/models）が動作することを確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "test-token")
    client = TestClient(app)

    # /health - 認証不要
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json().get("status") == "ok"

    # /v1/models - 認証必要
    resp = client.get("/v1/models", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    assert "data" in resp.json()


def test_smoke_endpoints_tools_and_mcp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """CI smokeで必須のエンドポイント（/tools, /mcp）が動作することを確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", db_file)
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "test-token")
    client = TestClient(app)

    # /tools - 認証必要
    resp = client.get("/tools", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # /mcp (JSON-RPC initialize) - 認証必要
    resp = client.post(
        "/mcp",
        headers={
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
        },
        json={"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("jsonrpc") == "2.0"
    assert "result" in data or "error" in data


def test_smoke_endpoint_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """CI smokeで/runエンドポイントが認証付きで動作することを確認"""
    db_file = tmp_path / "test.db"
    registry.init_db(db_file)
    # Note: monkeypatch.setattr(gateway, "DEFAULT_DB_PATH") does not work
    # because Python default arguments are evaluated at function definition time.
    # Use db_path query parameter instead.
    monkeypatch.setenv("MCP_GATEWAY_PROXY_TOKEN", "test-token")

    # with形式でlifespanを確実に実行
    with TestClient(app) as client:
        # /run - 認証なしで401または403
        # Note: testing.py's TestClient auto-injects Authorization header from env,
        # so we explicitly set an empty/invalid header to test unauthenticated access.
        resp = client.post(
            f"/run?db_path={db_file}",
            headers={"Authorization": ""},
            json={"server_id": 1, "tool_name": "test", "args": {}},
        )
        assert resp.status_code in (
            401,
            403,
        ), f"Expected 401/403, got {resp.status_code}"

        # /run - 認証ありで動作（サーバ未登録なので400/404相当のエラー）
        resp = client.post(
            f"/run?db_path={db_file}",
            headers={"Authorization": "Bearer test-token"},
            json={"server_id": 999, "tool_name": "test", "args": {}},
        )
        # サーバ未登録でも認証は通過する（400, 404, または500）
        assert resp.status_code in (400, 404, 500)


class TestGeminiKeyConfig:
    """Tests for Gemini API key configuration endpoints."""

    AUTH = {"Authorization": "Bearer admin-token"}

    def test_gemini_status_not_configured(self, monkeypatch):
        """GET /api/config/gemini-status returns not configured when no key."""
        monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
        old = os.environ.pop("GOOGLE_API_KEY", None)
        try:
            with TestClient(app) as client:
                resp = client.get(
                    "/api/config/gemini-status", headers=self.AUTH
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["configured"] is False
        finally:
            if old is not None:
                os.environ["GOOGLE_API_KEY"] = old

    def test_set_gemini_key(self, monkeypatch):
        """POST /api/config/gemini-key stores key in environment."""
        monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
        old = os.environ.pop("GOOGLE_API_KEY", None)
        try:
            with TestClient(app) as client:
                resp = client.post(
                    "/api/config/gemini-key",
                    json={"api_key": "AIzaSyTestKey12345678"},
                    headers=self.AUTH,
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["gemini_configured"] is True
                assert os.environ.get("GOOGLE_API_KEY") == "AIzaSyTestKey12345678"

                # Verify status endpoint reflects the change
                resp2 = client.get(
                    "/api/config/gemini-status", headers=self.AUTH
                )
                data2 = resp2.json()
                assert data2["configured"] is True
                assert "AIza" in data2["key_preview"]
        finally:
            os.environ.pop("GOOGLE_API_KEY", None)
            if old is not None:
                os.environ["GOOGLE_API_KEY"] = old

    def test_set_gemini_key_empty_rejected(self, monkeypatch):
        """POST /api/config/gemini-key rejects empty key."""
        monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
        with TestClient(app) as client:
            resp = client.post(
                "/api/config/gemini-key",
                json={"api_key": "   "},
                headers=self.AUTH,
            )
            assert resp.status_code == 400

    def test_gemini_key_requires_auth(self, monkeypatch):
        """Gemini key endpoints require admin authentication."""
        monkeypatch.setenv("MCP_GATEWAY_ADMIN_TOKEN", "admin-token")
        with TestClient(app) as client:
            resp = client.post(
                "/api/config/gemini-key",
                json={"api_key": "test"},
            )
            assert resp.status_code == 401
            resp2 = client.get("/api/config/gemini-status")
            assert resp2.status_code == 401


