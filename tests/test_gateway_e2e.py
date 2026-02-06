"""Gateway E2E smoke tests (manual run)."""

import os
import time

import httpx
import pytest


E2E_URL = os.getenv("MCP_GATEWAY_E2E_URL")
if not E2E_URL:
    pytest.skip("MCP_GATEWAY_E2E_URL is not set", allow_module_level=True)
E2E_TOKEN = os.getenv("MCP_GATEWAY_E2E_TOKEN")
if not E2E_TOKEN:
    pytest.skip("MCP_GATEWAY_E2E_TOKEN is not set", allow_module_level=True)


def _wait_for_health(client: httpx.Client, timeout_s: float = 5.0) -> httpx.Response:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = client.get("/health")
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.2)
            continue
        if resp.status_code == 200:
            return resp
        time.sleep(0.2)
    if last_exc:
        raise last_exc
    raise AssertionError("health check did not return 200")


def test_e2e_health_and_tools():
    with httpx.Client(base_url=E2E_URL, timeout=5) as client:
        resp = _wait_for_health(client)
        assert resp.json().get("status") == "ok"

        headers = {"Authorization": f"Bearer {E2E_TOKEN}"}
        tools = client.get("/tools", headers=headers)
        assert tools.status_code == 200
        assert isinstance(tools.json(), list)

        mcp = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "mcp-1",
                "method": "tools/list",
                "params": {},
            },
        )
        assert mcp.status_code == 200
        mcp_body = mcp.json()
        assert mcp_body.get("jsonrpc") == "2.0"
        assert mcp_body.get("id") == "mcp-1"
        assert "error" not in mcp_body
        assert isinstance(mcp_body.get("result"), list)

        allowlist_status = client.get("/api/allowlist/status")
        assert allowlist_status.status_code == 200
        body = allowlist_status.json()
        for key in (
            "total",
            "allow",
            "deny",
            "quarantine",
            "last_scan_ts",
            "last_decision_ts",
            "shadow_audit_chain_ok",
            "policy_bundle_hash_ok",
        ):
            assert key in body
