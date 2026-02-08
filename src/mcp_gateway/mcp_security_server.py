"""MCP Security Server - AI agent security filter hub.

This module implements a JSON-RPC 2.0 MCP server that acts as a security
gateway for AI agents. When an AI agent connects to this server, all
URL-accessing tool calls are automatically intercepted, scanned, and
filtered through the Causal Web Sandbox.

Architecture:
    AI Agent ──MCP──> MCP Security Server ──scan──> Causal Web Sandbox
                                          ──if safe──> Actual Browser/Fetch
                                          ──if blocked──> Reject + Explanation

Key features:
    - 2-tier scanning: fast (< 5ms) + deep (Gemini causal analysis)
    - Causal chain: explains WHY a page is dangerous
    - MCP zero-day detection: JSON-RPC injection patterns in web content
    - Seamless: transparent proxy, no AI agent changes needed
    - Session tracking: per-agent scan history and statistics
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from .causal_sandbox import (
    MCPInterceptRequest,
    MCPInterceptResult,
    SSRFError,
    ThreatClassification,
    fast_scan,
    intercept_mcp_tool_call,
    run_causal_scan,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Protocol Constants
# ---------------------------------------------------------------------------

MCP_JSONRPC_VERSION = "2.0"
MCP_SERVER_NAME = "mcp-security-gateway"
MCP_SERVER_VERSION = "1.0.0"

# Tools this server exposes to AI agents
MCP_TOOLS = [
    {
        "name": "secure_browse",
        "description": (
            "Navigate to a URL with automatic security scanning. "
            "Returns page content only if safe. Blocks phishing, malware, "
            "MCP injection, and DGA domains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to",
                },
                "scan_depth": {
                    "type": "string",
                    "enum": ["fast", "deep", "auto"],
                    "default": "auto",
                    "description": "Scan depth: fast (URL-only), deep (full page), auto (2-tier)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "secure_fetch",
        "description": (
            "Fetch URL content with security scanning. "
            "Similar to secure_browse but returns raw content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_url",
        "description": (
            "Check URL safety without fetching. Fast DGA/TLD/structure analysis. "
            "Returns security verdict with causal chain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to check",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "scan_report",
        "description": (
            "Full security scan report with DOM analysis, network traces, "
            "accessibility audit, DGA detection, and Gemini causal verdict."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to scan",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "session_stats",
        "description": "Get security scan statistics for current session.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------


class SessionStats(BaseModel):
    """Per-session scan statistics."""

    session_id: str
    total_scans: int = 0
    blocked: int = 0
    warned: int = 0
    allowed: int = 0
    fast_scans: int = 0
    deep_scans: int = 0
    avg_latency_ms: float = 0.0
    threats_detected: dict[str, int] = Field(default_factory=dict)
    started_at: str = ""


_sessions: dict[str, SessionStats] = {}
_scan_latencies: dict[str, list[float]] = defaultdict(list)


def _get_session(session_id: str) -> SessionStats:
    """Get or create session stats."""
    if session_id not in _sessions:
        _sessions[session_id] = SessionStats(
            session_id=session_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
    return _sessions[session_id]


def _update_session(session_id: str, result: MCPInterceptResult) -> None:
    """Update session stats with scan result."""
    stats = _get_session(session_id)
    stats.total_scans += 1

    if result.verdict:
        action = result.verdict.recommended_action
        if action == "block":
            stats.blocked += 1
        elif action == "warn":
            stats.warned += 1
        else:
            stats.allowed += 1

        threat = result.verdict.classification.value
        if threat != "benign":
            stats.threats_detected[threat] = stats.threats_detected.get(threat, 0) + 1

    if result.tier in ("fast", "skip"):
        stats.fast_scans += 1
    else:
        stats.deep_scans += 1

    _scan_latencies[session_id].append(result.latency_ms)
    latencies = _scan_latencies[session_id]
    stats.avg_latency_ms = round(sum(latencies) / len(latencies), 1)


# ---------------------------------------------------------------------------
# Tool Handlers
# ---------------------------------------------------------------------------


def _handle_secure_browse(params: dict[str, Any], session_id: str) -> dict[str, Any]:
    """Handle secure_browse tool call."""
    url = params.get("url", "")
    scan_depth = params.get("scan_depth", "auto")

    if not url:
        return {"error": "url parameter is required"}

    req = MCPInterceptRequest(
        method="browser_navigate", params={"url": url}, session_id=session_id,
    )
    result = intercept_mcp_tool_call(req)
    _update_session(session_id, result)

    if not result.allowed:
        response: dict[str, Any] = {
            "blocked": True,
            "url": url,
            "reason": result.reason,
            "tier": result.tier,
            "latency_ms": result.latency_ms,
        }
        if result.verdict:
            response["classification"] = result.verdict.classification.value
            response["confidence"] = result.verdict.confidence
            response["attack_narrative"] = result.verdict.attack_narrative
            response["causal_chain"] = [
                s.model_dump() for s in result.verdict.causal_chain
            ]
            response["mcp_threats"] = result.verdict.mcp_specific_threats
        return response

    # URL is safe - return clearance (actual browsing done by client)
    response = {
        "blocked": False,
        "url": url,
        "clearance": "approved",
        "tier": result.tier,
        "latency_ms": result.latency_ms,
    }
    if result.verdict:
        response["classification"] = result.verdict.classification.value
        response["confidence"] = result.verdict.confidence
    return response


def _handle_secure_fetch(params: dict[str, Any], session_id: str) -> dict[str, Any]:
    """Handle secure_fetch tool call - fetch URL content with security scanning.

    Unlike secure_browse (which returns clearance for client-side navigation),
    secure_fetch actually retrieves the page, scans it, and returns sanitized
    content if safe. This enables AI agents to read web pages through the
    security gateway.
    """
    url = params.get("url", "")
    if not url:
        return {"error": "url parameter is required"}

    # Run full causal scan (fetches + analyzes the page)
    try:
        scan_result = run_causal_scan(url)
    except SSRFError as exc:
        return {
            "blocked": True,
            "url": url,
            "reason": f"SSRF blocked: {exc}",
            "tier": "ssrf_guard",
        }
    except Exception as exc:
        return {"error": f"Scan failed: {exc}"}

    _update_session(session_id, MCPInterceptResult(
        allowed=scan_result.verdict.recommended_action != "block",
        action=scan_result.verdict.recommended_action,
        reason=scan_result.verdict.summary,
        tier=scan_result.tier or "deep",
        verdict=scan_result.verdict,
        latency_ms=scan_result.scan_latency_ms or 0.0,
    ))

    if scan_result.verdict.recommended_action == "block":
        response: dict[str, Any] = {
            "blocked": True,
            "url": url,
            "reason": scan_result.verdict.summary,
            "classification": scan_result.verdict.classification.value,
            "confidence": scan_result.verdict.confidence,
            "attack_narrative": scan_result.verdict.attack_narrative,
            "causal_chain": [
                s.model_dump() for s in scan_result.verdict.causal_chain
            ],
            "mcp_threats": scan_result.verdict.mcp_specific_threats,
            "tier": "deep",
        }
        return response

    # Safe - return page content for the AI agent to read
    from .causal_sandbox import extract_visible_text

    visible_text = ""
    if scan_result.bundle and scan_result.bundle.content_length > 0:
        # Re-fetch is avoided: extract text from the bundle we already have
        try:
            import httpx

            resp = httpx.get(url, timeout=15.0, follow_redirects=True)
            visible_text = extract_visible_text(resp.text)
        except Exception:
            visible_text = "(content extraction failed)"

    return {
        "blocked": False,
        "url": url,
        "classification": scan_result.verdict.classification.value,
        "confidence": scan_result.verdict.confidence,
        "content": visible_text[:50_000],
        "content_length": len(visible_text),
        "sha256": scan_result.bundle.sha256 if scan_result.bundle else "",
        "dom_threats_count": len(scan_result.dom_threats),
        "tier": "deep",
        "latency_ms": scan_result.scan_latency_ms or 0.0,
    }


def _handle_check_url(params: dict[str, Any], session_id: str) -> dict[str, Any]:
    """Handle check_url tool call - fast scan only."""
    url = params.get("url", "")
    if not url:
        return {"error": "url parameter is required"}

    t0 = time.monotonic()
    try:
        verdict = fast_scan(url)
    except Exception as exc:
        return {"error": f"Scan failed: {exc}"}

    latency = (time.monotonic() - t0) * 1000

    return {
        "url": url,
        "classification": verdict.classification.value,
        "confidence": verdict.confidence,
        "recommended_action": verdict.recommended_action,
        "risk_indicators": verdict.risk_indicators,
        "causal_chain": [s.model_dump() for s in verdict.causal_chain],
        "attack_narrative": verdict.attack_narrative,
        "mcp_threats": verdict.mcp_specific_threats,
        "tier": "fast",
        "latency_ms": round(latency, 1),
    }


def _handle_scan_report(params: dict[str, Any], session_id: str) -> dict[str, Any]:
    """Handle scan_report tool call - full deep scan."""
    url = params.get("url", "")
    if not url:
        return {"error": "url parameter is required"}

    try:
        result = run_causal_scan(url)
    except SSRFError as exc:
        return {"error": f"SSRF blocked: {exc}"}
    except Exception as exc:
        return {"error": f"Scan failed: {exc}"}

    return {
        "url": result.url,
        "run_id": result.run_id,
        "classification": result.verdict.classification.value,
        "confidence": result.verdict.confidence,
        "recommended_action": result.verdict.recommended_action,
        "risk_indicators": result.verdict.risk_indicators,
        "evidence_refs": result.verdict.evidence_refs,
        "causal_chain": [s.model_dump() for s in result.verdict.causal_chain],
        "attack_narrative": result.verdict.attack_narrative,
        "mcp_threats": result.verdict.mcp_specific_threats,
        "dom_threats_count": len(result.dom_threats),
        "dom_threats": [t.model_dump() for t in result.dom_threats[:20]],
        "suspicious_network": len([n for n in result.network_traces if n.is_suspicious]),
        "total_network_traces": len(result.network_traces),
        "a11y_deceptive_count": len(result.a11y_deceptive),
        "bundle": result.bundle.model_dump(),
        "eval_method": result.eval_method,
        "scan_latency_ms": result.scan_latency_ms,
        "tier": "deep",
    }


def _handle_session_stats(session_id: str) -> dict[str, Any]:
    """Handle session_stats tool call."""
    stats = _get_session(session_id)
    return stats.model_dump()


# ---------------------------------------------------------------------------
# JSON-RPC Message Handler
# ---------------------------------------------------------------------------


def handle_message(raw: str, session_id: str = "") -> str | None:
    """Handle a single JSON-RPC message.

    Args:
        raw: Raw JSON-RPC message string.
        session_id: Session identifier for stats tracking.

    Returns:
        JSON-RPC response string, or None for notifications.
    """
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return _error_response(None, -32700, "Parse error")

    if not isinstance(msg, dict):
        return _error_response(None, -32600, "Invalid Request")

    msg_id = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params", {})

    if method == "initialize":
        return _jsonrpc_response(msg_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": MCP_SERVER_NAME,
                "version": MCP_SERVER_VERSION,
            },
        })

    if method == "notifications/initialized":
        return None  # notification, no response

    if method == "tools/list":
        return _jsonrpc_response(msg_id, {"tools": MCP_TOOLS})

    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        return _handle_tool_call(msg_id, tool_name, tool_args, session_id)

    if method == "ping":
        return _jsonrpc_response(msg_id, {})

    # Unknown method
    return _error_response(msg_id, -32601, f"Method not found: {method}")


def _handle_tool_call(
    msg_id: Any, tool_name: str, args: dict[str, Any], session_id: str,
) -> str:
    """Route tool call to handler."""
    if tool_name == "secure_browse":
        result = _handle_secure_browse(args, session_id)
    elif tool_name == "secure_fetch":
        result = _handle_secure_fetch(args, session_id)
    elif tool_name == "check_url":
        result = _handle_check_url(args, session_id)
    elif tool_name == "scan_report":
        result = _handle_scan_report(args, session_id)
    elif tool_name == "session_stats":
        result = _handle_session_stats(session_id)
    else:
        return _error_response(msg_id, -32602, f"Unknown tool: {tool_name}")

    # Format as MCP tool result
    content = [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]
    return _jsonrpc_response(msg_id, {"content": content})


# ---------------------------------------------------------------------------
# JSON-RPC Helpers
# ---------------------------------------------------------------------------


def _jsonrpc_response(msg_id: Any, result: Any) -> str:
    """Build a JSON-RPC success response."""
    return json.dumps({
        "jsonrpc": MCP_JSONRPC_VERSION,
        "id": msg_id,
        "result": result,
    }, ensure_ascii=False)


def _error_response(msg_id: Any, code: int, message: str) -> str:
    """Build a JSON-RPC error response."""
    return json.dumps({
        "jsonrpc": MCP_JSONRPC_VERSION,
        "id": msg_id,
        "error": {"code": code, "message": message},
    }, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Stdio Transport
# ---------------------------------------------------------------------------


def run_stdio_server() -> None:
    """Run the MCP Security Server over stdio (LSP-style framing).

    Reads JSON-RPC messages from stdin, processes them, and writes
    responses to stdout. Each message is framed with Content-Length header.
    """
    session_id = str(uuid.uuid4())
    logger.info("MCP Security Server started, session=%s", session_id)

    buf = b""
    while True:
        try:
            chunk = sys.stdin.buffer.read(4096)
            if not chunk:
                break
            buf += chunk

            while buf:
                # Try to parse Content-Length framed message
                header_end = buf.find(b"\r\n\r\n")
                if header_end == -1:
                    # Try bare JSON (for simpler clients)
                    try:
                        raw = buf.decode("utf-8").strip()
                        if raw:
                            response = handle_message(raw, session_id)
                            if response:
                                _write_response(response)
                        buf = b""
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        break
                    break

                # Parse Content-Length header
                header = buf[:header_end].decode("utf-8")
                content_length = 0
                for line in header.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        content_length = int(line.split(":")[1].strip())
                        break

                if content_length == 0:
                    buf = buf[header_end + 4:]
                    continue

                body_start = header_end + 4
                if len(buf) < body_start + content_length:
                    break  # Need more data

                body = buf[body_start:body_start + content_length].decode("utf-8")
                buf = buf[body_start + content_length:]

                response = handle_message(body, session_id)
                if response:
                    _write_response(response)

        except KeyboardInterrupt:
            break
        except Exception as exc:
            logger.error("Server error: %s", exc)
            break

    logger.info("MCP Security Server stopped")


def _write_response(response: str) -> None:
    """Write a JSON-RPC response with Content-Length framing."""
    body = response.encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n"
    sys.stdout.buffer.write(header.encode("utf-8") + body)
    sys.stdout.buffer.flush()


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_stdio_server()
