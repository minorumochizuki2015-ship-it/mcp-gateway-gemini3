"""Registry for MCP servers, scan results, council evaluations, and allowlist."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sqlite_utils

from . import evidence


def _normalize_db_path(db_path: str | Path) -> Path:
    path_str = str(db_path)
    if not path_str:
        raise ValueError("db_path is empty")
    if "$" in path_str:
        raise ValueError("db_path contains '$' (unexpanded env?)")
    return Path(path_str)


def init_db(db_path: str | Path = "data/mcp_gateway.db") -> sqlite_utils.Database:
    """
    Initialize the database and create tables if they don't exist.

    Args:
        db_path: Path to SQLite database file

    Returns:
        sqlite_utils.Database instance
    """
    db_path_obj = _normalize_db_path(db_path)
    db_path_obj.parent.mkdir(parents=True, exist_ok=True)

    db = sqlite_utils.Database(db_path_obj)

    # Create mcp_servers table
    if "mcp_servers" not in db.table_names():
        db["mcp_servers"].create(
            {
                "id": int,
                "name": str,
                "base_url": str,
                "origin_url": str,
                "origin_sha": str,
                "status": str,  # draft/pending_scan/approved/blocked
                "created_at": str,
                "updated_at": str,
            },
            pk="id",
        )
    migrate_mcp_servers_schema(db)

    # Create scan_results table
    if "scan_results" not in db.table_names():
        db["scan_results"].create(
            {
                "id": int,
                "server_id": int,
                "run_id": str,
                "scan_type": str,  # static/mcpsafety
                "status": str,  # pass/warn/fail
                "findings": str,  # JSON
                "started_at": str,
                "ended_at": str,
            },
            pk="id",
        )

    # Create council_evaluations table
    if "council_evaluations" not in db.table_names():
        db["council_evaluations"].create(
            {
                "id": int,
                "run_id": str,
                "server_id": int,
                "scores": str,  # JSON: {security, utility, cost}
                "decision": str,  # allow/deny/quarantine
                "rationale": str,
                "created_at": str,
            },
            pk="id",
        )

    # Create allowlist table
    if "allowlist" not in db.table_names():
        db["allowlist"].create(
            {
                "id": int,
                "server_id": int,
                "tools_exposed": str,  # JSON array
                "risk_level": str,
                "capabilities": str,  # JSON array
                "status": str,  # proposed/active/revoked
                "created_at": str,
                "updated_at": str,
            },
            pk="id",
        )
    migrate_allowlist_schema(db)

    # Create mcp_environments table (for UI settings)
    if "mcp_environments" not in db.table_names():
        db["mcp_environments"].create(
            {
                "id": int,
                "name": str,
                "endpoint_url": str,
                "status": str,  # active/disabled
                "memo": str,
                "secret_hash": str,  # SHA256 of secret, empty if no secret
                "created_at": str,
                "updated_at": str,
            },
            pk="id",
        )

    # Create scan_profiles table (for UI settings)
    if "scan_profiles" not in db.table_names():
        db["scan_profiles"].create(
            {
                "id": int,
                "name": str,  # quick/full/custom
                "check_categories": str,  # JSON array
                "is_default": int,  # 0/1
                "created_at": str,
                "updated_at": str,
            },
            pk="id",
        )

    return db


EVIDENCE_ENV_VAR = "MCP_GATEWAY_EVIDENCE_PATH"
DEFAULT_EVIDENCE_PATH = Path("observability/policy/ci_evidence.jsonl")
_SECRET_KEY_FRAGMENTS = (
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "credential",
)


def _evidence_path() -> Path:
    override = os.getenv(EVIDENCE_ENV_VAR)
    return Path(override) if override else DEFAULT_EVIDENCE_PATH


def _looks_like_secret_ref(value: str) -> bool:
    return value.startswith("$") or value.startswith("env:")


def _redact_secret_values(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for k, v in value.items():
            key = str(k).lower()
            if any(fragment in key for fragment in _SECRET_KEY_FRAGMENTS):
                if isinstance(v, str) and _looks_like_secret_ref(v):
                    redacted[k] = v
                else:
                    redacted[k] = "{REDACTED}"
                continue
            redacted[k] = _redact_secret_values(v)
        return redacted
    if isinstance(value, list):
        return [_redact_secret_values(v) for v in value]
    return value


_RISK_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_DEFAULT_RISK_LEVEL = "medium"


def _normalize_risk_level(value: str | None, *, default: str = _DEFAULT_RISK_LEVEL) -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in _RISK_LEVEL_ORDER else default


def _merge_risk_level(base: str, candidate: str) -> str:
    if not base:
        return candidate
    if not candidate:
        return base
    return (
        candidate
        if _RISK_LEVEL_ORDER.get(candidate, -1) > _RISK_LEVEL_ORDER.get(base, -1)
        else base
    )


def _parse_capabilities(raw: Any) -> list[str]:
    if raw is None:
        return []
    values: list[Any]
    if isinstance(raw, list):
        values = raw
    elif isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            values = parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            values = []
    else:
        try:
            values = list(raw)
        except TypeError:
            values = []
    return sorted({str(c).strip().lower() for c in values if str(c).strip()})


def _parse_tools_exposed(raw: Any) -> list[dict]:
    if raw is None:
        return []
    try:
        tools = json.loads(raw) if isinstance(raw, str) else list(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    return [tool for tool in tools if isinstance(tool, dict)]


def _extract_tool_risk_caps(tools: list[dict]) -> tuple[str, list[str]]:
    risk = ""
    caps: set[str] = set()
    for tool in tools:
        risk = _merge_risk_level(
            risk, _normalize_risk_level(tool.get("risk_level"), default="")
        )
        caps.update(_parse_capabilities(tool.get("capabilities")))
    return risk, sorted(caps)


def derive_risk_context(row: dict, tools: list[dict] | None = None) -> tuple[str, list[str]]:
    """Merge allowlist + tool-level risk context into a single view."""
    tools = tools if tools is not None else _parse_tools_exposed(row.get("tools_exposed"))
    base_risk = _normalize_risk_level(row.get("risk_level"))
    base_caps = _parse_capabilities(row.get("capabilities"))
    tool_risk, tool_caps = _extract_tool_risk_caps(tools)
    risk_level = _merge_risk_level(base_risk, tool_risk)
    capabilities = sorted(set(base_caps) | set(tool_caps))
    return risk_level, capabilities


def compute_tools_manifest_hash(tools_exposed: list[dict]) -> str:
    """allowlist.tools_exposed を canonicalize して SHA256 を返す。"""
    canonical_tools: list[dict[str, Any]] = []
    for tool in tools_exposed:
        if not isinstance(tool, dict):
            continue
        input_schema = tool.get("input_schema")
        if input_schema is None:
            input_schema = tool.get("args")
        canonical_tools.append(
            {
                "name": str(tool.get("name") or ""),
                "description": str(tool.get("description") or ""),
                "input_schema": (
                    _redact_secret_values(input_schema) if input_schema else {}
                ),
                "output_schema": (
                    _redact_secret_values(tool.get("output_schema"))
                    if tool.get("output_schema")
                    else {}
                ),
            }
        )
    canonical_tools.sort(key=lambda t: t.get("name") or "")
    payload = json.dumps(
        canonical_tools,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def upsert_server(
    db: sqlite_utils.Database,
    name: str,
    base_url: str,
    status: str = "draft",
    origin_url: str | None = None,
    origin_sha: str | None = None,
) -> int:
    """
    Insert or update a server record.

    Args:
        db: Database instance
        name: Server name
        base_url: Server base URL
        status: Server status (draft/pending_scan/approved/blocked)
        origin_url: GitHub repo URL (required; repo@sha intake)
        origin_sha: Git commit SHA (required)

    Returns:
        Server ID
    """
    now = datetime.now(timezone.utc).isoformat()
    origin_url = origin_url.strip() if isinstance(origin_url, str) else None
    origin_sha = origin_sha.strip() if isinstance(origin_sha, str) else None
    if origin_url == "":
        origin_url = None
    if origin_sha == "":
        origin_sha = None
    if (origin_url is None) != (origin_sha is None):
        raise ValueError("origin_url and origin_sha must be provided together")

    # Check if server exists by name
    existing = list(db["mcp_servers"].rows_where("name = ?", [name]))

    if existing:
        server_id = existing[0]["id"]
        current_origin_url = str(existing[0].get("origin_url") or "").strip()
        current_origin_sha = str(existing[0].get("origin_sha") or "").strip()
        if origin_url is None and origin_sha is None:
            origin_url = current_origin_url or None
            origin_sha = current_origin_sha or None
        if not origin_url or not origin_sha:
            raise ValueError("origin_url and origin_sha are required")
        update_data = {
            "base_url": base_url,
            "status": status,
            "updated_at": now,
            "origin_url": origin_url,
            "origin_sha": origin_sha,
        }
        db["mcp_servers"].update(server_id, update_data)
    else:
        if not origin_url or not origin_sha:
            raise ValueError("origin_url and origin_sha are required")
        result = db["mcp_servers"].insert(
            {
                "name": name,
                "base_url": base_url,
                "origin_url": origin_url,
                "origin_sha": origin_sha,
                "status": status,
                "created_at": now,
                "updated_at": now,
            }
        )
        server_id = result.last_pk

    return server_id


def get_server(db: sqlite_utils.Database, server_id: int) -> dict | None:
    """
    Get a server by ID.

    Args:
        db: Database instance
        server_id: Server ID

    Returns:
        Server dict or None if not found
    """
    try:
        return dict(db["mcp_servers"].get(server_id))
    except sqlite_utils.db.NotFoundError:
        return None


def list_servers(db: sqlite_utils.Database, status: str | None = None) -> list[dict]:
    """
    List all servers, optionally filtered by status.

    Args:
        db: Database instance
        status: Optional status filter

    Returns:
        List of server dicts
    """
    if status:
        return list(db["mcp_servers"].rows_where("status = ?", [status]))
    return list(db["mcp_servers"].rows)


def save_scan_result(
    db: sqlite_utils.Database,
    server_id: int,
    run_id: str,
    scan_type: str,
    status: str,
    findings: list[dict],
) -> int:
    """
    Save a scan result.

    Args:
        db: Database instance
        server_id: Server ID
        run_id: Run ID (UUID)
        scan_type: Scan type (static/mcpsafety)
        status: Result status (pass/warn/fail)
        findings: List of finding dicts

    Returns:
        Scan result ID
    """
    import json

    now = datetime.now(timezone.utc).isoformat()

    result = db["scan_results"].insert(
        {
            "server_id": server_id,
            "run_id": run_id,
            "scan_type": scan_type,
            "status": status,
            "findings": json.dumps(findings, ensure_ascii=False),
            "started_at": now,
            "ended_at": now,
        }
    )

    return result.last_pk


def save_council_evaluation(
    db: sqlite_utils.Database,
    server_id: int,
    run_id: str,
    scores: dict,
    decision: str,
    rationale: str,
) -> int:
    """
    Save a council evaluation.

    Args:
        db: Database instance
        server_id: Server ID
        run_id: Run ID (UUID)
        scores: Scores dict {security, utility, cost}
        decision: Decision (allow/deny/quarantine)
        rationale: Rationale text

    Returns:
        Evaluation ID
    """
    import json

    now = datetime.now(timezone.utc).isoformat()

    result = db["council_evaluations"].insert(
        {
            "run_id": run_id,
            "server_id": server_id,
            "scores": json.dumps(scores, ensure_ascii=False),
            "decision": decision,
            "rationale": rationale,
            "created_at": now,
        }
    )

    return result.last_pk


def get_allowlist_snapshot(db: sqlite_utils.Database) -> dict:
    """
    Get a snapshot of all active allowlist entries.

    Returns:
        Dict with server_id -> tools_exposed mapping
    """
    snapshot = {}
    for entry in get_allowlist_entries(db):
        snapshot[entry["server_id"]] = entry["tools_exposed"]

    return snapshot


def get_allowlist_entries(
    db: sqlite_utils.Database, *, repair: bool = True
) -> list[dict]:
    """Get active allowlist rows with parsed risk_level/capabilities."""
    if "allowlist" not in db.table_names():
        return []
    if repair:
        migrate_allowlist_schema(db)
    now = datetime.now(timezone.utc).isoformat()

    active_rows = list(db["allowlist"].rows_where("status = ?", ["active"]))
    entries: list[dict] = []
    for row in active_rows:
        entry = _parse_allowlist_row(row)
        expected_hash = str(row.get("tools_manifest_hash") or "")
        if repair:
            observed_hash = compute_tools_manifest_hash(entry["tools_exposed"])
            if not expected_hash:
                db["allowlist"].update(
                    entry["id"],
                    {"tools_manifest_hash": observed_hash, "updated_at": now},
                )
                evidence.append(
                    {
                        "event": "tool_manifest_changed",
                        "change_type": "pinned",
                        "server_id": entry["server_id"],
                        "allowlist_id": entry["id"],
                        "old_hash": "",
                        "new_hash": observed_hash,
                        "tool_count": len(entry["tools_exposed"]),
                    },
                    path=_evidence_path(),
                )
                expected_hash = observed_hash
            elif expected_hash != observed_hash:
                db["allowlist"].update(
                    entry["id"], {"status": "revoked", "updated_at": now}
                )
                evidence.append(
                    {
                        "event": "tool_manifest_changed",
                        "change_type": "drift",
                        "action": "revoked",
                        "server_id": entry["server_id"],
                        "allowlist_id": entry["id"],
                        "old_hash": expected_hash,
                        "new_hash": observed_hash,
                        "tool_count": len(entry["tools_exposed"]),
                    },
                    path=_evidence_path(),
                )
                continue
            base_risk = _normalize_risk_level(row.get("risk_level"))
            base_caps = _parse_capabilities(row.get("capabilities"))
            if entry["risk_level"] != base_risk or set(entry["capabilities"]) != set(
                base_caps
            ):
                update_fields: dict[str, Any] = {}
                if entry["risk_level"] != base_risk:
                    update_fields["risk_level"] = entry["risk_level"]
                if set(entry["capabilities"]) != set(base_caps):
                    update_fields["capabilities"] = json.dumps(
                        entry["capabilities"], ensure_ascii=False
                    )
                if update_fields:
                    update_fields["updated_at"] = now
                    db["allowlist"].update(entry["id"], update_fields)
        entry["tools_manifest_hash"] = expected_hash
        entries.append(entry)
    return entries


def _parse_allowlist_row(row: dict) -> dict:
    """allowlist 行を Python 表現に変換し、欠損時はデフォルトを補う。"""
    tools = _parse_tools_exposed(row.get("tools_exposed") or "[]")
    risk_level, capabilities = derive_risk_context(row, tools)
    return {
        "id": row.get("id"),
        "server_id": row.get("server_id"),
        "tools_exposed": tools,
        "tools_manifest_hash": str(row.get("tools_manifest_hash") or ""),
        "risk_level": risk_level,
        "capabilities": capabilities,
        "status": row.get("status"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def migrate_mcp_servers_schema(db: sqlite_utils.Database) -> None:
    """origin_url / origin_sha カラムを追加する最小マイグレーションを適用する。"""
    if "mcp_servers" not in db.table_names():
        return
    columns = db["mcp_servers"].columns_dict
    if "origin_url" not in columns:
        db.execute(
            "ALTER TABLE mcp_servers ADD COLUMN origin_url TEXT NOT NULL DEFAULT ''"
        )
    if "origin_sha" not in columns:
        db.execute(
            "ALTER TABLE mcp_servers ADD COLUMN origin_sha TEXT NOT NULL DEFAULT ''"
        )


def migrate_allowlist_schema(db: sqlite_utils.Database) -> None:
    """risk_level / capabilities カラムを追加する最小マイグレーションを適用する。"""
    if "allowlist" not in db.table_names():
        return
    columns = db["allowlist"].columns_dict
    if "risk_level" not in columns:
        db.execute(
            "ALTER TABLE allowlist ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'medium'"
        )
    if "capabilities" not in columns:
        db.execute(
            "ALTER TABLE allowlist ADD COLUMN capabilities TEXT NOT NULL DEFAULT '[]'"
        )
    if "tools_manifest_hash" not in columns:
        db.execute(
            "ALTER TABLE allowlist ADD COLUMN tools_manifest_hash TEXT NOT NULL DEFAULT ''"
        )


def promote_allowlist_entry(db: sqlite_utils.Database, server_id: int) -> bool:
    """
    指定 server_id の allowlist を昇格させる。

    - status="proposed" の行があれば、そのうち 1 件を status="active" に変更。
    - 同じ server_id の既存 status="active" 行はすべて "revoked" に変更。
    - proposed が無い場合は何もせず False を返す。
    - 正常に昇格した場合は True を返す。
    """
    now = datetime.now(timezone.utc).isoformat()
    proposed = list(
        db["allowlist"].rows_where(
            "server_id = ? AND status = ?", [server_id, "proposed"], order_by="-id"
        )
    )
    if not proposed:
        return False

    db.execute(
        "UPDATE allowlist SET status = ?, updated_at = ? WHERE server_id = ? AND status = ?",
        ("revoked", now, server_id, "active"),
    )

    target = proposed[0]
    tools_manifest_hash = ""
    try:
        tools = json.loads(target.get("tools_exposed") or "[]")
        if isinstance(tools, list):
            tools_manifest_hash = compute_tools_manifest_hash(
                [t for t in tools if isinstance(t, dict)]
            )
    except Exception:
        tools_manifest_hash = ""
    db["allowlist"].update(
        target["id"],
        {
            "status": "active",
            "updated_at": now,
            "tools_manifest_hash": tools_manifest_hash,
        },
    )
    return True


def revoke_allowlist_entries(db: sqlite_utils.Database, server_id: int) -> int:
    """
    指定 server_id の status=\"active\" の allowlist 行をすべて \"revoked\" に変更する。

    Returns:
        更新した件数（0 件でも可）
    """
    now = datetime.now(timezone.utc).isoformat()
    result = db.execute(
        "UPDATE allowlist SET status = ?, updated_at = ? WHERE server_id = ? AND status = ?",
        ("revoked", now, server_id, "active"),
    )
    return int(result.rowcount or 0)


# --- Settings API helper functions ---


def list_environments(db: sqlite_utils.Database) -> list[dict]:
    """Get all mcp_environments (secrets not returned)."""
    envs = []
    for row in db["mcp_environments"].rows:
        envs.append(
            {
                "id": row["id"],
                "name": row["name"],
                "endpoint_url": row["endpoint_url"],
                "status": row["status"],
                "memo": row["memo"],
                "has_secret": bool(row.get("secret_hash", "")),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return envs


def upsert_environment(
    db: sqlite_utils.Database,
    name: str,
    endpoint_url: str,
    status: str = "active",
    memo: str = "",
    secret: str = "",
) -> int:
    """Insert or update mcp_environment. Secret is hashed if provided."""
    now = datetime.now(timezone.utc).isoformat()
    secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest() if secret else ""

    existing = list(db["mcp_environments"].rows_where("name = ?", [name]))
    if existing:
        env_id = existing[0]["id"]
        update_data: dict[str, Any] = {
            "endpoint_url": endpoint_url,
            "status": status,
            "memo": memo,
            "updated_at": now,
        }
        if secret:
            update_data["secret_hash"] = secret_hash
        db["mcp_environments"].update(env_id, update_data)
    else:
        result = db["mcp_environments"].insert(
            {
                "name": name,
                "endpoint_url": endpoint_url,
                "status": status,
                "memo": memo,
                "secret_hash": secret_hash,
                "created_at": now,
                "updated_at": now,
            }
        )
        env_id = result.last_pk

    return env_id


def list_profiles(db: sqlite_utils.Database) -> list[dict]:
    """Get all scan_profiles."""
    profiles = []
    for row in db["scan_profiles"].rows:
        profiles.append(
            {
                "id": row["id"],
                "name": row["name"],
                "check_categories": (
                    json.loads(row["check_categories"])
                    if row.get("check_categories")
                    else []
                ),
                "is_default": bool(row["is_default"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return profiles


def upsert_profile(
    db: sqlite_utils.Database,
    name: str,
    check_categories: list[str],
    is_default: bool = False,
) -> int:
    """Insert or update scan_profile."""
    now = datetime.now(timezone.utc).isoformat()
    check_json = json.dumps(check_categories)

    existing = list(db["scan_profiles"].rows_where("name = ?", [name]))
    if existing:
        profile_id = existing[0]["id"]
        db["scan_profiles"].update(
            profile_id,
            {
                "check_categories": check_json,
                "is_default": int(is_default),
                "updated_at": now,
            },
        )
    else:
        result = db["scan_profiles"].insert(
            {
                "name": name,
                "check_categories": check_json,
                "is_default": int(is_default),
                "created_at": now,
                "updated_at": now,
            }
        )
        profile_id = result.last_pk

    return profile_id
