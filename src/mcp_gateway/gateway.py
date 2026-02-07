"""FastAPI Gateway providing /health and /tools endpoints."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import httpx
import sqlite_utils  # type: ignore[import-not-found]
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import evidence, registry, scanner

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
APPROVALS_RULES_PATH = BASE_DIR / "rules" / "APPROVALS.yaml"

# Create FastAPI app
app = FastAPI(
    title="MCP Gateway",
    description="Safe MCP aggregation and evaluation gateway",
    version="0.1.0",
)

# Default database path
DEFAULT_DB_PATH = Path("data/mcp_gateway.db")
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 1
DEFAULT_RATE_LIMIT_BURST = 20
DEFAULT_REQUEST_TIMEOUT_S = 70
DEFAULT_RESPONSE_TIMEOUT_S = 10
DEFAULT_RESPONSE_SIZE_CAP_BYTES = 512 * 1024
_RATE_LIMIT_BUCKET: deque[float] = deque()
_RATE_LIMIT_ENABLED: bool = True
SANITIZE_MAX_LEN = 512
_RE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_RE_HTML = re.compile(r"<[^>]+>")
SNAPSHOT_DIR = Path("artifacts/gateway/snapshots")
DIFF_DIR = Path("artifacts/gateway/diffs")
BLOCKED_RISK_LEVELS = {"high", "critical"}
BLOCKED_CAPABILITIES = {"network_write", "file_write"}
DEFAULT_RESTRICTED_SINKS = {"network_write", "file_write", "restricted"}
SOURCE_TRUSTED = "trusted"
SOURCE_UNTRUSTED = "untrusted"
DEFAULT_EVIDENCE_PATH = Path("observability/policy/ci_evidence.jsonl")
EVIDENCE_ENV_VAR = "MCP_GATEWAY_EVIDENCE_PATH"
POLICY_BUNDLE_PATH = Path("observability/policy/policy_bundle.tar")
POLICY_BUNDLE_SIG_PATH = Path("observability/policy/policy_bundle.sig")
APPROVALS_LEDGER = Path("APPROVALS.md")
PROXY_TOKEN_ENV = "MCP_GATEWAY_PROXY_TOKEN"
PROXY_TOKENS_ENV = "MCP_GATEWAY_PROXY_TOKENS"
PROXY_MODELS_ENV = "MCP_GATEWAY_PROXY_MODELS"
DLP_MODE_ENV = "MCP_GATEWAY_DLP_MODE"
UPSTREAM_BASE_ENV = "MCP_GATEWAY_UPSTREAM_BASE_URL"
UPSTREAM_API_KEY_ENV = "MCP_GATEWAY_UPSTREAM_API_KEY"
ADMIN_TOKEN_ENV = "MCP_GATEWAY_ADMIN_TOKEN"
ADMIN_TOKEN_FILE_ENV = "MCP_GATEWAY_ADMIN_TOKEN_FILE"
ADMIN_SESSION_COOKIE_NAME = "mcp_gateway_admin_session"
ADMIN_SESSION_TTL_ENV = "MCP_GATEWAY_ADMIN_SESSION_TTL_S"
ADMIN_SESSION_SECURE_ENV = "MCP_GATEWAY_ADMIN_SESSION_SECURE"
SCAN_TTL_ENV = "MCP_GATEWAY_SCAN_TTL_S"
ADMIN_SESSION_SAMESITE = "strict"
UPSTREAM_API_KEY_FILE_ENV = "MCP_GATEWAY_UPSTREAM_API_KEY_FILE"
CONTROL_UPSTREAM_TABLE = "control_upstream"
CONTROL_TOKENS_TABLE = "control_tokens"
CONTROL_POLICY_PROFILE_TABLE = "control_policy_profiles"
DEFAULT_CONTROL_UPSTREAM = {
    "base_url": "",
    "provider": "",
    "models_allowlist": [],
    "status": "unknown",
    "last_tested": "",
    "api_key": "",
}
AUDIT_DEFAULT_LIMIT = 200
AUDIT_MAX_LIMIT = 500
PROFILE_PRESETS = {
    "standard": {"restricted_sinks": set(), "allow_untrusted_with_approvals": False},
    "strict": {
        "restricted_sinks": {"sampling"},
        "allow_untrusted_with_approvals": False,
    },
    "development": {"restricted_sinks": set(), "allow_untrusted_with_approvals": True},
}

_POLICY_BUNDLE_SIGNATURE_CACHE = {"ts": 0.0, "status": "unknown"}
_POLICY_BUNDLE_SIGNATURE_TTL_S = 60


def _env_int(name: str, default: int, *, min_value: int = 1) -> int:
    """環境変数から整数を取得し、無効値はデフォルトへフォールバックする。"""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(
            f"[gateway] {name} is invalid ({raw!r}); using default {default}",
            file=sys.stderr,
        )
        return default
    if value < min_value:
        print(
            f"[gateway] {name} must be >= {min_value} (got {value}); using default {default}",
            file=sys.stderr,
        )
        return default
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    """環境変数から boolean を取得する。"""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _read_secret(env_name: str, file_env_name: str) -> str:
    """環境変数/ファイルのいずれかから secret を取得する。

    ファイル経由（*_FILE 環境変数）を推奨。環境変数直接設定は
    開発環境のみ許可し、本番では Docker/K8s Secrets を使用すべき。
    """
    file_path = os.getenv(file_env_name, "").strip()
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError:
            logger.warning(
                "Secret file not found: %s (set by %s)",
                file_path,
                file_env_name,
            )
            return ""
    # ファイル経由ではなく環境変数から直接読んだ場合は警告
    value = os.getenv(env_name, "").strip()
    if value:
        logger.warning(
            "Secret loaded from env var %s instead of file (%s). "
            "Use file-based secrets in production (Docker/K8s Secrets).",
            env_name,
            file_env_name,
        )
    return value


RATE_LIMIT_WINDOW_SECONDS = _env_int(
    "MCP_GATEWAY_RATE_LIMIT_WINDOW_SECONDS", DEFAULT_RATE_LIMIT_WINDOW_SECONDS
)
RATE_LIMIT_BURST = _env_int("MCP_GATEWAY_RATE_LIMIT_BURST", DEFAULT_RATE_LIMIT_BURST)
REQUEST_TIMEOUT_S = _env_int("MCP_GATEWAY_REQUEST_TIMEOUT_S", DEFAULT_REQUEST_TIMEOUT_S)
RESPONSE_TIMEOUT_S = _env_int(
    "MCP_GATEWAY_RESPONSE_TIMEOUT_S", DEFAULT_RESPONSE_TIMEOUT_S
)
RESPONSE_SIZE_CAP_BYTES = _env_int(
    "MCP_GATEWAY_RESPONSE_SIZE_CAP_BYTES", DEFAULT_RESPONSE_SIZE_CAP_BYTES
)
ADMIN_SESSION_TTL_S = _env_int(ADMIN_SESSION_TTL_ENV, 3600, min_value=60)
ADMIN_SESSION_SECURE = _env_bool(ADMIN_SESSION_SECURE_ENV, default=False)
SCAN_TTL_S = _env_int(SCAN_TTL_ENV, 86400, min_value=60)


def _normalize_profile_name(value: str | None) -> str:
    name = str(value or "").strip().lower()
    return name if name in PROFILE_PRESETS else "standard"


def _policy_profile_from_env() -> dict:
    env_profile = os.getenv("MCP_GATEWAY_POLICY_PROFILE", "").strip().lower()
    profile_name = env_profile if env_profile in PROFILE_PRESETS else "standard"
    preset = PROFILE_PRESETS[profile_name]
    raw = os.getenv("MCP_GATEWAY_RESTRICTED_SINKS", "")
    additions = {v.strip().lower() for v in raw.split(",") if v.strip()}
    additions -= set(DEFAULT_RESTRICTED_SINKS)
    additions -= set(preset["restricted_sinks"])
    allow = os.getenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "").lower() in {
        "1",
        "true",
        "yes",
    }
    restricted_effective = sorted(
        set(DEFAULT_RESTRICTED_SINKS) | preset["restricted_sinks"] | additions
    )
    return {
        "profile_name": profile_name,
        "restricted_sinks_additions": sorted(additions),
        "restricted_sinks_effective": restricted_effective,
        "allow_untrusted_with_approvals": allow,
        "change_reason": "",
        "updated_at": "",
    }


def _policy_profile_config(db_path: str | Path | None = None) -> dict | None:
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    path = Path(db_path)
    if not path.exists():
        return None
    db = sqlite_utils.Database(path)
    _ensure_control_tables(db)
    row = next(db[CONTROL_POLICY_PROFILE_TABLE].rows, None)
    if not row:
        return None
    profile_name = _normalize_profile_name(row.get("profile_name"))
    preset = PROFILE_PRESETS[profile_name]
    raw_additions = row.get("restricted_sinks_additions") or "[]"
    try:
        additions = (
            json.loads(raw_additions)
            if isinstance(raw_additions, str)
            else list(raw_additions)
        )
    except (TypeError, json.JSONDecodeError):
        additions = []
    additions_set = {str(v).lower() for v in additions if str(v).strip()}
    restricted_effective = sorted(
        set(DEFAULT_RESTRICTED_SINKS) | preset["restricted_sinks"] | additions_set
    )
    allow_value = row.get("allow_untrusted_with_approvals")
    if allow_value is None or allow_value == "":
        allow_effective = preset["allow_untrusted_with_approvals"]
    else:
        allow_effective = bool(allow_value)
    return {
        "profile_name": profile_name,
        "restricted_sinks_additions": sorted(additions_set),
        "restricted_sinks_effective": restricted_effective,
        "allow_untrusted_with_approvals": allow_effective,
        "change_reason": str(row.get("change_reason") or ""),
        "updated_at": str(row.get("updated_at") or ""),
    }


def _restricted_sinks(db_path: str | Path | None = None) -> set[str]:
    """環境変数/Control Plane で上書き可能な危険SINK集合を返す。"""
    config = _policy_profile_config(db_path)
    if config is not None:
        return set(config["restricted_sinks_effective"])
    raw = os.getenv("MCP_GATEWAY_RESTRICTED_SINKS", "")
    if raw:
        values = {v.strip().lower() for v in raw.split(",") if v.strip()}
        return values | set(DEFAULT_RESTRICTED_SINKS)
    return set(DEFAULT_RESTRICTED_SINKS)


def _source_tag(entry: dict) -> str:
    """allowlistメタから出所タグを推定する（fail-closedでuntrusted）。"""
    status = str(entry.get("status") or "").lower()
    if status and status != "active":
        return SOURCE_UNTRUSTED
    risk = str(entry.get("risk_level") or "").lower()
    if risk in BLOCKED_RISK_LEVELS:
        return SOURCE_UNTRUSTED
    caps = {str(c).lower() for c in entry.get("capabilities", []) if c}
    if {"sampling", "untrusted_source"} & caps:
        return SOURCE_UNTRUSTED
    return SOURCE_TRUSTED


def _allow_untrusted_with_approvals(db_path: str | Path | None = None) -> bool:
    """環境変数/Control Plane で untrusted→restricted を承認付き許可にするか判定。"""
    config = _policy_profile_config(db_path)
    if config is not None:
        return bool(config["allow_untrusted_with_approvals"])
    return os.getenv("MCP_GATEWAY_ALLOW_UNTRUSTED_WITH_APPROVALS", "").lower() in {
        "1",
        "true",
        "yes",
    }


def _parse_capabilities(raw: str) -> set[str]:
    return {item.strip().lower() for item in re.split(r"[,\\s]+", raw) if item.strip()}


def _has_approval(
    row_id: str,
    *,
    server_id: int | None = None,
    tool_name: str | None = None,
    capabilities: Iterable[str] | None = None,
) -> bool:
    """APPROVALS.md を SSOT ルールに合わせて検証し、id が有効か判定する。"""
    if not row_id:
        return False
    try:
        rules_data = yaml.safe_load(APPROVALS_RULES_PATH.read_text(encoding="utf-8"))
    except Exception:
        rules_data = {}
    ledger_path = rules_data.get("ledger") or "APPROVALS.md"
    ledger = Path(ledger_path)
    if not ledger.is_absolute():
        ledger = APPROVALS_RULES_PATH.parent / ledger
    two_person_rule = bool(rules_data.get("two_person_rule", False))
    forbid_self_approval = bool(rules_data.get("forbid_self_approval", False))
    required_fields = [
        str(f).lower() for f in rules_data.get("required_fields", []) if str(f).strip()
    ]
    now = datetime.now(timezone.utc)
    try:
        content = ledger.read_text(encoding="utf-8")
    except OSError:
        return False

    header: list[str] = []
    approvals: list[dict[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells:
            continue
        if all(set(c) <= {"-"} for c in cells):
            continue
        if not header:
            header = [c.lower() for c in cells]
            continue
        row = {
            header[i]: cells[i] if i < len(cells) else "" for i in range(len(header))
        }
        approvals.append(row)

    target_id = row_id.lower()
    for row in approvals:
        rid = row.get("id", "").lower()
        if rid != target_id:
            continue
        # required fields
        for field in required_fields:
            if not row.get(field, "").strip():
                return False
        status = row.get("status", "").lower()
        if status != "approved":
            return False
        expiry_raw = row.get("expiry_utc", "")
        try:
            expiry = datetime.fromisoformat(expiry_raw.replace("Z", "+00:00"))
        except Exception:
            return False
        if expiry < now:
            return False
        requested_by = row.get("requested_by", "").lower()
        approver = row.get("approver", "").lower()
        if (
            (two_person_rule or forbid_self_approval)
            and requested_by
            and approver
            and requested_by == approver
        ):
            return False
        if server_id is not None:
            row_server_id = str(row.get("server_id", "")).strip()
            if not row_server_id or row_server_id != str(server_id):
                return False
        if tool_name is not None:
            row_tool = str(row.get("tool_name", "")).strip().lower()
            if not row_tool or row_tool != tool_name.lower():
                return False
        if capabilities is not None:
            row_caps_raw = str(row.get("capabilities", "")).strip()
            if not row_caps_raw:
                return False
            row_caps = _parse_capabilities(row_caps_raw)
            if "*" not in row_caps and "all" not in row_caps:
                requested = {
                    str(cap).lower() for cap in capabilities if str(cap).strip()
                }
                if not requested.issubset(row_caps):
                    return False
        return True
    return False


_DLP_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "email"),
]


def _detect_dlp(obj: object, findings: set[str] | None = None) -> set[str]:
    """Very small DLP detector."""
    if findings is None:
        findings = set()
    if isinstance(obj, dict):
        for v in obj.values():
            _detect_dlp(v, findings)
    elif isinstance(obj, list):
        for v in obj:
            _detect_dlp(v, findings)
    elif isinstance(obj, str):
        for pattern, label in _DLP_PATTERNS:
            if pattern.search(obj):
                findings.add(label)
    return findings


def _dlp_mode() -> str:
    raw = os.getenv(DLP_MODE_ENV, "record").strip().lower()
    if raw in {"", "record", "log", "audit"}:
        return "record"
    if raw in {"deny", "block", "enforce"}:
        return "deny"
    if raw in {"off", "false", "0", "disable", "disabled"}:
        return "off"
    print(
        f"[gateway] {DLP_MODE_ENV} is invalid ({raw!r}); using record",
        file=sys.stderr,
    )
    return "record"


def _mcp_streamable_endpoint(base_url: str) -> str | None:
    if not base_url:
        return None
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    path = parsed.path.rstrip("/")
    if not path.endswith("/mcp"):
        return None
    return base_url.rstrip("/")


def _latest_for_server(
    rows: Iterable[dict],
    server_id: int,
    started_key: str,
    ended_key: str,
    status_key: str,
) -> tuple[str, str]:
    """server_id ごとに最新の status を返す。"""
    latest_ts = ""
    latest_status = ""
    for row in rows:
        if row.get("server_id") != server_id:
            continue
        ts = str(row.get(ended_key) or row.get(started_key) or "")
        if ts and ts > latest_ts:
            latest_ts = ts
            latest_status = str(row.get(status_key) or "")
    return latest_ts, latest_status


def _source_info(
    db: sqlite_utils.Database, entry: dict, server_id: int
) -> tuple[str, list[str]]:
    """allowlist/scan/council を突合し、source_tag と理由を返す。"""
    reasons: list[str] = []
    status = str(entry.get("status") or "").lower()
    if status and status != "active":
        reasons.append(f"allowlist_status:{status}")
    risk = str(entry.get("risk_level") or "").lower()
    if risk in BLOCKED_RISK_LEVELS:
        reasons.append(f"risk_level:{risk}")
    caps = {str(c).lower() for c in entry.get("capabilities", []) if c}
    if "sampling" in caps or "untrusted_source" in caps:
        reasons.append("capability:sampling")

    for scan_type in ("static", "mcpsafety"):
        scan_rows = (
            row
            for row in db["scan_results"].rows
            if row.get("server_id") == server_id
            and str(row.get("scan_type") or "").lower() == scan_type
        )
        scan_ts, scan_status = _latest_for_server(
            scan_rows, server_id, "started_at", "ended_at", "status"
        )
        if not scan_ts:
            reasons.append(f"scan_missing:{scan_type}")
            continue
        scan_dt = _parse_iso(scan_ts)
        if scan_dt is None:
            reasons.append(f"scan_ts_invalid:{scan_type}")
        else:
            age_s = (datetime.now(timezone.utc) - scan_dt).total_seconds()
            if age_s > SCAN_TTL_S:
                reasons.append(f"scan_stale:{scan_type}")
        if scan_status:
            scan_status_norm = str(scan_status).lower()
            if scan_status_norm not in {"pass", "ok"}:
                reasons.append(f"scan_status:{scan_status_norm}:{scan_type}")
        else:
            reasons.append(f"scan_status:missing:{scan_type}")
    council_ts = ""
    council_status = ""
    for row in db["council_evaluations"].rows:
        if row.get("server_id") != server_id:
            continue
        ts = str(row.get("created_at") or "")
        if ts and ts > council_ts:
            council_ts = ts
            council_status = str(row.get("decision") or "")
    if council_status and council_status.lower() in {"deny", "quarantine"}:
        reasons.append(f"council_decision:{council_status}")

    tag = SOURCE_UNTRUSTED if reasons else SOURCE_TRUSTED
    return tag, reasons


def reset_rate_limit() -> None:
    """テスト用: レートリミット状態をリセットする。"""
    _RATE_LIMIT_BUCKET.clear()


def enable_rate_limit() -> None:
    """レートリミットを有効化する（テスト制御用）。"""
    global _RATE_LIMIT_ENABLED
    _RATE_LIMIT_ENABLED = True


def disable_rate_limit() -> None:
    """レートリミットを無効化する（テスト制御用）。"""
    global _RATE_LIMIT_ENABLED
    _RATE_LIMIT_ENABLED = False


def _sanitize_text(text: str | None) -> str:
    """ToolTweak 用にテキストをサニタイズする。"""
    if not text:
        return ""
    cleaned = _RE_CONTROL.sub("", text)
    cleaned = _RE_HTML.sub("", cleaned)
    return cleaned[:SANITIZE_MAX_LEN]


def _evidence_path() -> Path:
    """Evidence の出力先を環境変数で上書き可能にする。"""
    override = os.getenv(EVIDENCE_ENV_VAR)
    if override:
        return Path(override)
    return DEFAULT_EVIDENCE_PATH


def _ensure_control_tables(db: sqlite_utils.Database) -> None:
    tables = set(db.table_names())
    if CONTROL_UPSTREAM_TABLE not in tables:
        db[CONTROL_UPSTREAM_TABLE].create(
            {
                "id": int,
                "base_url": str,
                "provider": str,
                "api_key": str,
                "models_allowlist": str,
                "status": str,
                "last_tested": str,
                "created_at": str,
                "updated_at": str,
            },
            pk="id",
        )
    if CONTROL_TOKENS_TABLE not in tables:
        db[CONTROL_TOKENS_TABLE].create(
            {
                "id": int,
                "env_id": int,
                "token_hash": str,
                "token_salt": str,
                "token_prefix": str,
                "token_suffix": str,
                "issued_at": str,
                "expires_at": str,
                "note": str,
                "last_used_at": str,
                "revoked_at": str,
            },
            pk="id",
        )
    if CONTROL_POLICY_PROFILE_TABLE not in tables:
        db[CONTROL_POLICY_PROFILE_TABLE].create(
            {
                "id": int,
                "profile_name": str,
                "restricted_sinks_additions": str,
                "allow_untrusted_with_approvals": int,
                "change_reason": str,
                "created_at": str,
                "updated_at": str,
            },
            pk="id",
        )


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _admin_session_cookie(request: Request) -> str:
    return request.cookies.get(ADMIN_SESSION_COOKIE_NAME, "")


def _admin_session_payload(expires_at: int, nonce: str) -> str:
    return f"{expires_at}.{nonce}"


def _sign_admin_session(token: str, payload: str) -> str:
    return hmac.new(token.encode("utf-8"), payload.encode("utf-8"), sha256).hexdigest()


def _issue_admin_session(token: str) -> tuple[str, str]:
    expires_at = int(time.time()) + ADMIN_SESSION_TTL_S
    nonce = secrets.token_hex(16)
    payload = _admin_session_payload(expires_at, nonce)
    signature = _sign_admin_session(token, payload)
    session_token = f"{payload}.{signature}"
    expires_at_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
    return session_token, expires_at_iso


def _verify_admin_session(cookie_value: str, token: str) -> bool:
    if not cookie_value:
        return False
    parts = cookie_value.split(".", 2)
    if len(parts) != 3:
        return False
    exp_raw, nonce, signature = parts
    try:
        exp = int(exp_raw)
    except ValueError:
        return False
    if exp <= int(time.time()):
        return False
    payload = _admin_session_payload(exp, nonce)
    expected = _sign_admin_session(token, payload)
    return hmac.compare_digest(signature, expected)


def _origin_matches_host(origin: str, host: str) -> bool:
    try:
        origin_host = urlparse(origin).netloc
    except ValueError:
        return False
    if not origin_host:
        return False
    return origin_host == host


def _csrf_guard(request: Request) -> JSONResponse | None:
    method = request.method.upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return None
    origin = request.headers.get("origin") or ""
    host = request.headers.get("host") or request.url.netloc
    if not origin or not host or not _origin_matches_host(origin, host):
        return JSONResponse({"detail": "csrf check failed"}, status_code=403)
    return None


def _admin_auth_guard(request: Request) -> JSONResponse | None:
    token = _read_secret(ADMIN_TOKEN_ENV, ADMIN_TOKEN_FILE_ENV)
    if not token:
        return JSONResponse({"detail": "admin token not configured"}, status_code=503)
    if _verify_admin_session(_admin_session_cookie(request), token):
        if guard := _csrf_guard(request):
            return guard
        return None
    if _get_bearer_token(request) != token:
        return JSONResponse({"detail": "invalid admin token"}, status_code=401)
    return None


def _token_status(row: dict, now: datetime) -> str:
    if row.get("revoked_at"):
        return "revoked"
    expires_at = row.get("expires_at") or ""
    exp = _parse_iso(str(expires_at))
    if expires_at and exp is None:
        return "expired"
    if exp and exp <= now:
        return "expired"
    return "active"


def _control_upstream_summary(row: dict | None) -> dict:
    if not row:
        return {
            "configured": False,
            "base_url": "",
            "provider": "",
            "models_allowlist": [],
            "status": "unknown",
            "last_tested": "",
            "has_api_key": False,
        }
    raw_models = row.get("models_allowlist") or "[]"
    try:
        models = json.loads(raw_models)
    except Exception:
        models = []
    return {
        "configured": bool(row.get("base_url")),
        "base_url": row.get("base_url") or "",
        "provider": row.get("provider") or "",
        "models_allowlist": models,
        "status": row.get("status") or "unknown",
        "last_tested": row.get("last_tested") or "",
        "has_api_key": bool(row.get("api_key")),
    }


def _control_tokens_summary(db: sqlite_utils.Database) -> dict:
    now = datetime.now(timezone.utc)
    counts = {"active": 0, "expired": 0, "revoked": 0}
    for row in db[CONTROL_TOKENS_TABLE].rows:
        status = _token_status(row, now)
        counts[status] = counts.get(status, 0) + 1
    total = sum(counts.values())
    return {"total": total, "by_status": counts}


def _hash_token(token: str, salt: str) -> str:
    return sha256(f"{salt}:{token}".encode("utf-8")).hexdigest()


def _control_tokens_configured(db_path: str | Path | None) -> bool:
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    path = Path(db_path)
    if not path.exists():
        return False
    db = sqlite_utils.Database(path)
    _ensure_control_tables(db)
    return next(db[CONTROL_TOKENS_TABLE].rows, None) is not None


def _validate_control_token(token: str, db_path: str | Path | None) -> dict | None:
    if not token:
        return None
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    path = Path(db_path)
    if not path.exists():
        return None
    db = sqlite_utils.Database(path)
    _ensure_control_tables(db)
    now = datetime.now(timezone.utc)
    for row in db[CONTROL_TOKENS_TABLE].rows:
        if _token_status(row, now) != "active":
            continue
        salt = str(row.get("token_salt") or "")
        token_hash = str(row.get("token_hash") or "")
        if not salt or not token_hash:
            continue
        if _hash_token(token, salt) == token_hash:
            db[CONTROL_TOKENS_TABLE].update(
                row["id"], {"last_used_at": now.isoformat()}
            )
            return row
    return None


def _proxy_tokens() -> set[str]:
    raw = ",".join(os.getenv(name, "") for name in (PROXY_TOKEN_ENV, PROXY_TOKENS_ENV))
    return {t.strip() for t in raw.split(",") if t.strip()}


def _load_control_upstream(
    db_path: str | Path | None = None,
) -> dict[str, str | list[str]] | None:
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    path = Path(db_path)
    if not path.exists():
        return None
    db = sqlite_utils.Database(path)
    _ensure_control_tables(db)
    row = next(db[CONTROL_UPSTREAM_TABLE].rows, None)
    if not row:
        return None
    raw_models = row.get("models_allowlist") or "[]"
    try:
        models = (
            json.loads(raw_models) if isinstance(raw_models, str) else list(raw_models)
        )
    except (TypeError, json.JSONDecodeError):
        models = []
    return {
        "base_url": str(row.get("base_url") or ""),
        "provider": str(row.get("provider") or ""),
        "api_key": str(row.get("api_key") or ""),
        "models_allowlist": [str(m) for m in models if str(m).strip()],
    }


def _proxy_models() -> list[str]:
    """プロキシ許可モデルリストを取得する。

    空設定時は fail-closed（全モデル拒否）。
    明示的に許可するモデルを設定すること。
    """
    config = _load_control_upstream()
    if config is not None:
        return list(config["models_allowlist"])
    raw = os.getenv(PROXY_MODELS_ENV, "")
    if raw:
        return [t.strip() for t in raw.split(",") if t.strip()]
    # fail-closed: 明示的な設定がない場合は全モデル拒否
    return []


def _get_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _client_auth_info(
    request: Request, db_path: str | Path | None = None
) -> tuple[bool, int, str]:
    tokens = _proxy_tokens()
    token = _get_bearer_token(request)
    if token and token in tokens:
        return True, 200, ""
    if _validate_control_token(token, db_path):
        return True, 200, ""
    if not tokens and not _control_tokens_configured(db_path):
        return False, 503, "proxy token not configured"
    return False, 401, "invalid or missing token"


def _proxy_auth_guard(
    request: Request, *, path: str, db_path: str | Path | None = None
) -> JSONResponse | None:
    allowed, status, message = _client_auth_info(request, db_path)
    if allowed:
        return None
    if status == 503:
        return _openai_error(
            503,
            message,
            error_type="config_error",
            code="proxy_token_missing",
            event_payload={"path": path},
            request=request,
        )
    return _openai_error(
        401,
        message,
        error_type="authentication_error",
        code="invalid_token",
        event_payload={"path": path},
        request=request,
    )


def _upstream_config() -> tuple[str, str]:
    config = _load_control_upstream()
    if config is not None:
        base = str(config["base_url"]).strip()
        key = str(config["api_key"]).strip()
        return base, key
    base = os.getenv(UPSTREAM_BASE_ENV, "").strip()
    key = _read_secret(UPSTREAM_API_KEY_ENV, UPSTREAM_API_KEY_FILE_ENV)
    return base, key


def _emit_proxy_event(event: str, payload: dict) -> str:
    return evidence.append({"event": event, **payload}, path=_evidence_path())


def _get_trace_id(request: Request | None) -> str:
    """リクエストヘッダーからtrace_idを取得、またはUUIDを生成する。"""
    if request is not None:
        trace_id = request.headers.get("x-request-id", "").strip()
        if trace_id:
            return trace_id
    return str(uuid.uuid4())


def _openai_error(
    status_code: int,
    message: str,
    *,
    error_type: str = "invalid_request_error",
    code: str = "",
    event_payload: dict | None = None,
    request: Request | None = None,
) -> JSONResponse:
    trace_id = _get_trace_id(request)
    event = {
        "actor": "WORK",
        "decision": "deny",
        "reason": message,
        "reason_code": code,
        "trace_id": trace_id,
        **(event_payload or {}),
    }
    evidence_id = _emit_proxy_event("openai_proxy_block", event)
    resp = JSONResponse(
        {
            "error": {"message": message, "type": error_type, "code": code},
            "evidence_id": evidence_id,
            "trace_id": trace_id,
        },
        status_code=status_code,
    )
    resp.headers.update(
        {
            "X-MCP-Evidence-Id": evidence_id,
            "X-MCP-Block-Reason": message,
            "X-MCP-Trace-Id": trace_id,
        }
    )
    return resp


def _consume_token() -> Response | None:
    """簡易レートリミット: window 内のリクエスト数を制限する。429 Response を返す。"""
    if not _RATE_LIMIT_ENABLED:
        return None
    now = time.monotonic()
    while (
        _RATE_LIMIT_BUCKET and now - _RATE_LIMIT_BUCKET[0] > RATE_LIMIT_WINDOW_SECONDS
    ):
        _RATE_LIMIT_BUCKET.popleft()
    if len(_RATE_LIMIT_BUCKET) >= RATE_LIMIT_BURST:
        return Response(status_code=429, content="rate limit exceeded")
    _RATE_LIMIT_BUCKET.append(now)
    return None


def _emit_gateway_update(
    evidence_path: str | Path = "observability/policy/ci_evidence.jsonl",
) -> None:
    """gateway 設定スナップショットを Evidence に記録する。"""
    config = {
        "rate_limit_window_s": RATE_LIMIT_WINDOW_SECONDS,
        "rate_limit_burst": RATE_LIMIT_BURST,
        "timeout_request_s": REQUEST_TIMEOUT_S,
        "timeout_response_s": RESPONSE_TIMEOUT_S,
        "response_size_cap_bytes": RESPONSE_SIZE_CAP_BYTES,
        "sanitization": "tool_tweak",
        "sanitization_enabled": True,
    }
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    DIFF_DIR.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    snapshot_path = SNAPSHOT_DIR / f"gateway_config_{now}.json"
    payload = json.dumps(config, sort_keys=True)
    snapshot_path.write_text(payload, encoding="utf-8", newline="\n")
    snapshot_sha = sha256(payload.encode("utf-8")).hexdigest()

    # diff_sha: 前回スナップショットとの差分ハッシュ（存在しない場合は空文字）
    prev_files = sorted(SNAPSHOT_DIR.glob("gateway_config_*.json"))
    diff_sha = ""
    diff_path: Path | None = None
    if len(prev_files) >= 2:
        # 最新（今回）と直前のファイルを比較
        prev_path = prev_files[-2]
        prev_payload = prev_path.read_text(encoding="utf-8")
        diff_json = {
            "previous": json.loads(prev_payload),
            "current": json.loads(payload),
        }
        diff_str = json.dumps(diff_json, sort_keys=True)
        diff_sha = sha256(diff_str.encode("utf-8")).hexdigest()
        diff_path = DIFF_DIR / f"gateway_diff_{now}.json"
        diff_path.write_text(diff_str, encoding="utf-8", newline="\n")

    evidence.append(
        {
            "event": "gateway_update",
            "config": config,
            "snapshot_sha": snapshot_sha,
            "snapshot_path": str(snapshot_path),
            "diff_sha": diff_sha,
            "diff_path": str(diff_path) if diff_path else "",
        },
        path=evidence_path,
    )


@app.middleware("http")
async def gateway_guard(request, call_next):
    """共通ガード: レートリミット・タイムアウト・レスポンスサイズ制限を適用する。"""
    rate_limit_resp = _consume_token()
    if rate_limit_resp:
        return rate_limit_resp
    try:
        response = await asyncio.wait_for(call_next(request), timeout=REQUEST_TIMEOUT_S)
    except asyncio.TimeoutError:
        return Response(status_code=504, content="request timeout")

    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > RESPONSE_SIZE_CAP_BYTES:
                evidence.append(
                    {
                        "event": "gateway_response_block",
                        "reason": "response_size_cap",
                        "size": int(content_length),
                        "cap": RESPONSE_SIZE_CAP_BYTES,
                    }
                )
                return Response(status_code=413, content="response too large")
        except ValueError:
            # content-length が不正なら後続のボディ判定へフォールバック
            pass

    body_bytes = b""
    if hasattr(response, "body") and response.body is not None:
        body_bytes = (
            response.body
            if isinstance(response.body, (bytes, bytearray))
            else str(response.body).encode("utf-8")
        )

    if body_bytes and len(body_bytes) > RESPONSE_SIZE_CAP_BYTES:
        evidence.append(
            {
                "event": "gateway_response_block",
                "reason": "response_size_cap",
                "size": len(body_bytes),
                "cap": RESPONSE_SIZE_CAP_BYTES,
            }
        )
        return Response(status_code=413, content="response too large")

    return response


def _allowlist_entry_by_server(entries: list[dict], server_id: int) -> dict | None:
    """サーバ ID から allowlist エントリを取得する。"""
    for entry in entries:
        if entry.get("server_id") == server_id:
            return entry
    return None


def _evaluate_manifest_guard(entry: dict) -> tuple[bool, str, str, str]:
    """tools_manifest_hash の整合を write-less で確認する。"""
    expected_hash = str(entry.get("tools_manifest_hash") or "")
    observed_hash = registry.compute_tools_manifest_hash(
        entry.get("tools_exposed") or []
    )
    if not expected_hash:
        return False, expected_hash, observed_hash, "uninitialized"
    if expected_hash != observed_hash:
        return False, expected_hash, observed_hash, "drift"
    return True, expected_hash, observed_hash, ""


def _emit_manifest_guard_event(
    entry: dict, expected_hash: str, observed_hash: str, reason: str
) -> None:
    evidence.append(
        {
            "event": "tool_manifest_guard",
            "decision": "deny",
            "reason": reason,
            "server_id": entry.get("server_id"),
            "allowlist_id": entry.get("id"),
            "expected_hash": expected_hash,
            "observed_hash": observed_hash,
            "tool_count": len(entry.get("tools_exposed") or []),
        },
        path=_evidence_path(),
    )


def _block_reason(entry: dict) -> dict | None:
    """risk_level/capabilities に基づきブロック理由を返す。許可の場合 None。"""
    risk = str(entry.get("risk_level") or "").lower()
    if risk in BLOCKED_RISK_LEVELS:
        return {"reason": "risk_level_blocked", "risk_level": risk}
    caps = {str(c).lower() for c in entry.get("capabilities", []) if c}
    blocked_caps = sorted(caps & BLOCKED_CAPABILITIES)
    if blocked_caps:
        return {"reason": "capability_blocked", "capabilities": blocked_caps}
    return None


def _block_reason_for_run(entry: dict, tool_caps: set[str]) -> dict | None:
    """run 経路では tool 側の制御に任せるため、allowlist 側のみでブロック判定する。"""
    risk = str(entry.get("risk_level") or "").lower()
    if risk in BLOCKED_RISK_LEVELS:
        return {"reason": "risk_level_blocked", "risk_level": risk}
    entry_caps = {str(c).lower() for c in entry.get("capabilities", []) if c}
    blocked_caps = sorted((entry_caps - tool_caps) & BLOCKED_CAPABILITIES)
    if blocked_caps:
        return {"reason": "capability_blocked", "capabilities": blocked_caps}
    return None


def _load_findings(row: dict) -> list[dict]:
    """scan_results 行から findings を JSON として読み込む。失敗時は空リスト。"""
    raw = str(row.get("findings") or "")
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def _duration_seconds(started: str | None, ended: str | None) -> int:
    """開始/終了時刻から秒を算出する。パース不能時は 0。"""
    if not started or not ended:
        return 0
    try:
        s_dt = datetime.fromisoformat(started)
        e_dt = datetime.fromisoformat(ended)
    except ValueError:
        return 0
    delta = (e_dt - s_dt).total_seconds()
    return int(delta) if delta > 0 else 0


def _count_by(findings: list[dict], key: str) -> dict[str, int]:
    """指定キーで件数を集計する。"""
    counts: dict[str, int] = {}
    for item in findings:
        val = str(item.get(key) or "").strip()
        if not val:
            continue
        counts[val] = counts.get(val, 0) + 1
    return counts


def _scan_summary(row: dict, server_label: str, findings: list[dict]) -> dict:
    """スキャン1件分の一覧用サマリを生成する。"""
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for sev, cnt in _count_by(findings, "severity").items():
        key = sev.lower()
        if key in severity_counts:
            severity_counts[key] += cnt
    owasp_counts = _count_by(findings, "owasp_llm_code")
    return {
        "id": row.get("run_id"),
        "server_id": row.get("server_id"),
        "startedAt": row.get("started_at"),
        "environment": server_label,
        "actor": row.get("actor") or "",
        "profile": row.get("scan_type") or "",
        "status": row.get("status") or "",
        "durationSeconds": _duration_seconds(
            row.get("started_at"), row.get("ended_at")
        ),
        "severity_counts": severity_counts,
        "owasp_counts": owasp_counts,
    }


def _allowlist_summary(
    entry: dict, server: dict, last_scan_ts: str | None = None
) -> dict:
    """AllowList 1件分の一覧用サマリを生成する。"""
    return {
        "id": entry.get("id"),
        "server_id": entry.get("server_id"),
        "name": server.get("name") or "",
        "base_url": server.get("base_url") or "",
        "status": entry.get("status") or "",
        "risk_level": entry.get("risk_level") or "",
        "capabilities": entry.get("capabilities") or [],
        "registered_at": entry.get("created_at") or "",
        "last_scan_ts": last_scan_ts or "",
        "source_tag": entry.get("source_tag") or "",
        "source_reasons": entry.get("source_reasons") or [],
    }


def _latest_iso(values: Iterable[str | None]) -> str:
    """ISO8601 文字列の中で最新を返す（無効値はスキップ）。"""
    latest = ""
    for raw in values:
        if not raw:
            continue
        value = str(raw)
        try:
            # validate format; ValueError を避けつつ辞書順比較
            datetime.fromisoformat(value)
        except ValueError:
            continue
        if value > latest:
            latest = value
    return latest


def _council_decision_counts(
    db: sqlite_utils.Database,
) -> tuple[dict[str, int], str]:
    """council_evaluations の最新決定（server_id 単位）を集計する。"""
    latest: dict[int, tuple[str, str]] = {}
    for row in db["council_evaluations"].rows:
        server_id = row.get("server_id")
        if server_id is None:
            continue
        decision = str(row.get("decision") or "").lower()
        created_at = str(row.get("created_at") or "")
        prev = latest.get(server_id)
        if prev is None or (created_at and created_at > prev[0]):
            latest[server_id] = (created_at, decision)

    counts = {"allow": 0, "deny": 0, "quarantine": 0}
    last_ts = ""
    for created_at, decision in latest.values():
        if created_at and created_at > last_ts:
            last_ts = created_at
        if decision in counts:
            counts[decision] += 1
    return counts, last_ts


def _shadow_audit_chain_ok() -> bool:
    """Shadow Audit のハッシュチェーン検証を行う（missing は True 扱い）。"""
    try:
        from scripts import shadow_audit_emit
    except Exception:
        return False
    try:
        return bool(shadow_audit_emit.verify_chain())
    except Exception:
        return False


def _policy_bundle_hash_ok(path: Path = POLICY_BUNDLE_PATH) -> bool:
    """policy_bundle.tar が存在し、ゼロ長でないことを確認する（legacy name）。"""
    try:
        return path.exists() and path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _policy_bundle_sha256(path: Path = POLICY_BUNDLE_PATH) -> str:
    """policy_bundle.tar の SHA256 を返す（存在しない/読めない場合は空文字）。"""
    if not _policy_bundle_hash_ok(path):
        return ""
    try:
        h = sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _verify_policy_bundle_signature() -> str:
    """cosign verify-blob で policy_bundle の署名検証を試み、ステータス文字列を返す。"""
    if not _policy_bundle_hash_ok(POLICY_BUNDLE_PATH):
        return "skip:bundle_missing"
    if not POLICY_BUNDLE_SIG_PATH.exists():
        return "skip:sig_missing"
    if not shutil.which("cosign"):
        return "skip:cosign_missing"
    key = os.environ.get("COSIGN_KEY_VERIFY", "")
    if not key:
        return "skip:key_missing"
    try:
        result = subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--key",
                key,
                "--signature",
                str(POLICY_BUNDLE_SIG_PATH),
                str(POLICY_BUNDLE_PATH),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "error:timeout"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error:exception:{type(exc).__name__}"
    return "verified" if result.returncode == 0 else f"failed:{result.returncode}"


def _policy_bundle_signature_status() -> str:
    """署名検証ステータスを返す（短時間キャッシュ付き）。"""
    now = time.monotonic()
    cached_at = float(_POLICY_BUNDLE_SIGNATURE_CACHE.get("ts", 0.0))
    cached_status = str(_POLICY_BUNDLE_SIGNATURE_CACHE.get("status", "unknown"))
    if cached_status != "unknown" and now - cached_at < _POLICY_BUNDLE_SIGNATURE_TTL_S:
        return cached_status
    status = _verify_policy_bundle_signature()
    _POLICY_BUNDLE_SIGNATURE_CACHE["ts"] = now
    _POLICY_BUNDLE_SIGNATURE_CACHE["status"] = status
    return status


def _infer_upstream_provider(base_url: str, provider: str) -> str:
    if provider:
        return provider.lower()
    lowered = base_url.lower()
    if "generativelanguage.googleapis.com" in lowered:
        return "gemini"
    return ""


def _build_upstream_test_request(
    base_url: str, provider: str, api_key: str
) -> tuple[str, dict | None]:
    base = base_url.rstrip("/")
    if provider == "gemini":
        if not api_key:
            raise ValueError("upstream api key is required for gemini")
        if base.endswith("/v1beta"):
            url = f"{base}/models?key={api_key}"
        else:
            url = f"{base}/v1beta/models?key={api_key}"
        return url, None
    if base.endswith("/v1"):
        url = f"{base}/models"
    else:
        url = f"{base}/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
    return url, headers


def _redact_url_query_params(url: str, param_names: set[str]) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    if not parsed.query:
        return url
    query = parse_qsl(parsed.query, keep_blank_values=True)
    redacted: list[tuple[str, str]] = []
    changed = False
    for key, value in query:
        if key.lower() in param_names:
            redacted.append((key, "REDACTED"))
            changed = True
        else:
            redacted.append((key, value))
    if not changed:
        return url
    new_query = urlencode(redacted, doseq=True)
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
    )


@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        await asyncio.to_thread(
            evidence.append,
            {
                "event": "health_check",
                "status": "ok",
                "path": "/health",
            },
            _evidence_path(),
        )
    except Exception as exc:  # noqa: BLE001 - ヘルス応答を優先
        print(f"[gateway] failed to append health evidence: {exc}", file=sys.stderr)
    return {"status": "ok"}


@app.get("/v1/models")
async def list_proxy_models(request: Request):
    path = "/v1/models"
    guard = _proxy_auth_guard(request, path=path)
    if guard:
        return guard
    models = _proxy_models()
    created = int(time.time())
    data = [
        {
            "id": model_id,
            "object": "model",
            "created": created,
            "owned_by": "mcp-gateway",
        }
        for model_id in models
    ]
    evidence_id = _emit_proxy_event(
        "openai_proxy_models",
        {
            "actor": "WORK",
            "decision": "allow",
            "path": path,
            "model_count": len(data),
        },
    )
    resp = JSONResponse({"object": "list", "data": data})
    resp.headers["X-MCP-Evidence-Id"] = evidence_id
    return resp


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    path = "/v1/chat/completions"
    guard = _proxy_auth_guard(request, path=path)
    if guard:
        return guard
    try:
        payload = await request.json()
    except Exception:
        return _openai_error(400, "invalid json", code="invalid_json", request=request)
    if not isinstance(payload, dict):
        return _openai_error(
            400, "invalid request body", code="invalid_body", request=request
        )
    model = payload.get("model")
    messages = payload.get("messages")
    if not isinstance(model, str) or not isinstance(messages, list):
        return _openai_error(
            400,
            "model and messages are required",
            code="missing_fields",
            request=request,
        )

    # Sanitize user messages (F-001: prompt injection defense)
    from .sanitizer import ContextSanitizer, SanitizationLevel

    _sanitizer = ContextSanitizer(level=SanitizationLevel.STANDARD)
    threats_found = 0
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                result = _sanitizer.sanitize(content)
                if not result.is_safe:
                    threats_found += result.threat_count
                    msg["content"] = result.sanitized_text
    if threats_found > 0:
        evidence.append(
            {
                "event": "prompt_sanitized",
                "path": path,
                "threats_found": threats_found,
                "model": model,
            }
        )

    allowed_models = _proxy_models()
    if model not in allowed_models:
        return _openai_error(
            403,
            "model not allowed",
            error_type="invalid_request_error",
            code="model_not_allowed",
            event_payload={
                "path": path,
                "model": model,
                "allowed_models": allowed_models,
            },
            request=request,
        )
    if payload.get("stream") is True:
        return _openai_error(
            400,
            "streaming not supported",
            code="streaming_not_supported",
            request=request,
        )
    upstream_base, upstream_key = _upstream_config()
    if not upstream_base or not upstream_key:
        return _openai_error(
            503,
            "upstream not configured",
            error_type="config_error",
            code="upstream_missing",
            request=request,
        )
    upstream_url = f"{upstream_base.rstrip('/')}/v1/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
            upstream_resp = await client.post(
                upstream_url,
                json=payload,
                headers={"Authorization": f"Bearer {upstream_key}"},
            )
    except httpx.TimeoutException:
        return _openai_error(
            504,
            "upstream timeout",
            error_type="upstream_error",
            code="upstream_timeout",
            request=request,
        )
    except httpx.RequestError as exc:
        return _openai_error(
            502,
            f"upstream error: {type(exc).__name__}",
            error_type="upstream_error",
            code="upstream_error",
            request=request,
        )

    if upstream_resp.status_code >= 400:
        return _openai_error(
            502,
            f"upstream error ({upstream_resp.status_code})",
            error_type="upstream_error",
            code=f"upstream_{upstream_resp.status_code}",
            request=request,
        )

    try:
        upstream_body = upstream_resp.json()
    except ValueError:
        return _openai_error(
            502,
            "invalid upstream json",
            error_type="upstream_error",
            code="invalid_json",
            request=request,
        )

    dlp_findings = _detect_dlp(upstream_body)
    if dlp_findings:
        dlp_mode = _dlp_mode()
        dlp_event_id = ""
        if dlp_mode != "off":
            dlp_event_id = evidence.append(
                {
                    "event": "proxy_dlp_detected",
                    "actor": "WORK",
                    "model": model,
                    "findings": sorted(dlp_findings),
                    "decision": "deny" if dlp_mode == "deny" else "record",
                    "mode": dlp_mode,
                },
                path=_evidence_path(),
            )
        if dlp_mode == "deny":
            return _openai_error(
                403,
                "dlp detected",
                error_type="policy_error",
                code="dlp_detected",
                event_payload={
                    "path": path,
                    "model": model,
                    "dlp_event_id": dlp_event_id,
                    "dlp_findings": sorted(dlp_findings),
                },
                request=request,
            )

    evidence_id = _emit_proxy_event(
        "openai_proxy_chat",
        {
            "actor": "WORK",
            "decision": "allow",
            "path": path,
            "model": model,
            "upstream_status": upstream_resp.status_code,
        },
    )
    resp = JSONResponse(upstream_body, status_code=upstream_resp.status_code)
    resp.headers["X-MCP-Evidence-Id"] = evidence_id
    return resp


def _sanitize_tool_entry(tool: dict) -> dict:
    sanitized = dict(tool)
    name = _sanitize_text(tool.get("name"))
    desc = _sanitize_text(tool.get("description"))
    if name:
        sanitized["name"] = name
    if desc:
        sanitized["description"] = desc
    return sanitized


def _iter_allowlisted_tools(db: sqlite_utils.Database):
    entries = registry.get_allowlist_entries(db, repair=False)
    for entry in entries:
        allowed, expected_hash, observed_hash, reason = _evaluate_manifest_guard(entry)
        if not allowed:
            _emit_manifest_guard_event(entry, expected_hash, observed_hash, reason)
            continue
        if _block_reason(entry):
            continue
        source_tag, _ = _source_info(db, entry, entry["server_id"])
        if source_tag != SOURCE_TRUSTED:
            continue
        for tool in entry["tools_exposed"]:
            yield entry, _sanitize_tool_entry(tool)


@app.get("/tools")
async def list_tools(request: Request, db_path: str = str(DEFAULT_DB_PATH)):
    """
    List all tools from active allowlist entries.

    Returns:
        List of tools from active allowlist servers
    """
    allowed, status, message = _client_auth_info(request, db_path)
    if not allowed:
        return JSONResponse({"detail": message}, status_code=status)
    if not Path(db_path).exists():
        return []

    db = sqlite_utils.Database(db_path)
    return [tool for _, tool in _iter_allowlisted_tools(db)]


@app.post("/mcp")
async def mcp_gateway(
    request: Request, payload: dict, db_path: str = str(DEFAULT_DB_PATH)
):
    req_id = payload.get("id") if isinstance(payload, dict) else None

    def _rpc_error(code: int, message: str, *, data=None):
        body = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }
        if data is not None:
            body["error"]["data"] = data
        return JSONResponse(body)

    def _rpc_result(result: object):
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})

    if not isinstance(payload, dict):
        return _rpc_error(-32600, "invalid request")
    if payload.get("jsonrpc") != "2.0":
        return _rpc_error(-32600, "invalid request")
    method = payload.get("method")
    if not isinstance(method, str):
        return _rpc_error(-32600, "invalid request")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        return _rpc_error(-32602, "invalid params")

    allowed, status, message = _client_auth_info(request, db_path)
    if not allowed:
        return _rpc_error(status, message)

    if not Path(db_path).exists():
        if method in {"tools/list", "tools/describe"}:
            return _rpc_result([])
        return _rpc_error(404, "server not found")

    db = sqlite_utils.Database(db_path)

    if method == "tools/list":
        tools = []
        for entry, tool in _iter_allowlisted_tools(db):
            item = dict(tool)
            item["server_id"] = entry.get("server_id")
            tools.append(item)
        return _rpc_result(tools)

    if method == "tools/describe":
        names = []
        if isinstance(params.get("name"), str):
            names = [params["name"]]
        elif isinstance(params.get("names"), list):
            names = [n for n in params["names"] if isinstance(n, str)]
        if not names:
            return _rpc_error(-32602, "invalid params")
        server_id = params.get("server_id")
        if server_id is not None and not isinstance(server_id, int):
            return _rpc_error(-32602, "invalid params")
        name_set = set(names)
        tools = []
        for entry, tool in _iter_allowlisted_tools(db):
            if server_id is not None and entry.get("server_id") != server_id:
                continue
            if tool.get("name") not in name_set:
                continue
            item = dict(tool)
            item["server_id"] = entry.get("server_id")
            tools.append(item)
        return _rpc_result(tools)

    if method == "tools/call":
        tool_name = params.get("name") or params.get("tool_name")
        if not isinstance(tool_name, str):
            return _rpc_error(-32602, "invalid params")
        arguments = params.get("arguments") or params.get("args") or {}
        if not isinstance(arguments, dict):
            return _rpc_error(-32602, "invalid params")
        server_id = params.get("server_id")
        if server_id is not None and not isinstance(server_id, int):
            return _rpc_error(-32602, "invalid params")
        if server_id is None:
            matches = [
                entry.get("server_id")
                for entry, tool in _iter_allowlisted_tools(db)
                if tool.get("name") == tool_name
            ]
            unique_ids = sorted({sid for sid in matches if isinstance(sid, int)})
            if len(unique_ids) == 1:
                server_id = unique_ids[0]
            else:
                return _rpc_error(400, "server_id required")
        run_payload = {
            "server_id": server_id,
            "tool_name": tool_name,
            "arguments": arguments,
        }
        if "approvals_row_id" in params:
            run_payload["approvals_row_id"] = params.get("approvals_row_id")
        run_resp = await run_tool(run_payload, request=request, db_path=db_path)
        try:
            body = json.loads(run_resp.body.decode("utf-8"))
        except Exception:
            body = {"error": "invalid response"}
        if run_resp.status_code >= 400:
            return _rpc_error(
                run_resp.status_code,
                body.get("error", "error"),
                data=body,
            )
        resp = _rpc_result(body)
        source_tag = run_resp.headers.get("X-MCP-Source-Tag")
        source_reason = run_resp.headers.get("X-MCP-Source-Reason")
        if source_tag:
            resp.headers["X-MCP-Source-Tag"] = source_tag
        if source_reason:
            resp.headers["X-MCP-Source-Reason"] = source_reason
        return resp

    return _rpc_error(-32601, "method not found")


@app.post("/run")
async def run_tool(
    payload: dict, request: Request, db_path: str = str(DEFAULT_DB_PATH)
):
    """
    AllowList に載っている server/tool のみ背後 MCP サーバへ委譲する /run 相当のプロキシ。
    """

    def _error(status_code: int, message: str, *, status: str = "error", extra=None):
        body = {"status": status, "error": message}
        if extra:
            body.update(extra)
        return JSONResponse(body, status_code=status_code)

    allowed, status_code, message = _client_auth_info(request, db_path)
    if not allowed:
        if status_code == 503:
            return _error(status_code, message)
        return _error(status_code, message, status="forbidden")
    if not Path(db_path).exists():
        return _error(404, "server not found")
    server_id = payload.get("server_id")
    tool_name = payload.get("tool_name")
    arguments = payload.get("arguments", {})
    if not isinstance(server_id, int) or not isinstance(tool_name, str):
        return _error(400, "invalid request")

    db = sqlite_utils.Database(db_path)
    server = registry.get_server(db, server_id)
    if not server:
        return _error(404, "server not found")

    entries = registry.get_allowlist_entries(db, repair=False)
    entry = _allowlist_entry_by_server(entries, server_id)
    if not entry:
        return _error(
            403,
            "tool not allowed",
            status="forbidden",
            extra={"server_id": server_id, "tool_name": tool_name},
        )
    allowed, expected_hash, observed_hash, reason = _evaluate_manifest_guard(entry)
    if not allowed:
        _emit_manifest_guard_event(entry, expected_hash, observed_hash, reason)
        return _error(
            403,
            "tool not allowed",
            status="forbidden",
            extra={"server_id": server_id, "tool_name": tool_name},
        )
    tools = entry["tools_exposed"]
    tool_names = {t.get("name") for t in tools}
    if tool_name not in tool_names:
        return _error(
            403,
            "tool not allowed",
            status="forbidden",
            extra={"server_id": server_id, "tool_name": tool_name},
        )

    # SOURCE/SINK 制御: allowlistメタから出所を推定し、危険SINKはデフォルトdeny
    tool_caps = set()
    for t in tools:
        if t.get("name") == tool_name:
            tool_caps = {str(c).lower() for c in t.get("capabilities", []) if c}
            break
    blocked = _block_reason_for_run(entry, tool_caps)
    if blocked:
        return _error(
            403,
            "tool blocked by policy",
            status="forbidden",
            extra={"server_id": server_id, "tool_name": tool_name, **blocked},
        )

    entry_caps = {str(c).lower() for c in entry.get("capabilities", []) if c}
    combined_caps = tool_caps | entry_caps
    restricted_sinks = _restricted_sinks(db_path)
    restricted_caps = sorted(combined_caps & restricted_sinks)
    approvals_row_id = str(payload.get("approvals_row_id") or "").strip()
    allow_with_approvals = _allow_untrusted_with_approvals(db_path)
    source_tag, source_reasons = _source_info(db, entry, server_id)
    approval_ok = (
        restricted_caps
        and allow_with_approvals
        and approvals_row_id
        and _has_approval(
            approvals_row_id,
            server_id=server_id,
            tool_name=tool_name,
            capabilities=restricted_caps,
        )
    )
    if source_tag == SOURCE_UNTRUSTED and not approval_ok:
        reason = (
            "untrusted_to_restricted_sink" if restricted_caps else "source_untrusted"
        )
        evidence.append(
            {
                "event": "source_sink_check",
                "actor": "WORK",
                "source_tag": source_tag,
                "source_reasons": source_reasons,
                "server_id": server_id,
                "tool_name": tool_name,
                "capabilities": sorted(combined_caps),
                "decision": "deny",
                "reason": reason,
            },
            _evidence_path(),
        )
        return _error(
            403,
            "untrusted source",
            status="forbidden",
            extra={
                "server_id": server_id,
                "tool_name": tool_name,
                "source_reasons": source_reasons,
            },
        )
    if source_tag == SOURCE_UNTRUSTED and restricted_caps and approval_ok:
        evidence.append(
            {
                "event": "source_sink_check",
                "actor": "WORK",
                "source_tag": source_tag,
                "source_reasons": source_reasons,
                "server_id": server_id,
                "tool_name": tool_name,
                "capabilities": sorted(combined_caps),
                "decision": "allow_with_approval",
                "approvals_row_id": approvals_row_id,
                "reason": "untrusted_to_restricted_sink_with_approval",
            },
            _evidence_path(),
        )

    base_url = str(server.get("base_url") or "").strip()
    mcp_endpoint = _mcp_streamable_endpoint(base_url)
    if mcp_endpoint:
        upstream_url = mcp_endpoint
        upstream_payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    else:
        upstream_url = f"{base_url.rstrip('/')}/run"
        upstream_payload = {"tool_name": tool_name, "arguments": arguments}
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
            upstream_resp = await client.post(
                upstream_url,
                json=upstream_payload,
            )
    except httpx.TimeoutException:
        return _error(
            504,
            "upstream timeout",
            extra={"server_id": server_id, "tool_name": tool_name},
        )
    except httpx.HTTPError as exc:
        return _error(
            502,
            f"upstream error: {type(exc).__name__}",
            extra={"server_id": server_id, "tool_name": tool_name},
        )

    try:
        upstream_body = upstream_resp.json()
    except ValueError:
        upstream_body = {"error": "invalid upstream json"}

    if upstream_resp.status_code >= 400:
        return _error(
            502,
            "upstream error",
            extra={
                "server_id": server_id,
                "tool_name": tool_name,
                "result": upstream_body,
            },
        )

    if mcp_endpoint:
        if not isinstance(upstream_body, dict):
            return _error(
                502,
                "invalid mcp response",
                extra={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "result": upstream_body,
                },
            )
        if "error" in upstream_body:
            return _error(
                502,
                "upstream error",
                extra={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "result": upstream_body,
                },
            )
        if "result" not in upstream_body:
            return _error(
                502,
                "invalid mcp response",
                extra={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "result": upstream_body,
                },
            )
        upstream_body = upstream_body["result"]

    dlp_findings = _detect_dlp(upstream_body)
    if dlp_findings:
        dlp_mode = _dlp_mode()
        dlp_event_id = ""
        if dlp_mode != "off":
            dlp_event_id = evidence.append(
                {
                    "event": "dlp_detected",
                    "actor": "WORK",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "findings": sorted(dlp_findings),
                    "decision": "deny" if dlp_mode == "deny" else "record",
                    "mode": dlp_mode,
                },
                _evidence_path(),
            )
        if dlp_mode == "deny":
            return _error(
                403,
                "dlp detected",
                status="forbidden",
                extra={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "dlp_findings": sorted(dlp_findings),
                    "evidence_id": dlp_event_id,
                },
            )

    resp = JSONResponse(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "status": "ok",
            "result": upstream_body,
            "source_tag": source_tag,
            "source_reasons": source_reasons,
        }
    )
    resp.headers["X-MCP-Source-Tag"] = source_tag
    if source_reasons:
        resp.headers["X-MCP-Source-Reason"] = ";".join(source_reasons)
    return resp


@app.get("/api/scans")
async def list_scans(db_path: str = str(DEFAULT_DB_PATH)):
    """スキャン一覧を JSON で返す。DB 不在時は空配列。"""
    if not Path(db_path).exists():
        return []
    db = sqlite_utils.Database(db_path)
    server_map = {row["id"]: row for row in db["mcp_servers"].rows}
    scans = []
    for row in db["scan_results"].rows:
        findings = _load_findings(row)
        server = server_map.get(row["server_id"], {})
        scans.append(
            _scan_summary(
                row,
                str(server.get("name") or server.get("base_url") or ""),
                findings,
            )
        )
    return scans


@app.get("/api/scans/{run_id}")
async def get_scan_detail(run_id: str, db_path: str = str(DEFAULT_DB_PATH)):
    """run_id に紐づくスキャン詳細と findings を返す。"""
    if not Path(db_path).exists():
        return JSONResponse({"detail": "not found"}, status_code=404)
    db = sqlite_utils.Database(db_path)
    server_map = {row["id"]: row for row in db["mcp_servers"].rows}
    rows = list(db["scan_results"].rows_where("run_id = ?", [run_id]))
    if not rows:
        return JSONResponse({"detail": "not found"}, status_code=404)
    row = rows[0]
    findings = _load_findings(row)
    server = server_map.get(row["server_id"], {})
    summary = _scan_summary(
        row, str(server.get("name") or server.get("base_url") or ""), findings
    )
    # Aggregate status across all scan_types for this run_id (fail-closed).
    statuses = [str(r.get("status") or "").lower() for r in rows]
    normalized = [status for status in statuses if status]
    agg_status = "fail"
    if normalized:
        if any(status == "fail" for status in normalized):
            agg_status = "fail"
        elif any(status == "skip" for status in normalized):
            # 未スキャン/失敗は失格扱い（fail-closed）
            agg_status = "fail"
        elif any(status == "warn" for status in normalized):
            agg_status = "warn"
        elif any(status not in {"pass", "ok"} for status in normalized):
            agg_status = "fail"
        else:
            agg_status = "pass"
    summary["status"] = agg_status
    sanitized_findings = []
    for item in findings:
        sanitized_findings.append(
            {
                "severity": str(item.get("severity") or ""),
                "category": str(item.get("category") or ""),
                "summary": _sanitize_text(item.get("summary")),
                "resource": _sanitize_text(item.get("resource")),
                "owasp_llm_code": str(item.get("owasp_llm_code") or ""),
                "owasp_llm_title": _sanitize_text(item.get("owasp_llm_title")),
                "evidence_source": str(item.get("evidence_source") or ""),
            }
        )
    return {"scan": summary, "findings": sanitized_findings}


class ScanRequest(BaseModel):
    """POST /api/scans request body."""

    server_id: int
    profile: str = "quick"  # quick/full


@app.post("/api/scans")
async def trigger_scan(req: ScanRequest, db_path: str = str(DEFAULT_DB_PATH)):
    """
    スキャン実行トリガー（UI用、SSRF対策として登録済みserver_idのみ許可）。

    入力: server_id（登録済み環境のみ）、profile（quick/full）
    実行: static/mcpsafety スキャンを実行
    Evidence: actor="ui", trigger_source="ui" を記録
    """
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)

    db = sqlite_utils.Database(db_path)

    # Check server exists (SSRF防止: 登録済みIDのみ許可)
    server = registry.get_server(db, req.server_id)
    if not server:
        return JSONResponse(
            {"detail": f"server_id {req.server_id} not found"}, status_code=404
        )

    # mcpsafety は必須（skip は fail 扱い）
    scan_types = ["static", "mcpsafety"]

    # Execute scan
    try:
        result = scanner.run_scan(db, req.server_id, scan_types=scan_types)
        run_id = result["run_id"]
        summary = result.get("summary", {})
        scan_status = summary.get("status") or "fail"

        # Emit UI-triggered evidence
        evidence.append(
            {
                "event": "mcp_scan_run",
                "run_id": run_id,
                "actor": "ui",
                "trigger_source": "ui",
                "server_id": req.server_id,
                "server_name": server["name"],
                "profile": req.profile,
                "scan_types": scan_types,
                "status": scan_status,
            },
            path=_evidence_path(),
        )

        # Run advanced threat detectors (signature cloaking, bait-and-switch, shadowing)
        advanced_result: dict = {}
        try:
            tools_exposed = []
            allowlist_row = next(
                db["allowlist"].rows_where(
                    "server_id = ?", [req.server_id]
                ),
                None,
            )
            if allowlist_row and allowlist_row.get("tools_exposed"):
                import json as _json

                raw = allowlist_row["tools_exposed"]
                tools_exposed = (
                    _json.loads(raw) if isinstance(raw, str) else raw
                )
            if tools_exposed:
                advanced_result = scanner.run_advanced_threat_scan(tools_exposed)
        except Exception as exc:
            logger.warning("Advanced threat scan failed: %s", exc)

        return {
            "run_id": run_id,
            "server_id": req.server_id,
            "status": "success",
            "advanced_threats": advanced_result.get("findings", []),
        }
    except Exception as e:
        return JSONResponse({"detail": f"scan failed: {str(e)}"}, status_code=500)


@app.get("/api/allowlist/status")
async def get_allowlist_status(db_path: str = str(DEFAULT_DB_PATH)):
    """AllowList のメタ情報とヘルスを返す。DB 不在時はゼロ値。"""
    shadow_ok = _shadow_audit_chain_ok()
    bundle_ok = _policy_bundle_hash_ok()
    bundle_sha256 = _policy_bundle_sha256()
    bundle_sig_status = _policy_bundle_signature_status()
    if not Path(db_path).exists():
        return {
            "total": 0,
            "allow": 0,
            "deny": 0,
            "quarantine": 0,
            "last_scan_ts": "",
            "last_decision_ts": "",
            "shadow_audit_chain_ok": shadow_ok,
            "policy_bundle_hash_ok": bundle_ok,
            "policy_bundle_present_ok": bundle_ok,
            "policy_bundle_sha256": bundle_sha256,
            "policy_bundle_signature_status": bundle_sig_status,
        }

    db = sqlite_utils.Database(db_path)
    allowlist_rows = list(db["allowlist"].rows)
    total = len(allowlist_rows)
    active_count = sum(
        1 for row in allowlist_rows if str(row.get("status") or "").lower() == "active"
    )
    decision_counts, last_decision_ts = _council_decision_counts(db)
    last_scan_ts = _latest_iso(
        [
            str(row.get("ended_at") or row.get("started_at") or "")
            for row in db["scan_results"].rows
        ]
    )
    return {
        "total": total,
        "allow": (
            decision_counts["allow"] if any(decision_counts.values()) else active_count
        ),
        "deny": decision_counts["deny"],
        "quarantine": decision_counts["quarantine"],
        "last_scan_ts": last_scan_ts,
        "last_decision_ts": last_decision_ts,
        "shadow_audit_chain_ok": shadow_ok,
        "policy_bundle_hash_ok": bundle_ok,
        "policy_bundle_present_ok": bundle_ok,
        "policy_bundle_sha256": bundle_sha256,
        "policy_bundle_signature_status": bundle_sig_status,
    }


@app.get("/api/dashboard/summary")
async def get_dashboard_summary(db_path: str = str(DEFAULT_DB_PATH)):
    """Suite UI ダッシュボード用のサマリを一括で返す。DB 不在時はゼロ値。"""
    zero_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    summary: dict = {
        "allowlist": {"total": 0, "active": 0, "deny": 0, "quarantine": 0},
        "scans": {
            "total": 0,
            "latest_status": "",
            "latest_ts": "",
            "severity_counts": dict(zero_severity),
        },
        "council": {"total": 0, "latest_decision": "", "latest_ts": ""},
    }
    if not Path(db_path).exists():
        return summary

    db = sqlite_utils.Database(db_path)

    # AllowList
    allowlist_rows = list(db["allowlist"].rows)
    total_allowlist = len(allowlist_rows)
    active_count = sum(
        1 for row in allowlist_rows if str(row.get("status") or "").lower() == "active"
    )
    decision_counts, _last_decision_ts = _council_decision_counts(db)
    allow_count = (
        decision_counts["allow"] if any(decision_counts.values()) else active_count
    )
    summary["allowlist"] = {
        "total": total_allowlist,
        "active": allow_count,
        "deny": decision_counts["deny"],
        "quarantine": decision_counts["quarantine"],
    }

    # Scans (latest only)
    scan_rows = list(db["scan_results"].rows)
    latest_scan_row: dict | None = None
    latest_scan_ts = ""
    for row in scan_rows:
        ts = str(row.get("ended_at") or row.get("started_at") or "")
        if ts and ts > latest_scan_ts:
            latest_scan_ts = ts
            latest_scan_row = row
    severity_counts = dict(zero_severity)
    latest_scan_status = ""
    if latest_scan_row:
        latest_scan_status = str(latest_scan_row.get("status") or "")
        findings = _load_findings(latest_scan_row)
        for sev, cnt in _count_by(findings, "severity").items():
            key = sev.lower()
            if key in severity_counts:
                severity_counts[key] += cnt
    summary["scans"] = {
        "total": len(scan_rows),
        "latest_status": latest_scan_status,
        "latest_ts": latest_scan_ts,
        "severity_counts": severity_counts,
    }

    # Council (latest decision overall; total uses latest-per-server counts)
    latest_decision = ""
    latest_decision_ts = ""
    for row in db["council_evaluations"].rows:
        ts = str(row.get("created_at") or "")
        if ts and ts > latest_decision_ts:
            latest_decision_ts = ts
            latest_decision = str(row.get("decision") or "")
    summary["council"] = {
        "total": sum(decision_counts.values()),
        "latest_decision": latest_decision,
        "latest_ts": latest_decision_ts,
    }
    return summary


@app.get("/api/allowlist")
async def list_allowlist(db_path: str = str(DEFAULT_DB_PATH)):
    """AllowList を一覧で返す。DB 不在時は空配列。"""
    if not Path(db_path).exists():
        return []
    db = sqlite_utils.Database(db_path)
    server_map = {row["id"]: row for row in db["mcp_servers"].rows}
    last_scan_map: dict[int, str] = {}
    for row in db["scan_results"].rows:
        ts = str(row.get("started_at") or row.get("ended_at") or "")
        if not ts:
            continue
        server_id = row.get("server_id")
        if server_id is None:
            continue
        prev = last_scan_map.get(server_id)
        if prev is None or ts > prev:
            last_scan_map[server_id] = ts
    entries = registry.get_allowlist_entries(db, repair=False)
    items = []
    for entry in entries:
        server = server_map.get(entry["server_id"], {})
        # enrich with source info
        source_tag, source_reasons = _source_info(
            db, entry, entry.get("server_id") or -1
        )
        entry = dict(entry)
        entry["source_tag"] = source_tag
        entry["source_reasons"] = source_reasons
        items.append(
            _allowlist_summary(
                entry, server, last_scan_map.get(entry.get("server_id") or -1)
            )
        )
    return items


@app.get("/api/allowlist/{server_id}")
async def get_allowlist_entry(server_id: int, db_path: str = str(DEFAULT_DB_PATH)):
    """指定 server_id の AllowList 情報を返す。未登録なら 404。"""
    if not Path(db_path).exists():
        return JSONResponse({"detail": "not found"}, status_code=404)
    db = sqlite_utils.Database(db_path)
    server = registry.get_server(db, server_id)
    if not server:
        return JSONResponse({"detail": "not found"}, status_code=404)
    entries = registry.get_allowlist_entries(db, repair=False)
    entry = next((e for e in entries if e.get("server_id") == server_id), None)
    if not entry:
        return JSONResponse({"detail": "not found"}, status_code=404)
    source_tag, source_reasons = _source_info(db, entry, server_id)
    entry = dict(entry)
    entry["source_tag"] = source_tag
    entry["source_reasons"] = source_reasons
    last_scan_ts = ""
    for row in db["scan_results"].rows_where("server_id = ?", [server_id]):
        ts = str(row.get("started_at") or row.get("ended_at") or "")
        if ts and ts > last_scan_ts:
            last_scan_ts = ts
    return _allowlist_summary(entry, server, last_scan_ts or None)


@app.get("/api/mcp")
async def list_mcp_servers(db_path: str = str(DEFAULT_DB_PATH)):
    """MCP サーバ一覧を返す（UI向け最小）。DB 不在時は空配列。"""
    if not Path(db_path).exists():
        return []
    db = sqlite_utils.Database(db_path)
    server_map = {row["id"]: row for row in db["mcp_servers"].rows}
    last_scan_map: dict[int, str] = {}
    for row in db["scan_results"].rows:
        ts = str(row.get("ended_at") or row.get("started_at") or "")
        if not ts:
            continue
        sid = row.get("server_id")
        if sid is None:
            continue
        prev = last_scan_map.get(sid)
        if prev is None or ts > prev:
            last_scan_map[sid] = ts
    last_decision_map: dict[int, tuple[str, str]] = {}
    for row in db["council_evaluations"].rows:
        sid = row.get("server_id")
        if sid is None:
            continue
        ts = str(row.get("created_at") or "")
        if not ts:
            continue
        prev = last_decision_map.get(sid)
        if prev is None or ts > prev[0]:
            last_decision_map[sid] = (ts, str(row.get("decision") or ""))
    entries = registry.get_allowlist_entries(db, repair=False)
    items = []
    for entry in entries:
        sid = entry.get("server_id") or -1
        server = server_map.get(sid, {})
        status = str(entry.get("status") or "")
        council_latest = last_decision_map.get(sid)
        if council_latest and council_latest[1]:
            status = council_latest[1]
        items.append({
            "server_id": sid,
            "name": server.get("name") or "",
            "base_url": server.get("base_url") or "",
            "status": status,
            "risk_level": entry.get("risk_level") or "",
            "capabilities": entry.get("capabilities") or [],
            "last_scan_ts": last_scan_map.get(sid, ""),
            "last_decision_ts": council_latest[0] if council_latest else "",
        })
    return items


@app.get("/api/mcp/{server_id}")
async def get_mcp_detail(server_id: int, db_path: str = str(DEFAULT_DB_PATH)):
    """MCP サーバの詳細を返す（read-only）。"""
    if not Path(db_path).exists():
        return JSONResponse({"detail": "not found"}, status_code=404)

    db = sqlite_utils.Database(db_path)
    server = registry.get_server(db, server_id)
    if not server:
        return JSONResponse({"detail": "not found"}, status_code=404)

    entries = registry.get_allowlist_entries(db, repair=False)
    entry = next((e for e in entries if e.get("server_id") == server_id), None)
    if not entry:
        return JSONResponse({"detail": "not found"}, status_code=404)

    scans = list(db["scan_results"].rows_where("server_id = ?", [server_id]))
    scan_row = max(
        scans,
        key=lambda r: str(r.get("ended_at") or r.get("started_at") or ""),
        default=None,
    )
    last_scan_ts = (
        str(scan_row.get("ended_at") or scan_row.get("started_at") or "")
        if scan_row
        else ""
    )
    # Severity counts from findings
    findings = _load_findings(scan_row) if scan_row else []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, cnt in _count_by(findings, "severity").items():
        key = sev.lower()
        if key in severity_counts:
            severity_counts[key] += cnt
    server_info = {
        "id": server.get("id"),
        "name": server.get("name") or "",
        "base_url": server.get("base_url") or "",
        "status": server.get("status") or "",
    }
    allow_info = {
        "status": entry.get("status") or "",
        "risk_level": entry.get("risk_level") or "",
        "capabilities": entry.get("capabilities") or [],
        "source_tag": SOURCE_TRUSTED,
        "source_reasons": [],
    }
    source_tag, source_reasons = _source_info(db, entry, server_id)
    allow_info["source_tag"] = source_tag
    allow_info["source_reasons"] = source_reasons
    scan_info = {
        "run_id": scan_row.get("run_id") if scan_row else "",
        "status": scan_row.get("status") if scan_row else "",
        "last_scan_ts": last_scan_ts,
        "severity_counts": severity_counts,
    }
    # Council info (latest evaluation)
    council_row = None
    council_ts = ""
    for row in db["council_evaluations"].rows_where("server_id = ?", [server_id]):
        ts = str(row.get("created_at") or "")
        if ts and ts > council_ts:
            council_ts = ts
            council_row = row
    council_info = {
        "run_id": str(council_row.get("run_id") or "") if council_row else "",
        "decision": str(council_row.get("decision") or "") if council_row else "",
        "rationale": str(council_row.get("rationale") or "") if council_row else "",
        "ts": council_ts,
    }
    evidence_info = {
        "scan_run_id": str(scan_row.get("run_id") or "") if scan_row else "",
        "council_run_id": str(council_row.get("run_id") or "") if council_row else "",
    }
    return {
        "server": server_info,
        "allowlist": allow_info,
        "scan": scan_info,
        "council": council_info,
        "evidence": evidence_info,
    }


@app.get("/api/mcp/{server_id}/history")
async def get_mcp_history(
    server_id: int,
    limit: int = 50,
    offset: int = 0,
    type: str = "all",
    db_path: str = str(DEFAULT_DB_PATH),
):
    """MCP サーバの scan/council 履歴を統合取得する（P1-3）。

    Args:
        server_id: サーバID
        limit: 取得件数（最大200）
        offset: オフセット
        type: scan|council|all
        db_path: DBパス

    Returns:
        items: 履歴アイテム配列, next_offset: 次のオフセット
    """
    if not Path(db_path).exists():
        return JSONResponse({"detail": "not found"}, status_code=404)
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)

    db = sqlite_utils.Database(db_path)
    server = registry.get_server(db, server_id)
    if not server:
        return JSONResponse({"detail": "server not found"}, status_code=404)

    items: list[dict] = []

    # Collect scan results
    if type in ("scan", "all"):
        for row in db["scan_results"].rows_where("server_id = ?", [server_id]):
            ts = str(row.get("ended_at") or row.get("started_at") or "")
            findings = _load_findings(row)
            severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = str(f.get("severity") or "").lower()
                if sev in severity:
                    severity[sev] += 1
            items.append({
                "type": "scan",
                "created_at": ts,
                "summary": f"scan {row.get('status') or 'unknown'}",
                "ref_id": str(row.get("run_id") or ""),
                "severity": severity,
            })

    # Collect council evaluations
    if type in ("council", "all"):
        for row in db["council_evaluations"].rows_where("server_id = ?", [server_id]):
            ts = str(row.get("created_at") or "")
            items.append({
                "type": "council",
                "created_at": ts,
                "summary": f"council decision={row.get('decision') or 'unknown'}",
                "ref_id": str(row.get("run_id") or ""),
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            })

    # Sort by created_at desc
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    # Pagination
    total = len(items)
    items = items[offset : offset + limit]
    next_offset = offset + len(items) if offset + len(items) < total else None

    return {"items": items, "next_offset": next_offset}


class McpCouncilRequest(BaseModel):
    """POST /api/mcp/{id}/council request body."""

    question: str = ""
    mode: str = ""


@app.post("/api/mcp/{server_id}/council")
async def run_mcp_council(
    request: Request,
    server_id: int,
    req: McpCouncilRequest,
    db_path: str = str(DEFAULT_DB_PATH),
):
    """MCP サーバに対して Council 評価を実行する（P1-4）。

    認証必須、Evidence記録必須。

    Args:
        server_id: サーバID
        req: リクエストボディ（question/mode任意）
        db_path: DBパス

    Returns:
        run_id: council run ID, status: completed, artifacts_ref: 参照パス
    """
    # Admin auth required (副作用ありのため)
    if guard := _admin_auth_guard(request):
        return guard

    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)

    db = sqlite_utils.Database(db_path)
    server = registry.get_server(db, server_id)
    if not server:
        return JSONResponse({"detail": "server not found"}, status_code=404)

    # Check if scan results exist
    scan_results = list(
        db["scan_results"].rows_where("server_id = ?", [server_id])
    )
    if not scan_results:
        return JSONResponse(
            {"detail": "no scan results found; run scan first"}, status_code=400
        )

    # Run council evaluation
    try:
        from . import ai_council

        result = ai_council.evaluate(db, server_id)
        run_id = result.get("run_id", "")

        # Emit evidence
        evidence.append(
            {
                "event": "council_run",
                "actor": "ui",
                "trigger_source": "ui",
                "server_id": server_id,
                "run_id": run_id,
                "decision": result.get("decision", ""),
                "question": req.question,
                "mode": req.mode,
            },
            path=_evidence_path(),
        )

        return {
            "run_id": run_id,
            "status": "completed",
            "decision": result.get("decision", ""),
            "rationale": result.get("rationale", ""),
            "artifacts_ref": f"artifacts/council/{run_id}",
        }
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception as e:
        logger.exception("council evaluation failed")
        return JSONResponse(
            {"detail": f"council evaluation failed: {e}"}, status_code=500
        )


class McpServerRequest(BaseModel):
    """POST /api/mcp request body."""

    name: str
    server_url: str
    origin_url: str
    origin_sha: str


@app.post("/api/mcp")
async def create_mcp_server(
    request: Request,
    req: McpServerRequest,
    db_path: str = str(DEFAULT_DB_PATH),
):
    """新規 MCP サーバを登録する（P1-5）。

    SSRF対策: URL検証のみ、外部リクエスト禁止。認証必須。

    Args:
        req: name, server_url, origin_url, origin_sha

    Returns:
        server_id, status: created|updated
    """
    # Admin auth required
    if guard := _admin_auth_guard(request):
        return guard

    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)

    # URL validation (SSRF対策)
    server_url = req.server_url.strip()
    origin_url = req.origin_url.strip()

    # Validate URL format (https only in production)
    for url, name in [(server_url, "server_url"), (origin_url, "origin_url")]:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return JSONResponse(
                {"detail": f"invalid {name}: must be a valid URL"}, status_code=400
            )
        # Recommend https (allow http for localhost/dev)
        if parsed.scheme not in ("http", "https"):
            return JSONResponse(
                {"detail": f"invalid {name}: must use http or https"}, status_code=400
            )

    # Validate origin_sha format (hex string, 7-40 chars)
    origin_sha = req.origin_sha.strip()
    if not origin_sha or not all(c in "0123456789abcdefABCDEF" for c in origin_sha):
        return JSONResponse(
            {"detail": "invalid origin_sha: must be a hex string"}, status_code=400
        )
    if len(origin_sha) < 7 or len(origin_sha) > 40:
        return JSONResponse(
            {"detail": "invalid origin_sha: must be 7-40 characters"}, status_code=400
        )

    db = sqlite_utils.Database(db_path)
    name = req.name.strip()
    if not name:
        return JSONResponse({"detail": "name is required"}, status_code=400)

    # Check if server exists
    existing = list(db["mcp_servers"].rows_where("name = ?", [name]))
    status = "updated" if existing else "created"

    try:
        server_id = registry.upsert_server(
            db, name, server_url, "draft", origin_url, origin_sha
        )

        # Emit evidence
        evidence.append(
            {
                "event": "mcp_server_registered",
                "actor": "ui",
                "trigger_source": "ui",
                "server_id": server_id,
                "name": name,
                "server_url": server_url,
                "origin_url": origin_url,
                "origin_sha": origin_sha,
                "status": status,
            },
            path=_evidence_path(),
        )

        return {"server_id": server_id, "status": status}
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception as e:
        logger.exception("server registration failed")
        return JSONResponse(
            {"detail": f"server registration failed: {e}"}, status_code=500
        )


# --- Settings API ---


class EnvironmentRequest(BaseModel):
    """POST /api/settings/environments request body."""

    name: str
    endpoint_url: str
    status: str = "active"
    memo: str = ""
    secret: str = ""  # Will be hashed, never returned


@app.get("/api/settings/environments")
async def list_environments(db_path: str = str(DEFAULT_DB_PATH)):
    """環境一覧取得（シークレット除外、has_secretフラグのみ）。"""
    if not Path(db_path).exists():
        return []
    db = sqlite_utils.Database(db_path)
    return registry.list_environments(db)


@app.post("/api/settings/environments")
async def create_environment(
    req: EnvironmentRequest, db_path: str = str(DEFAULT_DB_PATH)
):
    """環境登録/更新（シークレットはハッシュ保存、再表示不可）。"""
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)

    db = sqlite_utils.Database(db_path)
    env_id = registry.upsert_environment(
        db, req.name, req.endpoint_url, req.status, req.memo, req.secret
    )

    # Emit evidence
    evidence.append(
        {
            "event": "settings_updated",
            "actor": "ui",
            "trigger_source": "ui",
            "target": "environment",
            "env_id": env_id,
            "name": req.name,
        },
        path=DEFAULT_EVIDENCE_PATH,
    )

    return {"id": env_id, "name": req.name, "status": "success"}


class ProfileRequest(BaseModel):
    """POST /api/settings/profiles request body."""

    name: str
    check_categories: list[str]
    is_default: bool = False


@app.get("/api/settings/profiles")
async def list_profiles(db_path: str = str(DEFAULT_DB_PATH)):
    """プロファイル一覧取得。"""
    if not Path(db_path).exists():
        return []
    db = sqlite_utils.Database(db_path)
    return registry.list_profiles(db)


@app.post("/api/settings/profiles")
async def create_profile(req: ProfileRequest, db_path: str = str(DEFAULT_DB_PATH)):
    """プロファイル登録/更新。"""
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)

    db = sqlite_utils.Database(db_path)
    profile_id = registry.upsert_profile(
        db, req.name, req.check_categories, req.is_default
    )

    # Emit evidence
    evidence.append(
        {
            "event": "settings_updated",
            "actor": "ui",
            "trigger_source": "ui",
            "target": "profile",
            "profile_id": profile_id,
            "name": req.name,
        },
        path=DEFAULT_EVIDENCE_PATH,
    )

    return {"id": profile_id, "name": req.name, "status": "success"}


def _audit_summary(event_name: str, event: dict) -> str:
    if event_name == "control_upstream_updated":
        base_url = event.get("base_url") or ""
        provider = event.get("provider") or ""
        models = event.get("models_allowlist") or []
        return f"upstream updated (base_url={base_url}, provider={provider}, models={len(models)})"
    if event_name == "upstream_test":
        status = event.get("status") or ""
        http_status = event.get("http_status") or ""
        latency_ms = event.get("latency_ms") or ""
        return f"upstream test (status={status}, http={http_status}, latency_ms={latency_ms})"
    if event_name == "token_issued":
        env_id = event.get("env_id") or ""
        expires_at = event.get("expires_at") or ""
        return f"token issued (env_id={env_id}, expires_at={expires_at})"
    if event_name == "token_revoked":
        token_id = event.get("token_id") or ""
        return f"token revoked (token_id={token_id})"
    if event_name == "admin_session_issued":
        expires_at = event.get("expires_at") or ""
        return f"admin session issued (expires_at={expires_at})"
    if event_name == "openai_proxy_block":
        reason = event.get("reason") or ""
        code = event.get("code") or ""
        path = event.get("path") or ""
        return f"proxy blocked (reason={reason}, code={code}, path={path})"
    if event_name == "source_sink_check" and str(event.get("decision") or "") == "deny":
        server_id = event.get("server_id") or ""
        tool_name = event.get("tool_name") or ""
        reason = event.get("reason") or ""
        return f"mcp blocked (server_id={server_id}, tool={tool_name}, reason={reason})"
    if "block" in event_name:
        return f"blocked ({event_name})"
    return f"event {event_name}"


def _audit_entries(path: Path, limit: int) -> list[dict]:
    if limit <= 0 or not path.exists():
        return []
    detail_keys = {
        "path",
        "model",
        "allowed_models",
        "upstream_status",
        "server_id",
        "tool_name",
        "reason",
        "decision",
        "code",
        "status",
        "http_status",
        "latency_ms",
        "base_url",
        "provider",
        "models_allowlist",
        "token_id",
        "env_id",
        "expires_at",
        "note",
        "session_id_hash",
        "ttl_seconds",
        "cookie_name",
        "secure",
        "samesite",
        "capabilities",
        "source_reasons",
    }
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        event_name = str(event.get("event") or "")
        actor = str(event.get("actor") or event.get("trigger_source") or "")
        decision = str(event.get("decision") or "").lower()
        if not (
            event.get("trigger_source") == "ui"
            or actor == "ui"
            or decision == "deny"
            or "block" in event_name
        ):
            continue
        if event.get("trigger_source") == "ui" or actor == "ui":
            source = "ui"
        elif "openai_proxy" in event_name:
            source = "proxy"
        elif event_name == "source_sink_check":
            source = "mcp"
        else:
            source = "gateway"
        entries.append(
            {
                "evidence_id": str(event.get("run_id") or ""),
                "ts": str(event.get("ts") or ""),
                "type": event_name,
                "actor": actor,
                "summary": _audit_summary(event_name, event),
                "source": source,
                "detail": {key: event[key] for key in detail_keys if key in event},
            }
        )
    entries.sort(key=lambda item: item.get("ts", ""), reverse=True)
    return entries[:limit]


# --- Control Plane API ---
class ControlUpstreamRequest(BaseModel):
    base_url: str
    api_key: str = ""
    provider: str = ""
    models_allowlist: list[str] = []


class ControlTokenRequest(BaseModel):
    env_id: int
    expires_at: str
    note: str = ""


class ControlPolicyProfileRequest(BaseModel):
    profile_name: str = "standard"
    restricted_sinks_additions: list[str] = []
    allow_untrusted_with_approvals: bool | None = None
    change_reason: str = ""


class ControlSetupRequest(BaseModel):
    """ワンボタンフロー: Save→Test→Issue を一括実行"""

    base_url: str
    api_key: str = ""
    provider: str = ""
    models_allowlist: list[str] = []
    issue_token: bool = False
    token_env_id: int = 1
    token_expires_at: str = ""
    token_note: str = ""


@app.post("/api/control/session")
async def create_control_session(request: Request):
    token = _read_secret(ADMIN_TOKEN_ENV, ADMIN_TOKEN_FILE_ENV)
    if not token:
        return JSONResponse({"detail": "admin token not configured"}, status_code=503)
    cookie_value = _admin_session_cookie(request)
    bearer = _get_bearer_token(request)
    if not _verify_admin_session(cookie_value, token) and bearer != token:
        return JSONResponse({"detail": "invalid admin token"}, status_code=401)
    session_token, expires_at = _issue_admin_session(token)
    session_hash = sha256(session_token.encode("utf-8")).hexdigest()
    response = JSONResponse({"status": "ok", "expires_at": expires_at})
    response.set_cookie(
        ADMIN_SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        samesite=ADMIN_SESSION_SAMESITE,
        secure=ADMIN_SESSION_SECURE,
        max_age=ADMIN_SESSION_TTL_S,
        path="/",
    )
    evidence.append(
        {
            "event": "admin_session_issued",
            "actor": "ui",
            "trigger_source": "ui",
            "session_id_hash": session_hash,
            "ttl_seconds": ADMIN_SESSION_TTL_S,
            "cookie_name": ADMIN_SESSION_COOKIE_NAME,
            "secure": ADMIN_SESSION_SECURE,
            "samesite": ADMIN_SESSION_SAMESITE,
            "expires_at": expires_at,
        },
        path=_evidence_path(),
    )
    return response


@app.get("/api/control/upstream")
async def get_control_upstream(request: Request, db_path: str = str(DEFAULT_DB_PATH)):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return dict(DEFAULT_CONTROL_UPSTREAM)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    row = next(db[CONTROL_UPSTREAM_TABLE].rows, None)
    if not row:
        return dict(DEFAULT_CONTROL_UPSTREAM)
    raw_models = row.get("models_allowlist") or "[]"
    try:
        models = (
            json.loads(raw_models) if isinstance(raw_models, str) else list(raw_models)
        )
    except (TypeError, json.JSONDecodeError):
        models = []
    return {
        "base_url": str(row.get("base_url") or ""),
        "provider": str(row.get("provider") or ""),
        "models_allowlist": [str(m) for m in models if str(m).strip()],
        "status": str(row.get("status") or "unknown"),
        "last_tested": str(row.get("last_tested") or ""),
        "api_key": "{REDACTED}" if row.get("api_key") else "",
    }


@app.put("/api/control/upstream")
async def put_control_upstream(
    request: Request, req: ControlUpstreamRequest, db_path: str = str(DEFAULT_DB_PATH)
):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    now = datetime.now(timezone.utc).isoformat()
    row = next(db[CONTROL_UPSTREAM_TABLE].rows, None)
    data = {
        "base_url": req.base_url,
        "provider": req.provider,
        "models_allowlist": json.dumps(req.models_allowlist),
        "updated_at": now,
    }
    if req.api_key:
        data["api_key"] = req.api_key
    if row:
        db[CONTROL_UPSTREAM_TABLE].update(row["id"], data)
        upstream_id = int(row["id"])
    else:
        data.update(
            {
                "api_key": req.api_key,
                "status": "unknown",
                "last_tested": "",
                "created_at": now,
            }
        )
        upstream_id = int(db[CONTROL_UPSTREAM_TABLE].insert(data).last_pk)
    evidence.append(
        {
            "event": "control_upstream_updated",
            "actor": "ui",
            "trigger_source": "ui",
            "upstream_id": upstream_id,
            "base_url": req.base_url,
            "provider": req.provider,
            "models_allowlist": req.models_allowlist,
        },
        path=_evidence_path(),
    )
    return {"id": upstream_id, "status": "success"}


@app.post("/api/control/upstream/test")
async def test_control_upstream(request: Request, db_path: str = str(DEFAULT_DB_PATH)):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    row = next(db[CONTROL_UPSTREAM_TABLE].rows, None)
    base_url = str(row.get("base_url") or "") if row else ""
    api_key = str(row.get("api_key") or "") if row else ""
    provider = str(row.get("provider") or "") if row else ""
    if not row or not base_url:
        return JSONResponse({"detail": "upstream not configured"}, status_code=400)
    provider = _infer_upstream_provider(base_url, provider)
    try:
        url, headers = _build_upstream_test_request(base_url, provider, api_key)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    redacted_url = _redact_url_query_params(
        url, {"key", "api_key", "access_token", "token"}
    )
    start = time.monotonic()
    status = "error"
    http_status = 0
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
            resp = await client.get(url, headers=headers)
        http_status = resp.status_code
        status = "ok" if resp.status_code < 400 else "error"
    except httpx.HTTPError:
        status = "error"
    latency_ms = int((time.monotonic() - start) * 1000)
    db[CONTROL_UPSTREAM_TABLE].update(
        row["id"],
        {"status": status, "last_tested": datetime.now(timezone.utc).isoformat()},
    )
    evidence_id = evidence.append(
        {
            "event": "upstream_test",
            "actor": "ui",
            "trigger_source": "ui",
            "base_url": base_url,
            "provider": provider,
            "test_url": redacted_url,
            "status": status,
            "latency_ms": latency_ms,
            "http_status": http_status,
        },
        path=_evidence_path(),
    )
    return {
        "status": status,
        "latency_ms": latency_ms,
        "http_status": http_status,
        "provider": provider,
        "evidence_id": evidence_id,
    }


@app.post("/api/control/setup")
async def control_setup(
    request: Request, req: ControlSetupRequest, db_path: str = str(DEFAULT_DB_PATH)
):
    """ワンボタンフロー: Save→Test→Issue を一括実行"""
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)

    # 1. Save upstream config
    now = datetime.now(timezone.utc).isoformat()
    row = next(db[CONTROL_UPSTREAM_TABLE].rows, None)
    upstream_id: int
    if row:
        upstream_id = int(row["id"])
        db[CONTROL_UPSTREAM_TABLE].update(
            upstream_id,
            {
                "base_url": req.base_url,
                "api_key": req.api_key,
                "provider": req.provider,
                "models_allowlist": json.dumps(req.models_allowlist),
                "updated_at": now,
            },
        )
    else:
        upstream_id = (
            db[CONTROL_UPSTREAM_TABLE]
            .insert(
                {
                    "base_url": req.base_url,
                    "api_key": req.api_key,
                    "provider": req.provider,
                    "models_allowlist": json.dumps(req.models_allowlist),
                    "status": "unknown",
                    "last_tested": "",
                    "updated_at": now,
                }
            )
            .last_pk
        )

    # 2. Test upstream
    provider = _infer_upstream_provider(req.base_url, req.provider)
    test_status = "error"
    test_latency_ms = 0
    try:
        url, headers = _build_upstream_test_request(req.base_url, provider, req.api_key)
        start = time.monotonic()
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
            resp = await client.get(url, headers=headers)
        test_status = "ok" if resp.status_code < 400 else "error"
        test_latency_ms = int((time.monotonic() - start) * 1000)
    except (ValueError, httpx.HTTPError):
        test_status = "error"
    db[CONTROL_UPSTREAM_TABLE].update(
        upstream_id, {"status": test_status, "last_tested": now}
    )

    # 3. Issue token (optional, only if upstream test passed)
    token_result = None
    if req.issue_token and test_status == "ok":
        token = secrets.token_urlsafe(32)
        salt = secrets.token_hex(8)
        token_hash = _hash_token(token, salt)
        prefix = token[:4]
        suffix = token[-4:] if len(token) >= 4 else token
        token_id = (
            db[CONTROL_TOKENS_TABLE]
            .insert(
                {
                    "env_id": req.token_env_id,
                    "token_hash": token_hash,
                    "token_salt": salt,
                    "token_prefix": prefix,
                    "token_suffix": suffix,
                    "issued_at": now,
                    "expires_at": req.token_expires_at,
                    "note": req.token_note,
                    "last_used_at": "",
                    "revoked_at": "",
                }
            )
            .last_pk
        )
        token_result = {"id": int(token_id), "token": token}

    # 4. Evidence
    evidence.append(
        {
            "event": "setup_completed",
            "actor": "ui",
            "trigger_source": "ui",
            "upstream_id": upstream_id,
            "test_status": test_status,
            "token_issued": token_result is not None,
        },
        path=_evidence_path(),
    )

    return {
        "status": "ok" if test_status == "ok" else "partial",
        "upstream": {
            "id": upstream_id,
            "test_status": test_status,
            "latency_ms": test_latency_ms,
        },
        "token": token_result,
    }


@app.get("/api/control/policy-profile")
async def get_control_policy_profile(
    request: Request, db_path: str = str(DEFAULT_DB_PATH)
):
    if guard := _admin_auth_guard(request):
        return guard
    config = _policy_profile_config(db_path)
    if config is None:
        config = _policy_profile_from_env()
    return config


@app.put("/api/control/policy-profile")
async def put_control_policy_profile(
    request: Request,
    req: ControlPolicyProfileRequest,
    db_path: str = str(DEFAULT_DB_PATH),
):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    profile_name = _normalize_profile_name(req.profile_name)
    preset = PROFILE_PRESETS[profile_name]
    additions = {
        str(v).lower() for v in req.restricted_sinks_additions if str(v).strip()
    }
    allow_value = (
        req.allow_untrusted_with_approvals
        if req.allow_untrusted_with_approvals is not None
        else preset["allow_untrusted_with_approvals"]
    )
    now = datetime.now(timezone.utc).isoformat()
    data = {
        "profile_name": profile_name,
        "restricted_sinks_additions": json.dumps(sorted(additions)),
        "allow_untrusted_with_approvals": 1 if allow_value else 0,
        "change_reason": req.change_reason,
        "updated_at": now,
    }
    row = next(db[CONTROL_POLICY_PROFILE_TABLE].rows, None)
    if row:
        db[CONTROL_POLICY_PROFILE_TABLE].update(row["id"], data)
        profile_id = int(row["id"])
    else:
        data["created_at"] = now
        profile_id = int(db[CONTROL_POLICY_PROFILE_TABLE].insert(data).last_pk)
    evidence_id = evidence.append(
        {
            "event": "control_policy_profile_updated",
            "actor": "ui",
            "trigger_source": "ui",
            "profile_id": profile_id,
            "profile_name": profile_name,
            "restricted_sinks_additions": sorted(additions),
            "allow_untrusted_with_approvals": bool(allow_value),
            "change_reason": req.change_reason,
        },
        path=_evidence_path(),
    )
    return {
        "id": profile_id,
        "evidence_id": evidence_id,
        **(_policy_profile_config(db_path) or {}),
    }


@app.get("/api/control/policy-profile/presets")
async def get_policy_profile_presets(request: Request):
    """プロファイルプリセット一覧: 標準/厳格/開発の選択肢を提供"""
    if guard := _admin_auth_guard(request):
        return guard
    presets = []
    for name, config in PROFILE_PRESETS.items():
        presets.append(
            {
                "name": name,
                "description": {
                    "standard": "バランス重視。デフォルト設定。",
                    "strict": "最大限の制限。sampling等の高リスク機能を制限。",
                    "development": "開発向け。承認済みuntrustedを許可。",
                }.get(name, ""),
                "restricted_sinks": sorted(config["restricted_sinks"]),
                "allow_untrusted_with_approvals": config["allow_untrusted_with_approvals"],
            }
        )
    return {
        "presets": presets,
        "core_rules": {
            "restricted_sinks": sorted(DEFAULT_RESTRICTED_SINKS),
            "description": "コア不変ルール（無効化不可）",
        },
    }


@app.post("/api/control/policy-profile/preview")
async def preview_policy_profile(
    request: Request,
    req: ControlPolicyProfileRequest,
    db_path: str = str(DEFAULT_DB_PATH),
):
    """プロファイル変更プレビュー: 変更前後の差分を表示（コミットなし）"""
    if guard := _admin_auth_guard(request):
        return guard
    # 現在の設定を取得
    current = _policy_profile_config(db_path)
    if current is None:
        current = _policy_profile_from_env()
    # 新しい設定を計算
    profile_name = _normalize_profile_name(req.profile_name)
    preset = PROFILE_PRESETS[profile_name]
    additions = {
        str(v).lower() for v in req.restricted_sinks_additions if str(v).strip()
    }
    allow_value = (
        req.allow_untrusted_with_approvals
        if req.allow_untrusted_with_approvals is not None
        else preset["allow_untrusted_with_approvals"]
    )
    restricted_effective = sorted(
        set(DEFAULT_RESTRICTED_SINKS) | preset["restricted_sinks"] | additions
    )
    proposed = {
        "profile_name": profile_name,
        "restricted_sinks_additions": sorted(additions),
        "restricted_sinks_effective": restricted_effective,
        "allow_untrusted_with_approvals": allow_value,
        "change_reason": req.change_reason,
    }
    # 差分を計算
    changes = []
    if current["profile_name"] != proposed["profile_name"]:
        changes.append(
            {
                "field": "profile_name",
                "from": current["profile_name"],
                "to": proposed["profile_name"],
            }
        )
    current_sinks = set(current.get("restricted_sinks_effective", []))
    proposed_sinks = set(proposed["restricted_sinks_effective"])
    added_sinks = proposed_sinks - current_sinks
    removed_sinks = current_sinks - proposed_sinks
    if added_sinks:
        changes.append({"field": "restricted_sinks", "added": sorted(added_sinks)})
    if removed_sinks:
        changes.append({"field": "restricted_sinks", "removed": sorted(removed_sinks)})
    if current.get("allow_untrusted_with_approvals") != proposed["allow_untrusted_with_approvals"]:
        changes.append(
            {
                "field": "allow_untrusted_with_approvals",
                "from": current.get("allow_untrusted_with_approvals"),
                "to": proposed["allow_untrusted_with_approvals"],
            }
        )
    return {
        "current": current,
        "proposed": proposed,
        "changes": changes,
        "has_changes": len(changes) > 0,
    }


@app.post("/api/control/tokens")
async def create_control_token(
    request: Request, req: ControlTokenRequest, db_path: str = str(DEFAULT_DB_PATH)
):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)

    # トークン期限（クライアント指定 or デフォルト1年）
    now_utc = datetime.now(timezone.utc)
    if req.expires_at:
        exp = _parse_iso(req.expires_at)
        calculated_expires_at = exp.isoformat() if exp else (now_utc + timedelta(days=365)).isoformat()
    else:
        calculated_expires_at = (now_utc + timedelta(days=365)).isoformat()

    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(8)
    token_hash = _hash_token(token, salt)
    prefix = token[:4]
    suffix = token[-4:] if len(token) >= 4 else token
    now = datetime.now(timezone.utc).isoformat()
    token_id = (
        db[CONTROL_TOKENS_TABLE]
        .insert(
            {
                "env_id": req.env_id,
                "token_hash": token_hash,
                "token_salt": salt,
                "token_prefix": prefix,
                "token_suffix": suffix,
                "issued_at": now,
                "expires_at": calculated_expires_at,
                "note": req.note,
                "last_used_at": "",
                "revoked_at": "",
            }
        )
        .last_pk
    )
    evidence.append(
        {
            "event": "token_issued",
            "actor": "ui",
            "trigger_source": "ui",
            "token_id": int(token_id),
            "env_id": req.env_id,
            "expires_at": calculated_expires_at,
            "requested_expires_at": req.expires_at,
            "subscription_linked": False,
            "note": req.note,
        },
        path=_evidence_path(),
    )
    return {"id": int(token_id), "token": token, "expires_at": calculated_expires_at}


@app.get("/api/control/tokens")
async def list_control_tokens(request: Request, db_path: str = str(DEFAULT_DB_PATH)):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return []
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    now = datetime.now(timezone.utc)
    tokens = []
    for row in db[CONTROL_TOKENS_TABLE].rows:
        prefix = str(row.get("token_prefix") or "")
        suffix = str(row.get("token_suffix") or "")
        masked = f"{prefix}...{suffix}" if (prefix or suffix) else ""
        tokens.append(
            {
                "id": row.get("id"),
                "env_id": row.get("env_id"),
                "token_masked": masked,
                "status": _token_status(row, now),
                "issued_at": row.get("issued_at") or "",
                "expires_at": row.get("expires_at") or "",
                "note": row.get("note") or "",
                "last_used_at": row.get("last_used_at") or "",
            }
        )
    return tokens


@app.post("/api/control/tokens/{token_id}/revoke")
async def revoke_control_token(
    request: Request, token_id: int, db_path: str = str(DEFAULT_DB_PATH)
):
    if guard := _admin_auth_guard(request):
        return guard
    if not Path(db_path).exists():
        return JSONResponse({"detail": "database not found"}, status_code=500)
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    rows = list(db[CONTROL_TOKENS_TABLE].rows_where("id = ?", [token_id]))
    if not rows:
        return JSONResponse({"detail": "not found"}, status_code=404)
    db[CONTROL_TOKENS_TABLE].update(
        token_id, {"revoked_at": datetime.now(timezone.utc).isoformat()}
    )
    evidence.append(
        {
            "event": "token_revoked",
            "actor": "ui",
            "trigger_source": "ui",
            "token_id": token_id,
        },
        path=_evidence_path(),
    )
    return {"id": token_id, "status": "revoked"}


@app.get("/api/control/audit")
async def get_control_audit(request: Request, limit: int = AUDIT_DEFAULT_LIMIT):
    if guard := _admin_auth_guard(request):
        return guard
    safe_limit = min(max(limit, 0), AUDIT_MAX_LIMIT)
    return _audit_entries(_evidence_path(), safe_limit)


@app.get("/api/control/diagnostics")
async def get_control_diagnostics(
    request: Request, db_path: str = str(DEFAULT_DB_PATH)
):
    if guard := _admin_auth_guard(request):
        return guard
    now = datetime.now(timezone.utc).isoformat()
    if not Path(db_path).exists():
        allowlist_status = await get_allowlist_status(db_path)
        return {
            "ts": now,
            "health": {"status": "ok"},
            "db_present": False,
            "upstream": _control_upstream_summary(None),
            "tokens": {
                "total": 0,
                "by_status": {"active": 0, "expired": 0, "revoked": 0},
            },
            "allowlist_status": allowlist_status,
            "policy_profile": _policy_profile_from_env(),
            "runtime": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
            },
        }
    db = sqlite_utils.Database(db_path)
    _ensure_control_tables(db)
    row = next(db[CONTROL_UPSTREAM_TABLE].rows, None)
    allowlist_status = await get_allowlist_status(db_path)
    profile = _policy_profile_config(db_path) or _policy_profile_from_env()
    return {
        "ts": now,
        "health": {"status": "ok"},
        "db_present": True,
        "upstream": _control_upstream_summary(row),
        "tokens": _control_tokens_summary(db),
        "allowlist_status": allowlist_status,
        "policy_profile": profile,
        "runtime": {"python": sys.version.split()[0], "platform": platform.platform()},
    }


# --- Report API ---


@app.get("/api/scans/{run_id}/report.json")
async def get_scan_report_json(run_id: str, db_path: str = str(DEFAULT_DB_PATH)):
    """
    監査資料レベルの詳細JSON（ツール名/バージョン/対象/実行日時/集計/改善提案）。
    シークレット除外。
    """
    if not Path(db_path).exists():
        return JSONResponse({"detail": "not found"}, status_code=404)

    db = sqlite_utils.Database(db_path)
    rows = list(db["scan_results"].rows_where("run_id = ?", [run_id]))
    if not rows:
        return JSONResponse({"detail": "not found"}, status_code=404)

    row = rows[0]
    server_id = row.get("server_id")
    server_obj = registry.get_server(db, server_id) if server_id else None
    server: dict[str, Any] = server_obj if server_obj else {}

    findings = _load_findings(row)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_counts: dict[str, int] = {}

    for item in findings:
        sev = str(item.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        code = str(item.get("owasp_llm_code") or "")
        if code:
            owasp_counts[code] = owasp_counts.get(code, 0) + 1

    report = {
        "report_metadata": {
            "tool_name": "MCP Gateway",
            "tool_version": "0.1.0",
            "run_id": run_id,
            "target_environment": (
                server.get("name", "unknown") if server else "unknown"
            ),
            "target_url": server.get("base_url", "") if server else "",
            "executed_at": row.get("started_at", ""),
            "completed_at": row.get("ended_at", ""),
            "scan_type": row.get("scan_type", ""),
            "status": row.get("status", ""),
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "owasp_llm_counts": owasp_counts,
        },
        "findings": [
            {
                "severity": str(item.get("severity") or ""),
                "category": str(item.get("category") or ""),
                "summary": _sanitize_text(item.get("summary")),
                "resource": _sanitize_text(item.get("resource")),
                "owasp_llm_code": str(item.get("owasp_llm_code") or ""),
                "owasp_llm_title": _sanitize_text(item.get("owasp_llm_title")),
                "evidence_source": str(item.get("evidence_source") or ""),
            }
            for item in findings
        ],
        "recommendations": [
            "Critical/High検出がある場合は直ちに対応してください。",
            "OWASP LLM Top10に該当する検出は優先的に修正してください。",
            "AllowList登録前にAI Council評価を実施してください。",
        ],
    }

    return report


@app.get("/api/scans/{run_id}/report.pdf")
async def get_scan_report_pdf(run_id: str, db_path: str = str(DEFAULT_DB_PATH)):
    """
    PDFレポート生成（シークレット除外、監査資料レベル）。
    reportlab を使用（軽量、外部依存最小）。
    """
    try:
        from io import BytesIO

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return JSONResponse(
            {"detail": "reportlab not installed (pip install reportlab)"},
            status_code=500,
        )

    if not Path(db_path).exists():
        return JSONResponse({"detail": "not found"}, status_code=404)

    db = sqlite_utils.Database(db_path)
    rows = list(db["scan_results"].rows_where("run_id = ?", [run_id]))
    if not rows:
        return JSONResponse({"detail": "not found"}, status_code=404)

    row = rows[0]
    server_id = row.get("server_id")
    server_obj = registry.get_server(db, server_id) if server_id else None
    server: dict[str, Any] = server_obj if server_obj else {}

    findings = _load_findings(row)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for item in findings:
        sev = str(item.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Build PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("MCP Gateway Scan Report", styles["Title"]))
    story.append(Spacer(1, 12))

    # Metadata
    story.append(Paragraph("Report Metadata", styles["Heading2"]))
    meta_data = [
        ["Run ID", run_id],
        ["Target", server.get("name", "unknown") if server else "unknown"],
        ["URL", (server.get("base_url", "") if server else "")[:60]],  # truncate
        ["Executed At", row.get("started_at", "")],
        ["Status", row.get("status", "")],
    ]
    meta_table = Table(meta_data)
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Summary
    story.append(Paragraph("Summary", styles["Heading2"]))
    summary_data = [
        ["Total Findings", str(len(findings))],
        ["Critical", str(severity_counts.get("critical", 0))],
        ["High", str(severity_counts.get("high", 0))],
        ["Medium", str(severity_counts.get("medium", 0))],
        ["Low", str(severity_counts.get("low", 0))],
    ]
    summary_table = Table(summary_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Recommendations
    story.append(Paragraph("Recommendations", styles["Heading2"]))
    story.append(
        Paragraph(
            "• Critical/High検出がある場合は直ちに対応してください。", styles["Normal"]
        )
    )
    story.append(Paragraph("• AI Council評価を実施してください。", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Build
    doc.build(story)
    buffer.seek(0)

    return Response(content=buffer.read(), media_type="application/pdf")


# ---------------------------------------------------------------------------
# Causal Web Sandbox endpoints
# ---------------------------------------------------------------------------

_WEB_SANDBOX_VERDICTS: deque[dict[str, Any]] = deque(maxlen=100)
_WEB_SANDBOX_MAX_ARTIFACTS = 100
_WEB_SANDBOX_ARTIFACTS: dict[str, dict[str, Any]] = {}


class WebSandboxScanRequest(BaseModel):
    """Request body for /api/web-sandbox/scan."""

    url: str


@app.post("/api/web-sandbox/scan")
async def web_sandbox_scan(request: Request, body: WebSandboxScanRequest) -> JSONResponse:
    """Run a causal web sandbox scan on a URL."""
    if guard := _admin_auth_guard(request):
        return guard
    from . import causal_sandbox

    try:
        result = causal_sandbox.run_causal_scan(body.url)
    except causal_sandbox.SSRFError as exc:
        return JSONResponse(
            {"detail": f"SSRF blocked: {exc}"}, status_code=400
        )
    except causal_sandbox.ResourceLimitError as exc:
        return JSONResponse(
            {"detail": f"Resource limit: {exc}"}, status_code=400
        )

    result_dict = result.model_dump()
    result_dict["verdict"]["classification"] = result.verdict.classification.value

    # LRU eviction: remove oldest entry when at capacity
    if len(_WEB_SANDBOX_ARTIFACTS) >= _WEB_SANDBOX_MAX_ARTIFACTS:
        oldest_key = next(iter(_WEB_SANDBOX_ARTIFACTS))
        del _WEB_SANDBOX_ARTIFACTS[oldest_key]
    _WEB_SANDBOX_ARTIFACTS[result.bundle.bundle_id] = result_dict
    _WEB_SANDBOX_VERDICTS.append(
        {
            "run_id": result.run_id,
            "url": result.url,
            "classification": result.verdict.classification.value,
            "confidence": result.verdict.confidence,
            "recommended_action": result.verdict.recommended_action,
            "summary": result.verdict.summary,
            "risk_indicators": result.verdict.risk_indicators,
            "evidence_refs": result.verdict.evidence_refs,
            "eval_method": result.eval_method,
            "timestamp": result.timestamp,
        }
    )

    return JSONResponse(result_dict)


@app.get("/api/web-sandbox/artifacts/{bundle_id}")
async def web_sandbox_artifact(bundle_id: str) -> JSONResponse:
    """Retrieve a web sandbox scan artifact by bundle ID."""
    artifact = _WEB_SANDBOX_ARTIFACTS.get(bundle_id)
    if not artifact:
        return JSONResponse({"detail": "not found"}, status_code=404)
    return JSONResponse(artifact)


@app.get("/api/web-sandbox/verdicts")
async def web_sandbox_verdicts() -> JSONResponse:
    """List recent web sandbox verdicts (in-memory, max 100)."""
    return JSONResponse({"verdicts": list(_WEB_SANDBOX_VERDICTS)})


# ---------------------------------------------------------------------------
# Gemini API Key configuration (hackathon demo)
# ---------------------------------------------------------------------------


class GeminiKeyRequest(BaseModel):
    """Request body for /api/config/gemini-key."""

    api_key: str


@app.post("/api/config/gemini-key")
async def set_gemini_key(request: Request, body: GeminiKeyRequest) -> JSONResponse:
    """Set the Gemini API key at runtime (hackathon demo convenience).

    Stores the key in the process environment so all Gemini-powered
    modules (council, scanner, redteam, web sandbox) can use it.
    """
    if guard := _admin_auth_guard(request):
        return guard
    trimmed = body.api_key.strip()
    if not trimmed:
        return JSONResponse({"detail": "api_key is required"}, status_code=400)
    os.environ["GOOGLE_API_KEY"] = trimmed
    return JSONResponse({"status": "ok", "gemini_configured": True})


@app.get("/api/config/gemini-status")
async def gemini_status(request: Request) -> JSONResponse:
    """Check whether Gemini API key is configured."""
    if guard := _admin_auth_guard(request):
        return guard
    key = os.getenv("GOOGLE_API_KEY", "")
    return JSONResponse({
        "configured": bool(key),
        "key_preview": f"{key[:4]}..." if len(key) > 4 else ("set" if key else ""),
    })
