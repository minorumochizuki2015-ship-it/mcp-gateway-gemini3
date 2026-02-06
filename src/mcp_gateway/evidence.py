"""Evidence helper for appending events to ci_evidence.jsonl with atomic writes."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SHADOW_MANIFEST = Path("observability/policy/shadow_audit/manifest.jsonl")
SHADOW_CHAIN = Path("observability/policy/shadow_audit/manifest.sha256")

_REDACTED_VALUE = "{REDACTED}"
_REDACTED_QUERY_VALUE = "REDACTED"

_SENSITIVE_KEY_EXACT = {
    "api_key",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "admin_token",
    "authorization",
    "x-api-key",
    "x-access-token",
    "x-auth-token",
    "x-authorization",
    "password",
    "secret",
}

_SENSITIVE_KEY_SUFFIXES = (
    "_api_key",
    "_access_token",
    "_refresh_token",
    "_id_token",
    "_client_secret",
    "_admin_token",
    "_authorization",
    "_password",
    "_secret",
    "_token",
    "_key",
)

_SENSITIVE_KEY_SUFFIX_EXCLUSIONS = (
    "_token_id",
    "_key_id",
)

_SENSITIVE_URL_QUERY_KEYS = {
    "key",
    "api_key",
    "access_token",
    "token",
}

_URL_SCHEMES = ("http://", "https://", "ws://", "wss://")

_REDACT_INLINE_QUERY = re.compile(
    r"(?i)([?&])(key|api_key|access_token|token)=([^&#\\s]+)"
)
_REDACT_BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{12,})")


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEY_EXACT:
        return True
    for excluded in _SENSITIVE_KEY_SUFFIX_EXCLUSIONS:
        if lowered.endswith(excluded):
            return False
    return lowered.endswith(_SENSITIVE_KEY_SUFFIXES)


def _redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url

    changed = False
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
        changed = True

    if parsed.query:
        query = parse_qsl(parsed.query, keep_blank_values=True)
        redacted: list[tuple[str, str]] = []
        for key, value in query:
            if key.lower() in _SENSITIVE_URL_QUERY_KEYS:
                redacted.append((key, _REDACTED_QUERY_VALUE))
                changed = True
            else:
                redacted.append((key, value))
        query_str = urlencode(redacted, doseq=True)
    else:
        query_str = parsed.query

    if not changed:
        return url
    return urlunsplit((parsed.scheme, netloc, parsed.path, query_str, parsed.fragment))


def _sanitize_string(value: str) -> str:
    sanitized = value
    if sanitized.startswith(_URL_SCHEMES):
        sanitized = _redact_url(sanitized)
    sanitized = _REDACT_INLINE_QUERY.sub(r"\1\2=" + _REDACTED_QUERY_VALUE, sanitized)
    sanitized = _REDACT_BEARER.sub("Bearer " + _REDACTED_QUERY_VALUE, sanitized)
    return sanitized


def _sanitize_obj(obj):  # type: ignore[no-untyped-def]
    if isinstance(obj, dict):
        sanitized: dict = {}
        for key, value in obj.items():
            key_str = str(key)
            if _is_sensitive_key(key_str):
                sanitized[key_str] = _REDACTED_VALUE
                continue
            sanitized[key_str] = _sanitize_obj(value)
        return sanitized
    if isinstance(obj, list):
        return [_sanitize_obj(item) for item in obj]
    if isinstance(obj, str):
        return _sanitize_string(obj)
    return obj


def append(
    event: dict, path: str | Path = "observability/policy/ci_evidence.jsonl"
) -> str:
    """
    Append an event to the Evidence JSONL file with atomic write.

    Automatically adds:
    - run_id: UUID4 string (if not present)
    - ts: UTC ISO8601 timestamp (if not present)

    Args:
        event: Event dictionary to append
        path: Path to JSONL file (default: observability/policy/ci_evidence.jsonl)

    Returns:
        The run_id of the appended event
    """
    path_obj = Path(path)

    # Ensure run_id and ts are present
    if "run_id" not in event:
        event["run_id"] = str(uuid.uuid4())
    if "ts" not in event:
        event["ts"] = datetime.now(timezone.utc).isoformat()

    # Read existing content
    lines: list[str] = []
    if path_obj.exists():
        lines = path_obj.read_text(encoding="utf-8").splitlines()

    # Append new event
    new_line = json.dumps(_sanitize_obj(event), ensure_ascii=False)
    lines.append(new_line)

    # If self_tune_run fails/quarantine、Shadow Audit に rollback_executed を記録
    if event.get("event") == "self_tune_run" and event.get("status") in {
        "fail",
        "abnormal",
        "quarantine",
    }:
        snapshot_path = str(event.get("snapshot_path") or "")
        reason = event.get("error", "self_tune_run failure")
        append_shadow_event(
            {
                "ts": event.get("ts"),
                "actor": event.get("actor", "WORK"),
                "event": "rollback_executed",
                "snapshot_path": snapshot_path,
                "reason": reason,
                "status": "executed",
            }
        )

    # Atomic write
    _atomic_write(path_obj, "\n".join(lines) + "\n", validate_jsonl=True)

    return event["run_id"]


def _atomic_write(path: Path, content: str, *, validate_jsonl: bool = False) -> None:
    """
    Write content to file atomically using temp file + replace pattern.

    Args:
        path: Target file path
        content: Content to write
        validate_jsonl: If True, validate that each line is valid JSON
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write to temp file
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")

    # Validate JSONL if requested
    if validate_jsonl:
        for line in content.splitlines():
            if line.strip():
                json.loads(line)  # Will raise if invalid

    # Atomic replace
    tmp.replace(path)


def _append_shadow_audit(record: dict) -> None:
    """Shadow Audit manifest にイベントを追記し、チェーンを更新する。"""
    lines = []
    if SHADOW_MANIFEST.exists():
        lines = SHADOW_MANIFEST.read_text(encoding="utf-8").splitlines()
    prev_hash = (
        SHADOW_CHAIN.read_text(encoding="utf-8").strip()
        if SHADOW_CHAIN.exists()
        else ""
    )
    new_line = json.dumps(record, ensure_ascii=False)
    new_hash = hashlib.sha256(
        (prev_hash + "\n" + new_line if prev_hash else new_line).encode("utf-8")
    ).hexdigest()
    _atomic_write(SHADOW_MANIFEST, "\n".join([*lines, new_line]), validate_jsonl=True)
    _atomic_write(SHADOW_CHAIN, new_hash)


def append_shadow_event(record: dict) -> None:
    """Shadow Audit manifest に任意イベントを追記する。"""
    _append_shadow_audit(record)
