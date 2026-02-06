"""Tests for evidence module."""

import json
from pathlib import Path

import pytest

from src.mcp_gateway import evidence


def _read_last_event(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8").splitlines()[-1])


def test_append_creates_file(tmp_path: Path):
    """Test that append creates the JSONL file."""
    test_file = tmp_path / "test_evidence.jsonl"

    event = {"event": "test_event", "data": "test_data"}
    run_id = evidence.append(event, test_file)

    assert test_file.exists()
    assert run_id == event["run_id"]


def test_append_adds_run_id_and_ts(tmp_path: Path):
    """Test that append auto-generates run_id and ts."""
    test_file = tmp_path / "test_evidence.jsonl"

    event = {"event": "test_event"}
    run_id = evidence.append(event, test_file)

    # Read back the file
    saved_event = _read_last_event(test_file)

    assert "run_id" in saved_event
    assert "ts" in saved_event
    assert saved_event["run_id"] == run_id
    assert "T" in saved_event["ts"]  # UTC ISO8601 format


def test_append_multiple_events(tmp_path: Path):
    """Test appending multiple events."""
    test_file = tmp_path / "test_evidence.jsonl"

    event1 = {"event": "event1"}
    event2 = {"event": "event2"}

    run_id1 = evidence.append(event1, test_file)
    run_id2 = evidence.append(event2, test_file)

    assert run_id1 != run_id2

    # Read all lines
    lines = test_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2

    saved1 = json.loads(lines[0])
    saved2 = json.loads(lines[1])

    assert saved1["event"] == "event1"
    assert saved2["event"] == "event2"


def test_atomic_write_validates_jsonl(tmp_path: Path):
    """Test that atomic write validates JSONL format."""
    test_file = tmp_path / "test.jsonl"

    # Valid JSONL
    valid_content = '{"key": "value"}\n{"key2": "value2"}'
    evidence._atomic_write(test_file, valid_content, validate_jsonl=True)
    assert test_file.exists()

    # Invalid JSONL should raise
    invalid_content = 'not valid json\n{"valid": "json"}'
    with pytest.raises(json.JSONDecodeError):
        evidence._atomic_write(test_file, invalid_content, validate_jsonl=True)


def test_evidence_redacts_sensitive_query_params(tmp_path: Path) -> None:
    evidence_path = tmp_path / "ci_evidence.jsonl"
    evidence.append(
        {
            "event": "upstream_test",
            "test_url": "https://generativelanguage.googleapis.com/v1beta/models?key=SECRET",
        },
        path=evidence_path,
    )
    event = _read_last_event(evidence_path)
    assert event["test_url"].endswith("/v1beta/models?key=REDACTED")


def test_evidence_redacts_bearer_inside_string(tmp_path: Path) -> None:
    evidence_path = tmp_path / "ci_evidence.jsonl"
    evidence.append(
        {
            "event": "proxy_error",
            "detail": "Authorization: Bearer 1234567890abcdef",
        },
        path=evidence_path,
    )
    event = _read_last_event(evidence_path)
    assert "REDACTED" in event["detail"]
    assert "1234567890abcdef" not in event["detail"]


def test_evidence_removes_userinfo_and_redacts_sensitive_fields(tmp_path: Path) -> None:
    evidence_path = tmp_path / "ci_evidence.jsonl"
    evidence.append(
        {
            "event": "control_upstream_updated",
            "base_url": "https://user:pass@example.com/v1?api_key=SECRET",
            "Authorization": "Bearer SECRETSECRETSECRET",
            "x-api-key": "SECRET",
            "token_id": "token-123",
        },
        path=evidence_path,
    )
    event = _read_last_event(evidence_path)
    assert event["base_url"].startswith("https://example.com/v1")
    assert "user:pass@" not in event["base_url"]
    assert "api_key=REDACTED" in event["base_url"]
    assert event["Authorization"] == "{REDACTED}"
    assert event["x-api-key"] == "{REDACTED}"
    assert event["token_id"] == "token-123"
