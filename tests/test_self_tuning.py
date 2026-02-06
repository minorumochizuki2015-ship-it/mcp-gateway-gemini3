import json
from pathlib import Path

import pytest
import sqlite_utils

from src.mcp_gateway import evidence, self_tuning


def _make_db(db_path: Path) -> None:
    db = sqlite_utils.Database(db_path)
    db["council_evaluations"].insert_all(
        [
            {
                "decision": "deny",
                "scores": json.dumps({"security": 0.9}),
                "created_at": "2025-01-01T00:00:00Z",
            },
            {
                "decision": "allow",
                "scores": json.dumps({"security": 0.4}),
                "created_at": "2025-01-02T00:00:00Z",
            },
        ]
    )


def test_run_self_tuning_records_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "db.sqlite"
    _make_db(db_path)
    ev_path = tmp_path / "evidence.jsonl"
    params_path = tmp_path / "params.json"

    result = self_tuning.run_self_tuning(
        db_path=db_path,
        params_path=params_path,
        lookback=10,
        strategy="auto",
        evidence_path=ev_path,
    )

    weights = result["new_weights"]
    assert 0.1 <= weights["security"] <= 0.7
    assert abs(sum(weights.values()) - 1.0) < 1e-6

    events = ev_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(events[-1])
    assert record["event"] == "self_tune_run"
    assert record["status"] == "pass"
    assert record["strategy"] == "auto"


def test_run_self_tuning_with_missing_table(tmp_path: Path) -> None:
    """council_evaluations が無くてもデフォルト値で pass する。"""
    db_path = tmp_path / "db.sqlite"
    ev_path = tmp_path / "evidence.jsonl"
    params_path = tmp_path / "params.json"

    # テーブルを作成しないまま実行
    result = self_tuning.run_self_tuning(
        db_path=db_path,
        params_path=params_path,
        lookback=10,
        strategy="auto",
        evidence_path=ev_path,
    )

    assert result["status"] == "pass"


def test_run_self_tuning_failure_emits_retest_and_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """異常時に再検査バックログと rollback 記録を残す。"""
    manifest = tmp_path / "shadow_manifest.jsonl"
    chain = tmp_path / "shadow_manifest.sha256"
    monkeypatch.setattr(evidence, "SHADOW_MANIFEST", manifest)
    monkeypatch.setattr(evidence, "SHADOW_CHAIN", chain)

    def _raise_db(*_: object, **__: object) -> None:
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(self_tuning.sqlite_utils, "Database", _raise_db)

    ev_path = tmp_path / "evidence.jsonl"
    snap_path = tmp_path / "snapshot.json"

    with pytest.raises(RuntimeError):
        self_tuning.run_self_tuning(
            db_path=tmp_path / "db.sqlite",
            params_path=tmp_path / "params.json",
            lookback=10,
            strategy="auto",
            evidence_path=ev_path,
            snapshot_path=snap_path,
        )

    events = [
        json.loads(line) for line in ev_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        ev["event"] == "self_tune_run" and ev["status"] == "fail" for ev in events
    )
    assert any(ev["event"] == "retest_queue_unavailable" for ev in events)
    assert any(ev["event"] == "retest_scheduled" for ev in events)

    rollback_events = [
        json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()
    ]
    assert rollback_events[-1]["event"] == "rollback_executed"
    assert rollback_events[-1]["snapshot_path"] == str(snap_path)
