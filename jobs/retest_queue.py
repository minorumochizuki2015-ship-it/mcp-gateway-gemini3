"""RQ を用いた再検査キュー実装。

Redis 未利用環境でも監査用 Evidence を残し、再検査要求を失わないことを目的とする。
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from redis import Redis  # type: ignore[import-not-found]
from rq import Queue  # type: ignore[import-not-found]

from src.mcp_gateway import evidence

EVIDENCE_PATH = Path("observability/policy/ci_evidence.jsonl")
RETEST_ON_DENY = True
RETEST_ON_QUARANTINE = True


def _get_redis_connection() -> tuple[Redis | None, str | None]:
    """REDIS_URL から Redis 接続を取得する。失敗時は理由文字列を返す。"""
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return None, "REDIS_URL not configured"
    try:
        conn = Redis.from_url(redis_url, socket_connect_timeout=2)
        conn.ping()
        return conn, None
    except Exception as exc:  # pragma: no cover - 接続環境依存
        return None, f"{type(exc).__name__}: {exc}"


def _emit_unavailable(
    *,
    job_id: str,
    run_id: str,
    server_id: int,
    reason: str,
    council_run_id: str | None,
    error: str,
    delay_hours: int,
    priority: str,
    snapshot_path: str | None,
) -> None:
    """Redis 不在時の Evidence を2件出力する。"""
    now_ts = datetime.now(timezone.utc).isoformat()
    events = [
        {
            "event": "retest_queue_unavailable",
            "job_id": job_id,
            "run_id": run_id,
            "server_id": server_id,
            "reason": reason,
            "council_run_id": council_run_id,
            "error": error,
            "fallback": "skip",
            "status": "skipped",
            "snapshot_path": snapshot_path,
            "evidence_path": str(EVIDENCE_PATH),
            "ts": now_ts,
        },
        {
            "event": "retest_scheduled",
            "job_id": job_id,
            "run_id": run_id,
            "server_id": server_id,
            "reason": reason,
            "council_run_id": council_run_id,
            "scheduled_at": None,
            "delay_hours": delay_hours,
            "priority": priority,
            "queue": "unavailable",
            "queue_system": "stub",
            "fallback": "skip",
            "status": "skipped",
            "snapshot_path": snapshot_path,
            "evidence_path": str(EVIDENCE_PATH),
            "ts": now_ts,
        },
    ]
    for ev in events:
        evidence.append(ev, path=EVIDENCE_PATH)


def enqueue_retest(
    server_id: int,
    reason: str,
    delay_hours: int = 24,
    priority: str = "normal",
    *,
    council_run_id: str | None = None,
    snapshot_path: str | None = None,
) -> str:
    """再検査ジョブを登録する。Redis 不在時も監査ログを残し job_id を返す。"""
    redis_conn, error = _get_redis_connection()
    job_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    if redis_conn is None:
        _emit_unavailable(
            job_id=job_id,
            run_id=run_id,
            server_id=server_id,
            reason=reason,
            council_run_id=council_run_id,
            error=error or "redis unavailable",
            delay_hours=delay_hours,
            priority=priority,
            snapshot_path=snapshot_path,
        )
        return job_id

    try:
        queue_name = {"low": "retest-low", "high": "retest-high"}.get(
            priority, "retest"
        )
        queue = Queue(queue_name, connection=redis_conn)
        job = queue.enqueue_in(
            timedelta(hours=delay_hours),
            "jobs.tasks.retest_server",
            server_id,
            reason,
            job_timeout="5m",
        )
        evidence.append(
            {
                "event": "retest_scheduled",
                "job_id": job.id,
                "run_id": run_id,
                "server_id": server_id,
                "reason": reason,
                "council_run_id": council_run_id,
                "scheduled_at": (
                    datetime.now(timezone.utc) + timedelta(hours=delay_hours)
                ).isoformat(),
                "delay_hours": delay_hours,
                "priority": priority,
                "queue": queue_name,
                "queue_system": "rq",
                "fallback": "none",
                "status": "scheduled",
                "snapshot_path": snapshot_path,
                "evidence_path": str(EVIDENCE_PATH),
                "ts": datetime.now(timezone.utc).isoformat(),
            },
            path=EVIDENCE_PATH,
        )
        return job.id
    except Exception as exc:  # pragma: no cover - enqueue 時の想定外エラー
        _emit_unavailable(
            job_id=job_id,
            run_id=run_id,
            server_id=server_id,
            reason=reason,
            council_run_id=council_run_id,
            error=f"RQ enqueue failed: {type(exc).__name__}: {exc}",
            delay_hours=delay_hours,
            priority=priority,
            snapshot_path=snapshot_path,
        )
        return job_id


def should_retest_on_decision(decision: str) -> bool:
    """評議結果に応じて再検査を行うか判定する。"""
    if decision == "quarantine":
        return RETEST_ON_QUARANTINE
    if decision == "deny":
        return RETEST_ON_DENY
    return False
