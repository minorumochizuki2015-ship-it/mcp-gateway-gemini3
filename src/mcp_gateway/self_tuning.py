"""Self-tuning module for adjusting AI Council weights based on historical results.

Analyzes past council evaluations and adjusts security/utility/cost weights
using simple heuristics. Saves adjusted weights to council_params.json and
emits self_tune_run events to Evidence.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import sqlite_utils

from . import evidence

# Weight bounds (per userフィードバック)
MIN_WEIGHT = 0.1
MAX_WEIGHT = 0.7
EVIDENCE_PATH = Path("observability/policy/ci_evidence.jsonl")


def analyze_history(db: sqlite_utils.Database, lookback: int = 100) -> dict:
    """
    Analyze recent council evaluations to calculate metrics.

    Args:
        db: Database instance
        lookback: Number of recent evaluations to analyze

    Returns:
        Dict with deny_rate, quarantine_rate, avg_security_score, etc.
    """
    try:
        evaluations = list(
            db["council_evaluations"].rows_where(order_by="-created_at", limit=lookback)
        )
    except sqlite3.OperationalError:
        # テーブル未作成時は空として扱う
        return {
            "deny_rate": 0.0,
            "quarantine_rate": 0.0,
            "allow_rate": 0.0,
            "avg_security_score": 0.0,
            "lookback_count": 0,
        }

    if not evaluations:
        return {
            "deny_rate": 0.0,
            "quarantine_rate": 0.0,
            "allow_rate": 0.0,
            "avg_security_score": 0.0,
            "lookback_count": 0,
        }

    total = len(evaluations)
    deny_count = sum(1 for e in evaluations if e["decision"] == "deny")
    quarantine_count = sum(1 for e in evaluations if e["decision"] == "quarantine")
    allow_count = sum(1 for e in evaluations if e["decision"] == "allow")

    # Calculate average security score
    security_scores = []
    for e in evaluations:
        scores = json.loads(e["scores"])
        if "security" in scores:
            security_scores.append(scores["security"])

    avg_security = (
        sum(security_scores) / len(security_scores) if security_scores else 0.0
    )

    return {
        "deny_rate": deny_count / total,
        "quarantine_rate": quarantine_count / total,
        "allow_rate": allow_count / total,
        "avg_security_score": avg_security,
        "lookback_count": total,
    }


def adjust_weights(current_weights: dict, metrics: dict) -> dict:
    """
    Adjust weights using simple heuristics.

    Rules (per user feedback with bounds 0.2-0.8):
    - If deny_rate > 0.3: increase security_weight by 0.1
    - If deny_rate < 0.1: decrease security_weight by 0.05
    - Clip to [MIN_WEIGHT, MAX_WEIGHT]
    - Normalize to sum to 1.0

    Args:
        current_weights: Current weights dict {security, utility, cost}
        metrics: Metrics from analyze_history

    Returns:
        Adjusted weights dict
    """
    # Start with current weights
    security = current_weights.get("security", 0.5)
    utility = current_weights.get("utility", 0.3)
    cost = current_weights.get("cost", 0.2)

    deny_rate = metrics["deny_rate"]

    # Adjust security weight based on deny rate
    if deny_rate > 0.3:
        security += 0.1
    elif deny_rate < 0.1:
        security -= 0.05

    # Clip to bounds
    security = max(MIN_WEIGHT, min(MAX_WEIGHT, security))

    # Keep utility and cost proportional for now
    # In production, could add more sophisticated logic
    remaining = 1.0 - security
    if remaining > 0:
        utility_ratio = utility / (utility + cost) if (utility + cost) > 0 else 0.6
        utility = remaining * utility_ratio
        cost = remaining * (1 - utility_ratio)
    else:
        utility = 0.1
        cost = 0.1

    # Normalize to ensure sum = 1.0
    total = security + utility + cost
    if total > 0:
        security /= total
        utility /= total
        cost /= total

    return {
        "security": round(security, 3),
        "utility": round(utility, 3),
        "cost": round(cost, 3),
    }


def save_params(weights: dict, metrics: dict, path: str | Path) -> None:
    """
    Save council parameters to JSON file atomically.

    Args:
        weights: Adjusted weights dict
        metrics: Metrics used for adjustment
        path: Path to save params JSON
    """
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)

    params = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "weights": weights,
        "metrics": metrics,
    }

    # Atomic write
    tmp = path_obj.with_suffix(path_obj.suffix + ".tmp")
    tmp.write_text(
        json.dumps(params, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n"
    )
    tmp.replace(path_obj)


def load_params(path: str | Path = "data/council_params.json") -> dict:
    """
    Load council parameters from JSON file.

    Args:
        path: Path to params JSON

    Returns:
        Params dict or default weights if file doesn't exist
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return {"version": 1, "weights": {"security": 0.5, "utility": 0.3, "cost": 0.2}}

    return json.loads(path_obj.read_text(encoding="utf-8"))


def run_self_tuning(
    db_path: str | Path = "data/mcp_gateway.db",
    params_path: str | Path = "data/council_params.json",
    lookback: int = 100,
    strategy: str = "auto",
    evidence_path: str | Path = EVIDENCE_PATH,
    snapshot_path: str | Path | None = None,
    retest_on_fail: bool = True,
) -> dict:
    """
    Run self-tuning process: analyze history, adjust weights, save params.

    Args:
        db_path: Path to database
        params_path: Path to council params JSON
        lookback: Number of evaluations to analyze
        snapshot_path: ロールバック用スナップショットパス（異常時に記録）
        retest_on_fail: 異常時に再検査バックログを残すか

    Returns:
        Dict with previous_weights, new_weights, metrics, run_id
    """
    evidence_path = Path(evidence_path)
    try:
        db = sqlite_utils.Database(db_path)

        current_params = load_params(params_path)
        current_weights = current_params.get(
            "weights", {"security": 0.5, "utility": 0.3, "cost": 0.2}
        )

        metrics = analyze_history(db, lookback)
        new_weights = adjust_weights(current_weights, metrics)
        save_params(new_weights, metrics, params_path)

        run_id = evidence.append(
            {
                "event": "self_tune_run",
                "previous_weights": current_weights,
                "new_weights": new_weights,
                "metrics": metrics,
                "lookback_count": lookback,
                "strategy": strategy,
                "status": "pass",
            },
            path=evidence_path,
        )

        return {
            "run_id": run_id,
            "previous_weights": current_weights,
            "new_weights": new_weights,
            "metrics": metrics,
            "strategy": strategy,
            "status": "pass",
        }
    except Exception as exc:  # pragma: no cover - 例外時は Evidence のみ残す
        fail_event = {
            "event": "self_tune_run",
            "status": "fail",
            "strategy": strategy,
            "error": str(exc),
        }
        if snapshot_path is not None:
            fail_event["snapshot_path"] = str(snapshot_path)
        run_id = evidence.append(fail_event, path=evidence_path)
        if retest_on_fail:
            stub_common = {
                "job_id": run_id,
                "server_id": -1,
                "reason": f"self_tune_run_fail:{run_id}",
                "council_run_id": None,
                "snapshot_path": str(snapshot_path) if snapshot_path else None,
                "evidence_path": str(evidence_path),
                "queue_system": "stub",
                "fallback": "skip",
                "status": "skipped",
            }
            evidence.append(
                {
                    **stub_common,
                    "event": "retest_queue_unavailable",
                    "error": "self_tune_run failed",
                },
                path=evidence_path,
            )
            evidence.append(
                {
                    **stub_common,
                    "event": "retest_scheduled",
                    "scheduled_at": None,
                    "delay_hours": 0,
                    "priority": "normal",
                    "queue": "unavailable",
                },
                path=evidence_path,
            )
        raise
