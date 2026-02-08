"""AI Council for evaluating scan results and making allow/deny decisions.

Uses Gemini 3 structured output for intelligent security analysis with
rule-based fallback when the API is unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from . import evidence, registry

logger = logging.getLogger(__name__)

EVIDENCE_PATH = Path("observability/policy/ci_evidence.jsonl")

META_PROMPT_ID = "meta_judge_v2_gemini3"
META_PROMPT = (
    "You are MetaJudge, an AI security council that evaluates MCP server scan results. "
    "Analyze the security findings, risk level, and capabilities to make a deterministic "
    "allow/deny/quarantine decision. Be conservative: when in doubt, quarantine."
)
META_SEED = 42
META_TEMPERATURE = 0.0
META_MAX_TOKENS = 1024

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview")
GEMINI_API_KEY_ENV = "GOOGLE_API_KEY"


class Decision(str, Enum):
    allow = "allow"
    deny = "deny"
    quarantine = "quarantine"


class FindingAnalysis(BaseModel):
    """Analysis of a single security finding."""

    severity: str = Field(description="Severity level: critical, high, medium, low, info")
    category: str = Field(description="Finding category: injection, data_leak, privilege_escalation, misc")
    exploitable: bool = Field(description="Whether this finding is immediately exploitable")
    mitigation: str = Field(description="Suggested mitigation in one sentence")


class CouncilVerdict(BaseModel):
    """Structured verdict from the AI Council evaluation."""

    security_score: float = Field(ge=0.0, le=1.0, description="Security score 0.0 (critical) to 1.0 (clean)")
    utility_score: float = Field(ge=0.0, le=1.0, description="Utility/functionality score")
    cost_score: float = Field(ge=0.0, le=1.0, description="Cost efficiency score")
    decision: Decision = Field(description="Final decision: allow, deny, or quarantine")
    rationale: str = Field(description="Explanation for the decision in 1-3 sentences")
    findings_analysis: list[FindingAnalysis] = Field(
        default_factory=list,
        description="Analysis of each significant finding",
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the decision")


def load_weights(params_path: str | Path = "data/council_params.json") -> dict:
    """
    council_params.json から重みを読み込み、無い場合はデフォルトを返す。

    Args:
        params_path: council パラメータ JSON のパス

    Returns:
        重みディクショナリ {security, utility, cost, meta_judge}
    """
    default = {"security": 0.5, "utility": 0.2, "cost": 0.2, "meta_judge": 0.1}
    path = Path(params_path)
    if not path.exists():
        return default

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        weights = data.get("weights", default)
        for k, v in default.items():
            weights.setdefault(k, v)
        return weights
    except (json.JSONDecodeError, KeyError):
        return default


def _get_risk_info(db: Any, server_id: int) -> tuple[str, list[str]]:
    """AllowList 上の risk_level / capabilities を取得（なければデフォルト）。"""
    risk_level = "medium"
    capabilities: list[str] = []
    if "allowlist" in db.table_names():
        rows = list(
            db["allowlist"].rows_where(
                "server_id = ?", [server_id], order_by="-updated_at"
            )
        )
        if rows:
            row = rows[0]
            risk_level, capabilities = registry.derive_risk_context(row)
    return risk_level, capabilities


def _build_gemini_prompt(
    server_name: str,
    all_findings: list[dict],
    risk_level: str,
    capabilities: list[str],
    weights: dict,
) -> str:
    """Build the evaluation prompt for Gemini 3."""
    findings_text = json.dumps(all_findings, indent=2, default=str) if all_findings else "[]"
    return f"""{META_PROMPT}

## MCP Server Under Review
- Name: {server_name}
- Risk Level: {risk_level}
- Capabilities: {', '.join(capabilities) if capabilities else 'none declared'}

## Security Scan Findings
{findings_text}

## Evaluation Weights
- Security: {weights.get('security', 0.5)}
- Utility: {weights.get('utility', 0.2)}
- Cost: {weights.get('cost', 0.2)}
- Meta Judge: {weights.get('meta_judge', 0.1)}

## Decision Rules
1. If ANY critical or high severity finding exists → security_score must be < 0.5
2. If risk_level is "high" or "critical" → deny
3. If capabilities include "sampling", "network_write", or "file_write" → extra scrutiny
4. Weighted score >= 0.8 with no warnings → allow
5. Otherwise → quarantine for manual review

Analyze the findings and provide your verdict."""


def _evaluate_with_gemini(
    server_name: str,
    all_findings: list[dict],
    risk_level: str,
    capabilities: list[str],
    weights: dict,
) -> CouncilVerdict | None:
    """Call Gemini 3 for structured verdict. Returns None if unavailable."""
    api_key = os.getenv(GEMINI_API_KEY_ENV)
    if not api_key:
        logger.info("Gemini API key not configured, using rule-based fallback")
        return None

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        prompt = _build_gemini_prompt(
            server_name, all_findings, risk_level, capabilities, weights
        )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=CouncilVerdict,
                temperature=META_TEMPERATURE,
                max_output_tokens=META_MAX_TOKENS,
                seed=META_SEED,
            ),
        )

        verdict = CouncilVerdict.model_validate_json(response.text)
        logger.info(
            "Gemini verdict: decision=%s confidence=%.2f",
            verdict.decision.value,
            verdict.confidence,
        )
        return verdict

    except ImportError:
        logger.warning("google-genai not installed")
        return None
    except Exception as exc:
        logger.warning("Gemini API call failed: %s: %s", type(exc).__name__, exc)
        return None


def _evaluate_rule_based(
    all_findings: list[dict],
    risk_level: str,
    capabilities: list[str],
    weights: dict,
) -> CouncilVerdict:
    """Rule-based fallback evaluation (original logic)."""
    has_critical = any(f.get("severity") in ["critical", "high"] for f in all_findings)
    has_warnings = any(f.get("severity") in ["warning", "medium"] for f in all_findings)

    if has_critical:
        security_score = 0.0
    elif has_warnings:
        security_score = 0.5
    else:
        security_score = 1.0

    high_risk = risk_level in {"high", "critical"}
    dangerous_caps = {"network_write", "file_write"}
    has_sampling = "sampling" in capabilities
    has_dangerous_cap = bool(set(capabilities) & dangerous_caps)

    rationale_prefix = ""
    if high_risk:
        security_score = 0.0
        rationale_prefix = f"risk_level={risk_level}; "
    elif has_sampling:
        security_score = min(security_score, 0.5)
        rationale_prefix = "sampling capability present; "
    elif has_dangerous_cap:
        security_score = min(security_score, 0.5)
        rationale_prefix = "dangerous capabilities present; "

    scores = {
        "security": security_score,
        "utility": 0.8,
        "cost": 0.7,
    }
    scores["meta_judge"] = min(scores["security"], scores["utility"])

    weighted_score = sum(scores[k] * weights.get(k, 0.0) for k in weights)

    if scores["security"] < 0.5:
        decision = Decision.deny
        rationale = rationale_prefix + "Security score too low due to critical findings or high risk"
    elif has_warnings or has_sampling or has_dangerous_cap:
        decision = Decision.quarantine
        rationale = (
            rationale_prefix
            + f"Warnings or risk flags detected (security score: {security_score:.2f})"
        )
    elif weighted_score >= 0.8:
        decision = Decision.allow
        rationale = (
            rationale_prefix
            + f"Weighted score {weighted_score:.2f} meets threshold (weights: sec={weights['security']:.2f})"
        )
    else:
        decision = Decision.quarantine
        rationale = (
            rationale_prefix
            + f"Weighted score {weighted_score:.2f} below threshold, manual review recommended"
        )

    return CouncilVerdict(
        security_score=scores["security"],
        utility_score=scores["utility"],
        cost_score=scores["cost"],
        decision=decision,
        rationale=rationale,
        findings_analysis=[],
        confidence=0.8,
    )


def evaluate(
    db: Any,
    server_id: int,
    scan_run_id: str | None = None,
    *,
    snapshot_path: str | Path | None = None,
) -> dict:
    """
    スキャン結果を評議し allow/deny/quarantine を決定し、Evidence に記録する。

    Uses Gemini 3 structured output when available, falls back to rule-based scoring.

    Args:
        db: データベースインスタンス
        server_id: 評価対象サーバー ID
        scan_run_id: 評価対象のスキャン run_id（省略時は最新）
        snapshot_path: ロールバック用スナップショットパス（任意、Shadow Audit 記録に使用）

    Returns:
        scores/decision/rationale を含む評価結果
    """
    run_id = str(uuid.uuid4())
    server = registry.get_server(db, server_id)

    if not server:
        raise ValueError(f"Server {server_id} not found")

    # Get latest scan results for this server
    scan_results = list(
        db["scan_results"].rows_where(
            "server_id = ?", [server_id], order_by="-ended_at"
        )
    )

    if not scan_results:
        raise ValueError(f"No scan results found for server {server_id}")

    # Use latest scan or specific run
    if scan_run_id:
        relevant_scans = [s for s in scan_results if s["run_id"] == scan_run_id]
    else:
        latest_run_id = scan_results[0]["run_id"]
        relevant_scans = [s for s in scan_results if s["run_id"] == latest_run_id]

    risk_level, capabilities = _get_risk_info(db, server_id)

    # Collect all findings
    all_findings = []
    for scan in relevant_scans:
        findings = json.loads(scan["findings"])
        all_findings.extend(findings)

    # Load weights
    weights = load_weights()

    # Try Gemini 3 first, fall back to rule-based
    eval_method = "rule_based"
    verdict = _evaluate_with_gemini(
        server["name"], all_findings, risk_level, capabilities, weights
    )
    if verdict is not None:
        eval_method = "gemini3"
    else:
        verdict = _evaluate_rule_based(all_findings, risk_level, capabilities, weights)

    # Extract scores and decision from verdict
    scores = {
        "security": verdict.security_score,
        "utility": verdict.utility_score,
        "cost": verdict.cost_score,
        "meta_judge": min(verdict.security_score, verdict.utility_score),
    }
    decision = verdict.decision.value
    rationale = verdict.rationale

    # Save to registry
    registry.save_council_evaluation(
        db,
        server_id=server_id,
        run_id=run_id,
        scores=scores,
        decision=decision,
        rationale=rationale,
    )

    allowlist_update = {"status": "skipped", "server_id": server_id}
    if decision == "allow":
        promoted = registry.promote_allowlist_entry(db, server_id)
        allowlist_update = {
            "status": "promoted" if promoted else "missing_proposed",
            "server_id": server_id,
        }
    elif decision in {"deny", "quarantine"}:
        revoked = registry.revoke_allowlist_entries(db, server_id)
        allowlist_update = {
            "status": "revoked",
            "server_id": server_id,
            "revoked": revoked,
        }

    # Schedule retest using job queue with deterministic Evidence emission
    retest_reason = f"council_{decision}:{run_id}"
    stub_job_id = str(uuid.uuid4())
    stub_run_id = str(uuid.uuid4())
    try:
        from jobs import retest_queue

        should_retest = retest_queue.should_retest_on_decision(decision)
    except Exception as exc:  # pragma: no cover - safety fallback
        evidence.append(
            {
                "event": "retest_policy_error",
                "run_id": stub_run_id,
                "server_id": server_id,
                "reason": retest_reason,
                "council_run_id": run_id,
                "queue": "policy_error",
                "queue_system": "stub",
                "status": "skipped",
                "snapshot_path": "",
                "evidence_path": str(EVIDENCE_PATH),
                "error": f"policy_eval: {type(exc).__name__}: {exc}",
            }
        )
        should_retest = False

    shadow_status = "skipped"
    shadow_queue = "none"
    shadow_delay = 0
    shadow_priority = "skipped"

    if should_retest:
        if decision == "quarantine":
            delay_hours = 24
            priority = "normal"
        elif decision == "deny":
            delay_hours = 48
            priority = "low"
        else:
            delay_hours = 24
            priority = "normal"

        shadow_delay = delay_hours
        shadow_priority = priority

        try:
            retest_queue.enqueue_retest(
                server_id,
                retest_reason,
                delay_hours=delay_hours,
                priority=priority,
                council_run_id=run_id,
                snapshot_path=str(snapshot_path) if snapshot_path else None,
            )
            shadow_status = "scheduled"
            shadow_queue = "rq"
        except Exception as exc:  # pragma: no cover - Redis 以外の例外
            evidence.append(
                {
                    "event": "retest_queue_unavailable",
                    "job_id": stub_job_id,
                    "run_id": stub_run_id,
                    "server_id": server_id,
                    "reason": retest_reason,
                    "council_run_id": run_id,
                    "error": "enqueue_failed",
                    "exc": f"{type(exc).__name__}: {exc}",
                    "fallback": "skip",
                    "status": "skipped",
                    "queue_system": "stub",
                    "snapshot_path": str(snapshot_path) if snapshot_path else "",
                    "evidence_path": str(EVIDENCE_PATH),
                }
            )
            evidence.append(
                {
                    "event": "retest_scheduled",
                    "job_id": stub_job_id,
                    "run_id": stub_run_id,
                    "server_id": server_id,
                    "reason": retest_reason,
                    "council_run_id": run_id,
                    "priority": priority,
                    "delay_hours": delay_hours,
                    "queue": "unavailable",
                    "queue_system": "stub",
                    "fallback": "skip",
                    "status": "skipped",
                    "snapshot_path": str(snapshot_path) if snapshot_path else "",
                    "evidence_path": str(EVIDENCE_PATH),
                }
            )
            shadow_status = "unavailable"
            shadow_queue = "stub"
    elif decision in {"deny", "quarantine"}:
        evidence.append(
            {
                "event": "retest_scheduled",
                "job_id": stub_job_id,
                "run_id": stub_run_id,
                "server_id": server_id,
                "reason": retest_reason,
                "council_run_id": run_id,
                "priority": "skipped",
                "delay_hours": 0,
                "queue": "policy_disabled",
                "queue_system": "none",
                "fallback": "policy_disabled",
                "status": "skipped",
                "snapshot_path": str(snapshot_path) if snapshot_path else "",
                "evidence_path": str(EVIDENCE_PATH),
            }
        )
        shadow_status = "skipped"
        shadow_queue = "none"

    if decision in {"deny", "quarantine"}:
        evidence.append_shadow_event(
            {
                "event": "council_retest",
                "council_run_id": run_id,
                "server_id": server_id,
                "reason": retest_reason,
                "decision": decision,
                "status": shadow_status,
                "queue_system": shadow_queue,
                "delay_hours": shadow_delay,
                "priority": shadow_priority,
                "snapshot_path": str(snapshot_path) if snapshot_path else "",
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

    # Emit evidence event
    evidence.append(
        {
            "event": "mcp_council_run",
            "run_id": run_id,
            "server_id": server_id,
            "server_name": server["name"],
            "scores": scores,
            "decision": decision,
            "profiles_used": ["security", "utility", "cost", "meta_judge"],
            "weights": weights,
            "eval_method": eval_method,
            "gemini_model": GEMINI_MODEL if eval_method == "gemini3" else None,
            "verdict_confidence": verdict.confidence,
            "findings_analysis_count": len(verdict.findings_analysis),
            "deterministic_config": {
                "meta_judge_rule": "min(security, utility)",
                "weighted_threshold": 0.8,
                "meta_prompt_id": META_PROMPT_ID,
                "seed": META_SEED,
                "temperature": META_TEMPERATURE,
                "max_tokens": META_MAX_TOKENS,
            },
            "allowlist_update": allowlist_update,
            "risk_level": risk_level,
            "capabilities": capabilities,
        }
    )

    return {
        "run_id": run_id,
        "server_id": server_id,
        "scores": scores,
        "decision": decision,
        "rationale": rationale,
        "eval_method": eval_method,
        "confidence": verdict.confidence,
        "findings_analysis": [fa.model_dump() for fa in verdict.findings_analysis],
    }
