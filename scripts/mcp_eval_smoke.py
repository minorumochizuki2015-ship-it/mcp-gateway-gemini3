from __future__ import annotations
import argparse
import json
import os
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from src.mcp_gateway import evidence, registry
from src.mcp_gateway import gateway as gateway_mod

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT_DIR / "tests" / "fixtures" / "mcp_eval" / "cases.jsonl"
DEFAULT_OUTPUT = ROOT_DIR / "observability" / "policy" / "mcp_eval_metrics.json"

def _load_cases(path: Path) -> list[dict]:
    cases: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        cases.append(json.loads(raw))
    return cases
def _bool_metrics() -> dict:
    return {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
def _update_metrics(bucket: dict, expected: bool, actual: bool) -> None:
    bucket["total"] += 1
    if expected and actual:
        bucket["tp"] += 1
    elif expected and not actual:
        bucket["fn"] += 1
    elif not expected and actual:
        bucket["fp"] += 1
    else:
        bucket["tn"] += 1
def _ratio(n: int, d: int) -> float | None:
    if d == 0:
        return None
    return round(n / d, 4)
def _finalize_metrics(bucket: dict) -> dict:
    precision = _ratio(bucket["tp"], bucket["tp"] + bucket["fp"])
    recall = _ratio(bucket["tp"], bucket["tp"] + bucket["fn"])
    accuracy = _ratio(bucket["tp"] + bucket["tn"], bucket["total"])
    bucket.update({"precision": precision, "recall": recall, "accuracy": accuracy})
    return bucket
def _eval_tool_manifest_drift(case: dict) -> bool:
    tools_original = case["input"]["tools_original"]
    tools_drift = case["input"]["tools_drift"]
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "mcp_eval.db"
        evidence_path = Path(tmpdir) / "mcp_eval_evidence.jsonl"
        prev_env = os.environ.get(registry.EVIDENCE_ENV_VAR)
        os.environ[registry.EVIDENCE_ENV_VAR] = str(evidence_path)
        try:
            db = registry.init_db(db_path)
            now = datetime.now(timezone.utc).isoformat()
            tools_hash = registry.compute_tools_manifest_hash(tools_original)
            row_id = db["allowlist"].insert(
                {
                    "server_id": 1,
                    "tools_exposed": json.dumps(tools_original, ensure_ascii=False),
                    "risk_level": "low",
                    "capabilities": "[]",
                    "status": "active",
                    "created_at": now,
                    "updated_at": now,
                    "tools_manifest_hash": tools_hash,
                }
            ).last_pk
            db["allowlist"].update(
                row_id,
                {"tools_exposed": json.dumps(tools_drift, ensure_ascii=False)},
            )
            registry.get_allowlist_entries(db, repair=True)
            status = db["allowlist"].get(row_id)["status"]
            return status == "revoked"
        finally:
            if prev_env is None:
                os.environ.pop(registry.EVIDENCE_ENV_VAR, None)
            else:
                os.environ[registry.EVIDENCE_ENV_VAR] = prev_env
def _eval_source_sink_policy(case: dict) -> str:
    entry = dict(case["input"]["entry"])
    tool_caps = {str(c).lower() for c in case["input"].get("tool_caps", []) if c}
    entry["capabilities"] = [
        str(c).lower() for c in entry.get("capabilities", []) if c
    ]
    blocked = gateway_mod._block_reason_for_run(entry, tool_caps)
    if blocked:
        return "deny"
    source_tag = gateway_mod._source_tag(entry)
    restricted_sinks = set(gateway_mod.DEFAULT_RESTRICTED_SINKS)
    combined_caps = tool_caps | set(entry["capabilities"])
    restricted_caps = sorted(combined_caps & restricted_sinks)
    if source_tag == gateway_mod.SOURCE_UNTRUSTED and restricted_caps:
        return "deny"
    return "allow"
def _eval_dlp(case: dict) -> bool:
    payload = case["input"]["payload"]
    findings = gateway_mod._detect_dlp(payload)
    return bool(findings)
def main() -> int:
    parser = argparse.ArgumentParser(description="Run MCP detection eval smoke.")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    cases = _load_cases(args.cases)
    by_kind: dict[str, dict] = defaultdict(_bool_metrics)
    results: list[dict] = []
    failures: list[str] = []
    for case in cases:
        kind = case["kind"]
        case_id = case["case_id"]
        if kind == "tool_manifest_drift":
            actual = _eval_tool_manifest_drift(case)
            expected = bool(case["expected"]["detected"])
            _update_metrics(by_kind[kind], expected, actual)
            passed = expected == actual
            result = {
                "case_id": case_id,
                "kind": kind,
                "expected": {"detected": expected},
                "actual": {"detected": actual},
                "pass": passed,
            }
        elif kind == "source_sink_policy":
            actual_decision = _eval_source_sink_policy(case)
            expected_decision = str(case["expected"]["decision"])
            expected = expected_decision == "deny"
            actual = actual_decision == "deny"
            _update_metrics(by_kind[kind], expected, actual)
            passed = expected_decision == actual_decision
            result = {
                "case_id": case_id,
                "kind": kind,
                "expected": {"decision": expected_decision},
                "actual": {"decision": actual_decision},
                "pass": passed,
            }
        elif kind == "dlp_detect":
            actual = _eval_dlp(case)
            expected = bool(case["expected"]["detected"])
            _update_metrics(by_kind[kind], expected, actual)
            passed = expected == actual
            result = {
                "case_id": case_id,
                "kind": kind,
                "expected": {"detected": expected},
                "actual": {"detected": actual},
                "pass": passed,
            }
        else:
            result = {
                "case_id": case_id,
                "kind": kind,
                "expected": case.get("expected", {}),
                "actual": {"error": "unknown kind"},
                "pass": False,
            }
        results.append(result)
        if not result["pass"]:
            failures.append(case_id)
    finalized = {k: _finalize_metrics(v) for k, v in by_kind.items()}
    summary = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cases_total": len(results),
        "cases_failed": len(failures),
        "failed_case_ids": failures,
        "metrics": finalized,
        "cases": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    status = "pass" if not failures else "fail"
    evidence.append(
        {
            "event": "mcp_eval_run",
            "status": status,
            "cases_total": len(results),
            "cases_failed": len(failures),
            "metrics_path": str(args.output),
        },
        path=ROOT_DIR / "observability" / "policy" / "ci_evidence.jsonl",
    )
    return 0 if not failures else 1
if __name__ == "__main__":
    raise SystemExit(main())
