"""レーン上限・Rules version・スキャン鮮度を検証するゲート。"""

from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from scripts.shadow_audit_emit import emit_event

DEFAULT_RULE_HASHES = Path("observability/policy/rule_hashes.jsonl")
DEFAULT_GOLDEN = Path("observability/policy/golden/rules_version.txt")


def _load_golden(path: Path) -> str:
    """期待する rules_version を取得する。"""
    if not path.exists():
        raise FileNotFoundError(f"golden rules_version not found: {path}")
    return path.read_text(encoding="utf-8").strip()


def _load_current(path: Path) -> tuple[str, str]:
    """rule_hashes.jsonl から最新の rules_version を取得する。"""
    if not path.exists():
        return "", "skip:rule_hashes_missing"
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return "", "skip:rule_hashes_empty"
    last = json.loads(lines[-1])
    return str(last.get("rules_version", "")), "ok"


def _python_gate(lane: str, files: int, lines: int, expected: str, current: str) -> list[str]:
    """Python でのゲート判定（OPA 不在時のバックアップ）。"""
    limits = {"A": (3, 50), "B": (5, 200), "T": (20, 800)}
    violations: list[str] = []
    if lane in limits:
        max_files, max_lines = limits[lane]
        if files > max_files:
            violations.append(f"lane {lane}: files limit exceeded (>{max_files})")
        if lines > max_lines:
            violations.append(f"lane {lane}: lines limit exceeded (>{max_lines})")
    if lane not in ("A", "B", "C", "T"):
        violations.append(f"unknown lane: {lane}")
    if expected and current and expected != current:
        violations.append("rules_version mismatch")
    if expected and not current:
        violations.append("rules_version missing (current)")
    if not expected:
        violations.append("rules_version missing (expected)")
    return violations


def _parse_ts(value: str | None) -> datetime | None:
    """ISO 8601 文字列を UTC aware datetime に変換する。"""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _freshness_gate(
    last_scan_ts: str | None,
    epss_score: float,
    kev_hit: bool,
    *,
    expiry_days: int,
    threshold: float,
    base_score: float | None = None,
) -> tuple[list[str], dict[str, float | str | int]]:
    """鮮度・脅威スコアを判定し、違反と付随メタを返す。"""
    meta: dict[str, float | str | int] = {
        "expiry_days": expiry_days,
        "threshold": threshold,
        "epss_score": epss_score,
        "kev_hit": kev_hit,
        "age_days": "N/A",
        "decayed_score": "N/A",
    }
    violations: list[str] = []

    if kev_hit:
        violations.append("KEV hit: require immediate rescan/deny")

    if epss_score > threshold:
        violations.append(f"EPSS score high (> {threshold}): {epss_score}")

    ts = _parse_ts(last_scan_ts)
    if ts:
        age = (datetime.now(timezone.utc) - ts).days
        meta["age_days"] = age
        if expiry_days > 0 and age > expiry_days:
            violations.append(f"stale scan: age_days={age} > expiry_days={expiry_days}")
        if base_score is not None and base_score > 0 and threshold > 0 and age > 0 and expiry_days > 0:
            k = math.log(base_score / threshold) / expiry_days if base_score > threshold else 0
            decayed = base_score * math.exp(-k * age) if k > 0 else base_score
            meta["decayed_score"] = round(decayed, 4)
            if decayed < threshold:
                violations.append(f"decayed score below threshold ({decayed} < {threshold})")
    else:
        violations.append("last_scan_ts missing or invalid")

    return violations, meta


def main() -> int:
    """エントリーポイント。Python ベースでゲートを判定する。"""
    parser = argparse.ArgumentParser(description="lane / rules_version gate")
    parser.add_argument("--lane", required=True, help="A/B/C/T のいずれか")
    parser.add_argument("--files", type=int, required=True, help="対象差分のファイル数")
    parser.add_argument("--lines", type=int, required=True, help="対象差分の行数")
    parser.add_argument(
        "--golden-rules-version",
        default=DEFAULT_GOLDEN,
        help="期待する rules_version を記録したファイルパス",
    )
    parser.add_argument(
        "--rule-hashes",
        default=DEFAULT_RULE_HASHES,
        help="現在の rules_version を取得する rule_hashes.jsonl",
    )
    parser.add_argument(
        "--last-scan-ts",
        default="",
        help="最新スキャンのタイムスタンプ（ISO8601）。例: 2025-12-04T00:00:00Z",
    )
    parser.add_argument(
        "--base-score",
        type=float,
        default=0.0,
        help="最新スキャン時の評価スコア（任意、減衰計算用）",
    )
    parser.add_argument(
        "--epss-score",
        type=float,
        default=0.0,
        help="最新の EPSS スコア（0-1）。閾値を超えると再スキャン要求",
    )
    parser.add_argument(
        "--kev-hit",
        action="store_true",
        help="KEV Catalog に該当する場合に指定（即再スキャン/deny）",
    )
    parser.add_argument(
        "--expiry-days",
        type=int,
        default=14,
        help="スキャン有効期限（日）。超過で stale と判定",
    )
    parser.add_argument(
        "--epss-threshold",
        type=float,
        default=0.2,
        help="EPSS 再スキャン閾値（例: 0.2）",
    )
    parser.add_argument(
        "--emit-shadow",
        action="store_true",
        help="判定結果を Shadow Audit manifest に記録する",
    )
    args = parser.parse_args()

    expected = _load_golden(Path(args.golden_rules_version))
    current, current_status = _load_current(Path(args.rule_hashes))
    violations: list[str] = []
    violations.extend(_python_gate(args.lane, args.files, args.lines, expected, current))
    freshness_violations, freshness_meta = _freshness_gate(
        args.last_scan_ts,
        args.epss_score,
        args.kev_hit,
        expiry_days=args.expiry_days,
        threshold=args.epss_threshold,
        base_score=args.base_score if args.base_score > 0 else None,
    )
    violations.extend(freshness_violations)

    status = "allow" if not violations else "deny"
    if status == "allow":
        print("policy_gate: OK")
    else:
        print("policy_gate: NG")
        for v in violations:
            print(f"- {v}")

    if args.emit_shadow:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": "WORK",
            "event": "policy_gate",
            "status": status,
            "lane": args.lane,
            "files": args.files,
            "lines": args.lines,
            "rules_version_expected": expected,
            "rules_version_current": current,
            "rules_version_status": current_status,
            "epss_score": args.epss_score,
            "kev_hit": args.kev_hit,
            "expiry_days": args.expiry_days,
            "last_scan_ts": args.last_scan_ts,
            "freshness_meta": freshness_meta,
            "violations": violations,
        }
        emit_event(record)

    return 0 if status == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
