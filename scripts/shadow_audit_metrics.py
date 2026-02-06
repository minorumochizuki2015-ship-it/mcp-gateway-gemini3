"""Shadow Audit のメトリクスを算出し、JSON で出力・保存するスクリプト。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.shadow_audit_emit import calculate_metrics


def _write_json(data: dict, path: Path) -> None:
    """JSON を UTF-8 / LF で書き出す。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")


def main() -> int:
    """メトリクスを計算し、標準出力と指定パスへ出力する。"""
    parser = argparse.ArgumentParser(description="Calculate Shadow Audit metrics and optionally write to disk.")
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to write metrics JSON (also updates --latest path when provided).",
    )
    parser.add_argument(
        "--latest",
        type=Path,
        default=Path("observability/policy/shadow_metrics.latest.json"),
        help="Path to write the latest metrics snapshot (used when --output is set).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("observability/policy/shadow_audit"),
        help="Shadow Audit root directory (contains manifest.jsonl).",
    )
    args = parser.parse_args()

    try:
        metrics = calculate_metrics(root=args.root)
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"error: failed to calculate metrics: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(metrics, ensure_ascii=False, indent=2))

    if args.output:
        try:
            _write_json(metrics, args.output)
            if args.latest:
                _write_json(metrics, args.latest)
        except OSError as exc:  # pragma: no cover - filesystem edge
            print(f"error: failed to write metrics to {args.output}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
