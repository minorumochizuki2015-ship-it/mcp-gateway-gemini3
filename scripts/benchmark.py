"""Reproducible benchmark: rule-based vs Gemini detection rates.

Usage:
    python scripts/benchmark.py                    # Rule-based only (no API key needed)
    GOOGLE_API_KEY=xxx python scripts/benchmark.py # Full comparison with Gemini
    GOOGLE_API_KEY=xxx python scripts/benchmark.py --gemini  # Explicit Gemini mode
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.mcp_gateway import causal_sandbox

CORPUS_PATH = ROOT / "tests" / "fixtures" / "benchmark_corpus.jsonl"
DEFAULT_OUTPUT = ROOT / "results" / "benchmark_results.json"


def _load_corpus(path: Path) -> list[dict]:
    """Load JSONL corpus file."""
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        cases.append(json.loads(line))
    return cases


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    """Calculate precision, recall, F1, accuracy."""
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    accuracy = (tp + tn) / total if total > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def run_benchmark(
    corpus: list[dict], include_gemini: bool = False
) -> dict:
    """Run benchmark on corpus with rule-based and optional Gemini methods."""
    rule_tp = rule_fp = rule_tn = rule_fn = 0
    gemini_tp = gemini_fp = gemini_tn = gemini_fn = 0
    rule_latencies = []
    gemini_latencies = []
    case_results = []

    for case in corpus:
        url = case["url"]
        expected_malicious = case["expected_malicious"]
        expected_classification = case.get("expected_classification", "unknown")

        # Rule-based scan
        t0 = time.perf_counter()
        try:
            rule_verdict = causal_sandbox.fast_scan(url)
            rule_detected = (
                rule_verdict.classification.value != "benign"
            )
            rule_class = rule_verdict.classification.value
        except Exception:
            rule_detected = False
            rule_class = "error"
        rule_ms = round((time.perf_counter() - t0) * 1000, 1)
        rule_latencies.append(rule_ms)

        # Update rule-based metrics
        if expected_malicious and rule_detected:
            rule_tp += 1
        elif expected_malicious and not rule_detected:
            rule_fn += 1
        elif not expected_malicious and rule_detected:
            rule_fp += 1
        else:
            rule_tn += 1

        result = {
            "case_id": case["case_id"],
            "url": url,
            "expected_malicious": expected_malicious,
            "expected_classification": expected_classification,
            "rule_based": {
                "detected": rule_detected,
                "classification": rule_class,
                "latency_ms": rule_ms,
            },
        }

        # Gemini Agent Scan (only if API key available)
        if include_gemini:
            t0 = time.perf_counter()
            try:
                agent_result = causal_sandbox.run_agent_scan(url)
                gemini_detected = (
                    agent_result.verdict.classification.value != "benign"
                )
                gemini_class = agent_result.verdict.classification.value
            except Exception:
                gemini_detected = False
                gemini_class = "error"
            gemini_ms = round((time.perf_counter() - t0) * 1000, 1)
            gemini_latencies.append(gemini_ms)

            # Update Gemini metrics
            if expected_malicious and gemini_detected:
                gemini_tp += 1
            elif expected_malicious and not gemini_detected:
                gemini_fn += 1
            elif not expected_malicious and gemini_detected:
                gemini_fp += 1
            else:
                gemini_tn += 1

            result["gemini_agent"] = {
                "detected": gemini_detected,
                "classification": gemini_class,
                "latency_ms": gemini_ms,
            }

        case_results.append(result)

    # Compute metrics
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpus_size": len(corpus),
        "methods": {
            "rule_based": {
                **_metrics(rule_tp, rule_fp, rule_tn, rule_fn),
                "avg_latency_ms": (
                    round(sum(rule_latencies) / len(rule_latencies), 1)
                    if rule_latencies
                    else 0
                ),
                "p95_latency_ms": (
                    round(
                        sorted(rule_latencies)[
                            int(len(rule_latencies) * 0.95)
                        ],
                        1,
                    )
                    if rule_latencies
                    else 0
                ),
            },
        },
        "cases": case_results,
    }

    if include_gemini:
        output["methods"]["gemini_agent"] = {
            **_metrics(gemini_tp, gemini_fp, gemini_tn, gemini_fn),
            "avg_latency_ms": (
                round(sum(gemini_latencies) / len(gemini_latencies), 1)
                if gemini_latencies
                else 0
            ),
            "p95_latency_ms": (
                round(
                    sorted(gemini_latencies)[
                        int(len(gemini_latencies) * 0.95)
                    ],
                    1,
                )
                if gemini_latencies
                else 0
            ),
        }
        # Compute advantage
        rule_m = output["methods"]["rule_based"]
        gem_m = output["methods"]["gemini_agent"]
        output["gemini_advantage"] = {
            "precision_delta": f"+{gem_m['precision'] - rule_m['precision']:.3f}",
            "recall_delta": f"+{gem_m['recall'] - rule_m['recall']:.3f}",
            "f1_delta": f"+{gem_m['f1'] - rule_m['f1']:.3f}",
        }

    return output


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MCP Gateway Detection Benchmark"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument(
        "--gemini",
        action="store_true",
        help="Include Gemini Agent comparison (requires GOOGLE_API_KEY)",
    )
    args = parser.parse_args()

    corpus = _load_corpus(args.corpus)
    include_gemini = args.gemini or bool(os.getenv("GOOGLE_API_KEY"))

    print(
        f"Running benchmark: {len(corpus)} cases, "
        f"gemini={'yes' if include_gemini else 'no (rule-based only)'}"
    )
    results = run_benchmark(corpus, include_gemini)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Summary
    rule = results["methods"]["rule_based"]
    print(
        f"\nRule-based: precision={rule['precision']}, "
        f"recall={rule['recall']}, f1={rule['f1']}, "
        f"avg_latency={rule['avg_latency_ms']}ms"
    )
    if "gemini_agent" in results["methods"]:
        gem = results["methods"]["gemini_agent"]
        print(
            f"Gemini:     precision={gem['precision']}, "
            f"recall={gem['recall']}, f1={gem['f1']}, "
            f"avg_latency={gem['avg_latency_ms']}ms"
        )
        adv = results["gemini_advantage"]
        print(
            f"Advantage:  precision{adv['precision_delta']}, "
            f"recall{adv['recall_delta']}, f1{adv['f1_delta']}"
        )

    print(f"\nResults written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
