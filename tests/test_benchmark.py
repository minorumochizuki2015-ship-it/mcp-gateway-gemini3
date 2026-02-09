"""Tests for benchmark.py script."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import benchmark  # noqa: E402


def test_load_corpus():
    """Corpus file loads and has expected structure."""
    corpus = benchmark._load_corpus(benchmark.CORPUS_PATH)
    assert len(corpus) == 26
    assert all(isinstance(case, dict) for case in corpus)
    assert all("case_id" in case for case in corpus)
    assert all("url" in case for case in corpus)
    assert all("expected_malicious" in case for case in corpus)

    # Check benign/malicious split
    benign = [c for c in corpus if not c["expected_malicious"]]
    malicious = [c for c in corpus if c["expected_malicious"]]
    assert len(benign) == 13
    assert len(malicious) == 13


def test_metrics_calculation():
    """TP/FP/TN/FN → precision/recall/f1 calculation."""
    # Perfect detection: tp=10, tn=10, fp=0, fn=0
    m = benchmark._metrics(tp=10, fp=0, tn=10, fn=0)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["accuracy"] == 1.0

    # 50% precision, 100% recall
    m = benchmark._metrics(tp=10, fp=10, tn=0, fn=0)
    assert m["precision"] == 0.5
    assert m["recall"] == 1.0
    assert m["f1"] == round(2 * 0.5 * 1.0 / (0.5 + 1.0), 4)

    # Zero division cases
    m = benchmark._metrics(tp=0, fp=0, tn=10, fn=10)
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1"] == 0.0


def test_rule_based_benchmark_runs():
    """Full benchmark with rule-based only completes."""
    corpus = benchmark._load_corpus(benchmark.CORPUS_PATH)

    # Mock fast_scan to avoid network calls
    with patch("benchmark.causal_sandbox.fast_scan") as mock_fast:
        mock_verdict = MagicMock()
        mock_verdict.classification.value = "benign"
        mock_fast.return_value = mock_verdict

        results = benchmark.run_benchmark(corpus, include_gemini=False)

        assert "timestamp" in results
        assert results["corpus_size"] == 26
        assert "rule_based" in results["methods"]
        assert "gemini_agent" not in results["methods"]
        assert len(results["cases"]) == 26

        # Verify metrics fields
        rule = results["methods"]["rule_based"]
        assert all(
            k in rule
            for k in [
                "tp",
                "fp",
                "tn",
                "fn",
                "precision",
                "recall",
                "f1",
                "accuracy",
                "avg_latency_ms",
            ]
        )


def test_benchmark_output_structure():
    """Output JSON has required fields."""
    corpus = benchmark._load_corpus(benchmark.CORPUS_PATH)

    with patch("benchmark.causal_sandbox.fast_scan") as mock_fast:
        mock_verdict = MagicMock()
        mock_verdict.classification.value = "benign"
        mock_fast.return_value = mock_verdict

        results = benchmark.run_benchmark(corpus, include_gemini=False)

        # Top-level structure
        assert "timestamp" in results
        assert "corpus_size" in results
        assert "methods" in results
        assert "cases" in results

        # Case structure
        case = results["cases"][0]
        assert "case_id" in case
        assert "url" in case
        assert "expected_malicious" in case
        assert "rule_based" in case
        assert "detected" in case["rule_based"]
        assert "classification" in case["rule_based"]
        assert "latency_ms" in case["rule_based"]


def test_gemini_advantage_computed():
    """When gemini included, advantage delta computed."""
    corpus = benchmark._load_corpus(benchmark.CORPUS_PATH)

    with patch("benchmark.causal_sandbox.fast_scan") as mock_fast, patch(
        "benchmark.causal_sandbox.run_agent_scan"
    ) as mock_agent:
        # Rule-based: always benign
        mock_verdict_rule = MagicMock()
        mock_verdict_rule.classification.value = "benign"
        mock_fast.return_value = mock_verdict_rule

        # Gemini: perfect detection (malicious for M-* cases, benign for B-*)
        def agent_side_effect(url):
            mock_result = MagicMock()
            mock_result.verdict.classification.value = (
                "phishing"
                if any(
                    bad in url
                    for bad in [".tk", ".ml", ".gq", ".cf", "jsonrpc"]
                )
                else "benign"
            )
            return mock_result

        mock_agent.side_effect = agent_side_effect

        results = benchmark.run_benchmark(corpus, include_gemini=True)

        assert "gemini_agent" in results["methods"]
        assert "gemini_advantage" in results

        # Verify advantage fields
        adv = results["gemini_advantage"]
        assert "precision_delta" in adv
        assert "recall_delta" in adv
        assert "f1_delta" in adv

        # Gemini should outperform (or equal) rule-based
        assert adv["precision_delta"].startswith("+")
        assert adv["recall_delta"].startswith("+")
        assert adv["f1_delta"].startswith("+")
