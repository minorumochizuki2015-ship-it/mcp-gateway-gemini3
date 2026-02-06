"""Tests for auto_gate_decider module."""

# Import the auto_gate_decider functions
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.auto_gate_decider import evaluate_gate, load_rules, match_patterns
from src.mcp_gateway import ai_council, registry


@pytest.fixture(autouse=True)
def _set_evidence_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Evidence の出力先をテスト用に差し替える。"""
    evidence_path = tmp_path / "ci_evidence.jsonl"
    monkeypatch.setenv("MCP_GATEWAY_EVIDENCE_PATH", str(evidence_path))
    import src.mcp_gateway.evidence as ev
    from jobs import retest_queue

    original_append = ev.append
    monkeypatch.setattr(
        ev, "append", lambda event, path="": original_append(event, evidence_path)
    )
    monkeypatch.setattr(retest_queue, "EVIDENCE_PATH", evidence_path)
    monkeypatch.setattr(ai_council, "EVIDENCE_PATH", evidence_path)
    monkeypatch.setattr(ev, "SHADOW_MANIFEST", tmp_path / "shadow_manifest.jsonl")
    monkeypatch.setattr(ev, "SHADOW_CHAIN", tmp_path / "shadow_manifest.sha256")


def test_match_patterns_ui_files():
    """Test that UI files match UI gate patterns."""
    assert (
        match_patterns("apps/orchestrator-ui/index.ts", ["apps/orchestrator-ui/**"])
        is True
    )
    assert match_patterns("src/components/Button.tsx", ["**/*.tsx"]) is True
    assert match_patterns("styles/main.css", ["**/*.css"]) is True
    assert match_patterns("package.json", ["package.json"]) is True


def test_match_patterns_no_match():
    """Test that unrelated files don't match patterns."""
    assert match_patterns("README.md", ["**/*.py"]) is False
    assert match_patterns("docs/guide.md", ["**/*.ts"]) is False


def test_evaluate_gate_paths_matched():
    """Test gate evaluation when paths match."""
    gate_config = {"paths_any": ["**/*.py", "**/*.ts"]}
    changed_files = ["src/main.py", "README.md"]

    result = evaluate_gate("test_gate", gate_config, changed_files, None, [])

    assert result["decision"] == "RUN"
    assert "paths_matched" in result["reason"]
    assert "src/main.py" in result["matched_files"]


def test_evaluate_gate_branch_always_on():
    """Test gate evaluation for always-on branches."""
    gate_config = {
        "always_on_branches": ["main", "release/*"],
        "paths_any": ["**/*.py"],
    }

    result = evaluate_gate("test_gate", gate_config, [], "main", [])

    assert result["decision"] == "RUN"
    assert "branch_matched" in result["reason"]


def test_evaluate_gate_label_matched():
    """Test gate evaluation when labels match."""
    gate_config = {"labels_any": ["run-ui-gate", "manual-test"]}

    result = evaluate_gate("test_gate", gate_config, [], None, ["run-ui-gate"])

    assert result["decision"] == "RUN"
    assert "label_matched" in result["reason"]


def test_evaluate_gate_no_match():
    """Test gate evaluation when nothing matches."""
    gate_config = {"paths_any": ["**/*.py"]}
    changed_files = ["README.md", "docs/guide.md"]

    result = evaluate_gate("test_gate", gate_config, changed_files, None, [])

    assert result["decision"] == "SKIP"
    assert result["reason"] == "no_match"


def test_evaluate_gate_no_patterns():
    """Test gate evaluation with no patterns defined."""
    gate_config = {}

    result = evaluate_gate("test_gate", gate_config, ["any.py"], None, [])

    assert result["decision"] == "SKIP"
    assert result["reason"] == "no_patterns_defined"


def test_load_rules_structure(tmp_path: Path):
    """Test loading auto_gate_rules.yaml structure."""
    # Create test rules file
    rules_file = tmp_path / "test_rules.yaml"
    rules_file.write_text(
        """
version: 1
ui_gate:
  paths_any:
    - "**/*.ts"
    - "**/*.tsx"
sbom:
  dep_files:
    - "**/package.json"
""",
        encoding="utf-8",
    )

    rules = load_rules(str(rules_file))

    assert rules["version"] == 1
    assert "ui_gate" in rules
    assert "sbom" in rules
    assert "**/*.ts" in rules["ui_gate"]["paths_any"]


def test_mcpsafety_gate_triggers_on_manifest():
    """Test mcpsafety gate runs when manifest files change."""
    gate_config = {
        "dep_files": ["**/mcp.json", "**/manifest.json"],
        "paths_any": ["src/**/*.py"],
    }
    changed_files = ["mcp.json", "src/server.py"]

    result = evaluate_gate("mcpsafety", gate_config, changed_files, None, [])

    assert result["decision"] == "RUN"
    assert "paths_matched" in result["reason"]
    assert "mcp.json" in result["matched_files"]


def test_evaluate_gate_risk_override():
    """High risk or dangerous capabilities force RUN even without matches."""
    gate_config = {}
    result = evaluate_gate(
        "mcpsafety",
        gate_config,
        changed_files=[],
        branch=None,
        labels=[],
        risk_level="high",
        capabilities=["sampling"],
    )
    assert result["decision"] == "RUN"
    assert result["reason"] == "risk_override"


def test_ai_council_denies_high_risk(tmp_path: Path):
    """Critical risk_level should push council decision to deny."""
    db_file = tmp_path / "test.db"
    db = registry.init_db(db_file)
    server_id = registry.upsert_server(db, "srv", "http://example", "approved", origin_url="https://github.com/example/repo", origin_sha="a1b2c3d")
    db["scan_results"].insert(
        {
            "server_id": server_id,
            "run_id": "r1",
            "scan_type": "static",
            "status": "pass",
            "findings": "[]",
            "started_at": "2025-01-01T00:00:00Z",
            "ended_at": "2025-01-01T00:00:01Z",
        }
    )
    db["allowlist"].insert(
        {
            "server_id": server_id,
            "tools_exposed": "[]",
            "risk_level": "critical",
            "capabilities": "[]",
            "status": "proposed",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        }
    )

    result = ai_council.evaluate(db, server_id)

    assert result["decision"] == "deny"
