"""Auto Gate Decider - Evaluate gate rules based on changed files.

Evaluates gates defined in auto_gate_rules.yaml against changed files
between two git commits and emits auto_gate_decision events to Evidence.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path, PurePath

import yaml

# Add parent to path for evidence import
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.mcp_gateway import evidence


def load_rules(rules_path: str = "auto_gate_rules.yaml") -> dict:
    """Load auto gate rules from YAML file."""
    with open(rules_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_changed_files(base_sha: str, head_sha: str) -> list[str]:
    """
    Get list of changed files between two commits using git diff.

    Args:
        base_sha: Base commit SHA
        head_sha: Head commit SHA

    Returns:
        List of changed file paths
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_sha}..{head_sha}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.CalledProcessError as e:
        print(f"Error getting changed files: {e}", file=sys.stderr)
        return []


def match_patterns(file_path: str, patterns: list[str]) -> bool:
    """
    Check if file path matches any of the glob patterns.

    Args:
        file_path: File path to check
        patterns: List of glob patterns

    Returns:
        True if any pattern matches
    """
    # Use PurePath for consistent cross-platform matching
    p = PurePath(file_path.replace("\\", "/"))

    for pattern in patterns:
        pat = pattern.replace("\\", "/")

        # 1) Try direct pathlib match
        if p.match(pat):
            return True

        # 2) If pattern starts with "**/", also try basename match
        if pat.startswith("**/") and p.name == pat.split("/", 1)[1]:
            return True

        # 3) Simplify "**/" segments for top-level files (e.g., src/**/*.py -> src/*.py)
        simplified = pat.replace("**/", "")
        if p.match(simplified):
            return True
    return False


def evaluate_gate(
    gate_name: str,
    gate_config: dict,
    changed_files: list[str],
    branch: str | None,
    labels: list[str],
    risk_level: str = "",
    capabilities: list[str] | None = None,
) -> dict:
    """
    Evaluate a single gate against changed files.

    Args:
        gate_name: Name of the gate
        gate_config: Gate configuration from rules
        changed_files: List of changed file paths
        branch: Current branch name
        labels: List of PR labels

    Returns:
        Dict with decision (RUN/SKIP), reason, and matched_files
    """
    capabilities = capabilities or []

    # Check branch always-on
    always_on_branches = gate_config.get("always_on_branches", [])
    if branch and branch in always_on_branches:
        return {
            "decision": "RUN",
            "reason": f"branch_matched: {branch}",
            "matched_files": [],
        }

    # Check labels
    labels_any = gate_config.get("labels_any", [])
    if labels_any:
        for label in labels:
            if label in labels_any:
                return {
                    "decision": "RUN",
                    "reason": f"label_matched: {label}",
                    "matched_files": [],
                }

    # Check file paths
    paths_any = gate_config.get("paths_any", [])
    dep_files = gate_config.get("dep_files", [])
    requires_update_if_paths_any = gate_config.get("requires_update_if_paths_any", [])

    all_patterns = paths_any + dep_files + requires_update_if_paths_any

    high_risk = risk_level.lower() in {"high", "critical"}
    cap_set = {str(c).lower() for c in capabilities}
    risk_caps = {"sampling", "file_write", "network_write"}

    if not all_patterns:
        if high_risk or cap_set & risk_caps:
            return {"decision": "RUN", "reason": "risk_override", "matched_files": []}
        # No patterns defined, skip by default
        return {
            "decision": "SKIP",
            "reason": "no_patterns_defined",
            "matched_files": [],
        }

    matched = []
    for file_path in changed_files:
        if match_patterns(file_path, all_patterns):
            matched.append(file_path)

    if matched:
        return {
            "decision": "RUN",
            "reason": f"paths_matched: {len(matched)} files",
            "matched_files": matched,
        }

    if high_risk or cap_set & risk_caps:
        return {"decision": "RUN", "reason": "risk_override", "matched_files": []}

    return {"decision": "SKIP", "reason": "no_match", "matched_files": []}


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate Auto Gate rules and emit decisions to Evidence"
    )
    parser.add_argument("--base", required=True, help="Base commit SHA")
    parser.add_argument("--head", required=True, help="Head commit SHA")
    parser.add_argument("--branch", help="Branch name (e.g., main, feature/foo)")
    parser.add_argument("--labels", help="Comma-separated list of PR labels")
    parser.add_argument("--pr-number", help="Pull request number")
    parser.add_argument(
        "--risk-level",
        help="Optional risk_level for gate bias (e.g., medium/high/critical)",
        default="",
    )
    parser.add_argument(
        "--capabilities",
        help="Optional comma-separated capabilities (e.g., sampling,file_write)",
        default="",
    )
    parser.add_argument(
        "--rules",
        default="auto_gate_rules.yaml",
        help="Path to auto gate rules YAML (default: auto_gate_rules.yaml)",
    )
    parser.add_argument(
        "--output",
        default="observability/policy/ci_evidence.jsonl",
        help="Evidence output file (default: observability/policy/ci_evidence.jsonl)",
    )

    args = parser.parse_args()

    # Parse labels
    labels = []
    if args.labels:
        labels = [label.strip() for label in args.labels.split(",")]
    risk_level = args.risk_level or os.getenv("MCP_GATEWAY_RISK_LEVEL", "")
    capabilities = []
    if args.capabilities:
        capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]
    else:
        env_caps = os.getenv("MCP_GATEWAY_CAPABILITIES", "")
        if env_caps:
            capabilities = [c.strip() for c in env_caps.split(",") if c.strip()]

    # Load rules
    rules = load_rules(args.rules)

    # Get changed files
    changed_files = get_changed_files(args.base, args.head)

    print(f"Evaluating gates for {len(changed_files)} changed files...")
    print(f"Base: {args.base}, Head: {args.head}")
    if args.branch:
        print(f"Branch: {args.branch}")
    if labels:
        print(f"Labels: {', '.join(labels)}")

    # Evaluate each gate
    decisions = []
    for gate_name, gate_config in rules.items():
        if gate_name == "version" or gate_name == "global":
            continue  # Skip meta keys

        result = evaluate_gate(
            gate_name,
            gate_config,
            changed_files,
            args.branch,
            labels,
            risk_level=risk_level,
            capabilities=capabilities,
        )

        # Emit evidence event
        event = {
            "event": "auto_gate_decision",
            "gate": gate_name,
            "decision": result["decision"],
            "reason": result["reason"],
            "base_sha": args.base,
            "head_sha": args.head,
            "branch": args.branch or "",
            "pr_number": args.pr_number or "",
            "matched_files": result["matched_files"][:10],  # Limit to 10 for brevity
            "matched_count": len(result["matched_files"]),
            "risk_level": risk_level,
            "capabilities": capabilities,
        }

        evidence.append(event, args.output)
        decisions.append(event)

        status = "✓ RUN" if result["decision"] == "RUN" else "○ SKIP"
        print(f"{status} {gate_name}: {result['reason']}")

    print(f"\nDecisions emitted to {args.output}")

    # Exit success regardless; decisions are logged. CI can inspect Evidence if needed.
    sys.exit(0)


if __name__ == "__main__":
    main()
