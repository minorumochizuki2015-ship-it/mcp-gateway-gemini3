#!/usr/bin/env python3
"""Lightweight pre-commit checks.

- Enforce trailing newline for JSONL files and plans/diff-plan.json.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET_PATTERNS = [
    "*.jsonl",
    "plans/diff-plan.json",
]


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def staged_files() -> list[str]:
    output = run_git(["diff", "--cached", "--name-only"])
    return [line for line in output.splitlines() if line.strip()]


def match_any(path: str, patterns: list[str]) -> bool:
    path_obj = Path(path)
    return any(path_obj.match(pattern) for pattern in patterns)


def has_trailing_newline(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return True
    if not data:
        return True
    return data.endswith(b"\n")


def main() -> int:
    files = staged_files()
    if not files:
        return 0

    violations: list[str] = []
    for path in files:
        if not match_any(path, TARGET_PATTERNS):
            continue
        full_path = ROOT / path
        if not has_trailing_newline(full_path):
            violations.append(path)

    if violations:
        print("[pre-commit] ERROR: missing trailing newline:")
        for item in sorted(violations):
            print(f"  - {item}")
        print("[pre-commit] Fix: add a newline at EOF and re-stage.")
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover - fail closed
        print(f"[pre-commit] ERROR: {exc}")
        sys.exit(2)
