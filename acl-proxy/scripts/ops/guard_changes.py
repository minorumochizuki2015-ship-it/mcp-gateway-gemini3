#!/usr/bin/env python3
"""Guard against unintended edits/deletes.

- Hard-block: deletion or zero-byte for protected paths.
- Warn: any change on protected_paths or warn_paths.

Uses git diff against HEAD. Safe no-op if repo is clean.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Change:
    status: str
    path: str


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "ORCH" / "STATE" / "change_scope.json"


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


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"missing config: {CONFIG_PATH}")
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_changes() -> list[Change]:
    output = run_git(["diff", "--name-status", "HEAD"])
    changes: list[Change] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        path = parts[-1]
        changes.append(Change(status=status, path=path))
    return changes


def parse_untracked() -> list[str]:
    output = run_git(["status", "--porcelain"])
    paths: list[str] = []
    for line in output.splitlines():
        if line.startswith("?? "):
            paths.append(line[3:])
    return paths


def is_zero_bytes(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size == 0
    except FileNotFoundError:
        return False


def glob_match(path: str, patterns: list[str]) -> bool:
    p = Path(path)
    for pattern in patterns:
        if p.match(pattern):
            return True
    return False


def main() -> int:
    config = load_config()
    protected = config.get("protected_paths", [])
    warn_paths = config.get("warn_paths", [])
    hard_block = config.get("hard_block", {})

    changes = parse_changes()
    untracked = parse_untracked()
    if not changes and not untracked:
        return 0

    hard_block_hits: list[str] = []
    warn_hits: list[str] = []

    for change in changes:
        path = change.path
        path_obj = ROOT / path
        is_protected = glob_match(path, protected)
        is_warn = glob_match(path, warn_paths)

        deleted = change.status.startswith("D")
        zero = is_zero_bytes(path_obj)

        if is_protected:
            warn_hits.append(path)
            if deleted and hard_block.get("delete", False):
                hard_block_hits.append(f"DELETE: {path}")
            if zero and hard_block.get("zero_bytes", False):
                hard_block_hits.append(f"ZERO_BYTES: {path}")
        elif is_warn:
            warn_hits.append(path)

    for path in untracked:
        is_protected = glob_match(path, protected)
        is_warn = glob_match(path, warn_paths)
        if is_protected:
            warn_hits.append(path)
            if hard_block.get("untracked", False):
                hard_block_hits.append(f"UNTRACKED: {path}")
        elif is_warn:
            warn_hits.append(path)

    if warn_hits:
        uniq_warn = sorted(set(warn_hits))
        print("[guard] WARN: protected/warn path changed:")
        for item in uniq_warn:
            print(f"  - {item}")

    if hard_block_hits:
        print("[guard] BLOCK: unsafe changes detected:")
        for item in sorted(set(hard_block_hits)):
            print(f"  - {item}")
        return 2

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover - fail closed
        print(f"[guard] ERROR: {exc}")
        sys.exit(2)
