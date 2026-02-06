#!/usr/bin/env python3
"""Lightweight pre-push checks.

- If workflow files changed, run actionlint.
- Enforce upstream-behind guard and nearby repo sweep.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "ORCH" / "STATE" / "change_scope.json"

WORKFLOW_PATTERNS = [
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
]

SKIP_ACTIONLINT_ENV = "MCP_GATEWAY_PREPUSH_SKIP_ACTIONLINT"
NEARBY_SWEEP_ALLOW_ENV = "MCP_GATEWAY_NEARBY_SWEEP_ALLOW"
NEARBY_SWEEP_REASON_ENV = "MCP_GATEWAY_NEARBY_SWEEP_REASON"
ALLOW_BEHIND_ENV = "MCP_GATEWAY_PREPUSH_ALLOW_BEHIND"
ALLOW_BEHIND_REASON_ENV = "MCP_GATEWAY_PREPUSH_ALLOW_BEHIND_REASON"

DEFAULT_NEARBY_REPOS = [
    "../mcp-gateway",
    "../mcp-gateway-release",
]


def load_nearby_repos() -> list[str]:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            repos = data.get("nearby_repos", [])
            if repos:
                return [str(repo) for repo in repos]
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_NEARBY_REPOS


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


def run_git_in_repo(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def match_any(path: str, patterns: list[str]) -> bool:
    path_obj = Path(path)
    return any(path_obj.match(pattern) for pattern in patterns)


def find_base() -> str | None:
    try:
        upstream = run_git(["rev-parse", "--verify", "@{u}"]).strip()
    except RuntimeError:
        return None
    return run_git(["merge-base", "HEAD", upstream]).strip()


def log_context() -> None:
    branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"]).strip()
    print(f"[pre-push] root: {ROOT}")
    print(f"[pre-push] branch: {branch}")


def check_toplevel() -> int:
    try:
        toplevel = run_git(["rev-parse", "--show-toplevel"]).strip()
    except RuntimeError as exc:
        print(f"[pre-push] ERROR: failed to resolve git root: {exc}")
        return 2
    if Path(toplevel).resolve() != ROOT.resolve():
        print("[pre-push] ERROR: git root mismatch")
        print(f"[pre-push] expected: {ROOT}")
        print(f"[pre-push] actual:   {toplevel}")
        return 2
    return 0


def sweep_nearby_repos() -> int:
    if os.environ.get(NEARBY_SWEEP_ALLOW_ENV) == "1":
        reason = os.environ.get(NEARBY_SWEEP_REASON_ENV, "").strip()
        if not reason:
            print(
                f"[pre-push] ERROR: {NEARBY_SWEEP_ALLOW_ENV}=1 requires"
                f" {NEARBY_SWEEP_REASON_ENV}"
            )
            return 2
        print(f"[pre-push] nearby sweep skipped ({reason})")
        return 0
    dirty: list[str] = []
    for repo in load_nearby_repos():
        repo_path = (ROOT / repo).resolve()
        if not repo_path.exists():
            continue
        if not (repo_path / ".git").exists():
            continue
        try:
            output = run_git_in_repo(repo_path, ["status", "--porcelain"]).strip()
        except RuntimeError:
            continue
        if output:
            dirty.append(str(repo_path))
    if dirty:
        print("[pre-push] ERROR: nearby repo(s) have uncommitted changes:")
        for path in sorted(dirty):
            print(f"  - {path}")
        return 2
    return 0


def check_upstream_behind() -> int:
    if os.environ.get(ALLOW_BEHIND_ENV) == "1":
        reason = os.environ.get(ALLOW_BEHIND_REASON_ENV, "").strip()
        if not reason:
            print(
                f"[pre-push] ERROR: {ALLOW_BEHIND_ENV}=1 requires"
                f" {ALLOW_BEHIND_REASON_ENV}"
            )
            return 2
        print(f"[pre-push] behind check skipped ({reason})")
        return 0
    try:
        run_git(["rev-parse", "--verify", "@{u}"])
    except RuntimeError:
        return 0
    counts = run_git(["rev-list", "--left-right", "--count", "HEAD...@{u}"]).strip()
    if not counts:
        return 0
    left, right = counts.split()
    behind = int(right)
    if behind > 0:
        upstream_name = run_git(["rev-parse", "--abbrev-ref", "@{u}"]).strip()
        print(f"[pre-push] ERROR: branch is behind {upstream_name} by {behind} commit(s)")
        print("[pre-push] Run: git fetch && git rebase @{u} (or git pull --rebase)")
        return 2
    return 0


def changed_files() -> tuple[list[str], bool]:
    base = find_base()
    if base:
        output = run_git(["diff", "--name-only", f"{base}..HEAD"])
        return [line for line in output.splitlines() if line.strip()], False
    try:
        run_git(["rev-parse", "--verify", "HEAD~1"])
        output = run_git(["diff", "--name-only", "HEAD~1..HEAD"])
        return [line for line in output.splitlines() if line.strip()], False
    except RuntimeError:
        output = run_git(["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"])
        return [line for line in output.splitlines() if line.strip()], True


def run_actionlint() -> int:
    if os.environ.get(SKIP_ACTIONLINT_ENV) == "1":
        print(f"[pre-push] actionlint skipped ({SKIP_ACTIONLINT_ENV}=1)")
        return 0
    if not shutil.which("actionlint"):
        print("[pre-push] actionlint not found. Install it or set:")
        print(f"  {SKIP_ACTIONLINT_ENV}=1")
        return 2
    print("[pre-push] actionlint")
    return subprocess.run(["actionlint"], cwd=ROOT, check=False).returncode


def main() -> int:
    if check_toplevel() != 0:
        return 2
    log_context()
    if check_upstream_behind() != 0:
        return 2
    if sweep_nearby_repos() != 0:
        return 2

    files, _ = changed_files()
    workflow_changed = any(match_any(path, WORKFLOW_PATTERNS) for path in files)

    if workflow_changed:
        code = run_actionlint()
        if code != 0:
            return code
    else:
        print("[pre-push] no workflow changes detected")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover - fail closed
        print(f"[pre-push] ERROR: {exc}")
        sys.exit(2)
