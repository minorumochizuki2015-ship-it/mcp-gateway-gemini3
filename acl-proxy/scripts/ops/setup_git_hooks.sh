#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: git not found" >&2
  exit 2
fi

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: not a git worktree: $ROOT" >&2
  exit 2
fi

if [ ! -d "$ROOT/scripts/hooks" ]; then
  echo "ERROR: hooks dir missing: $ROOT/scripts/hooks" >&2
  exit 2
fi

git -C "$ROOT" config core.hooksPath scripts/hooks
value="$(git -C "$ROOT" config --get core.hooksPath || true)"

echo "OK: core.hooksPath=$value"
echo "Note: hooks use ./.venv/bin/python when available, else python3/python."
