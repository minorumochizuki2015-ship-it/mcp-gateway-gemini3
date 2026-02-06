"""Export ci_evidence.jsonl and Shadow Audit manifest.jsonl into a chat-to-html input JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

CI_EVIDENCE = Path("observability/policy/ci_evidence.jsonl")
SHADOW_MANIFEST = Path("observability/policy/shadow_audit/manifest.jsonl")
OUTPUT = Path("artifacts/chattohtml_input.json")


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            raise ValueError(f"invalid JSONL line in {path}") from None
    return records


def export_chattohtml_input() -> None:
    ci = _load_jsonl(CI_EVIDENCE)
    shadow = _load_jsonl(SHADOW_MANIFEST)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ci_evidence": ci, "shadow_audit": shadow}
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    print(f"[export] wrote {OUTPUT} (ci_evidence={len(ci)} events, shadow_audit={len(shadow)} events)")


if __name__ == "__main__":
    try:
        export_chattohtml_input()
    except Exception as exc:  # noqa: BLE001
        print(f"[export] error: {exc}", file=sys.stderr)
        sys.exit(1)
