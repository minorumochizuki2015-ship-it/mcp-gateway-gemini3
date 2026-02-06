import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "shadow_audit_emit.py"
try:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from scripts.shadow_audit_emit import (emit_event,  # type: ignore
                                           verify_chain)
except ModuleNotFoundError:
    spec = importlib.util.spec_from_file_location("shadow_audit_emit", MODULE_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    emit_event = mod.emit_event  # type: ignore
    verify_chain = mod.verify_chain  # type: ignore


def test_emit_updates_chain(tmp_path):
    root = tmp_path / "shadow"
    first = emit_event(
        {
            "ts": "2025-01-01T00:00:00Z",
            "actor": "WORK",
            "event": "PLAN",
            "rule_ids": [],
            "policy_refs": [],
            "reasoning_digest": "a",
            "inputs_hash": "in1",
            "outputs_hash": "out1",
            "approval_state": "none",
            "approvals_row_id": "",
        },
        root,
    )
    second = emit_event(
        {
            "ts": "2025-01-01T00:00:01Z",
            "actor": "WORK",
            "event": "TEST",
            "rule_ids": [],
            "policy_refs": [],
            "reasoning_digest": "b",
            "inputs_hash": "in2",
            "outputs_hash": "out2",
            "approval_state": "none",
            "approvals_row_id": "",
        },
        root,
    )
    assert first != second
    assert verify_chain(root)
