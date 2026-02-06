import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "shadow_audit_emit.py"
try:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from scripts.shadow_audit_emit import (emit_event,  # type: ignore
                                          calculate_metrics,
                                          verify_manifest_signature,
                                           verify_chain)
except ModuleNotFoundError:
    spec = importlib.util.spec_from_file_location("shadow_audit_emit", MODULE_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    emit_event = mod.emit_event  # type: ignore
    calculate_metrics = mod.calculate_metrics  # type: ignore
    verify_manifest_signature = mod.verify_manifest_signature  # type: ignore
    verify_chain = mod.verify_chain  # type: ignore


def _record(n: int) -> dict:
    return {
        "ts": f"2025-01-01T00:00:0{n}Z",
        "actor": "WORK",
        "event": "PLAN",
        "rule_ids": [],
        "policy_refs": [],
        "reasoning_digest": f"r{n}",
        "inputs_hash": f"in{n}",
        "outputs_hash": f"out{n}",
        "approval_state": "none",
        "approvals_row_id": "",
    }


def test_chain_appends_and_verifies(tmp_path: Path):
    root = tmp_path / "shadow"
    h1 = emit_event(_record(1), root)
    h2 = emit_event(_record(2), root)
    assert h1 != h2
    assert verify_chain(root)
    assert (root / "manifest.jsonl").read_text(encoding="utf-8").count("\n") == 1


def test_emit_no_json_error(tmp_path: Path):
    root = tmp_path / "shadow2"
    emit_event(_record(1), root, sign=False)
    emit_event(_record(2), root, sign=False)
    assert verify_chain(root)


def test_tamper_detected(tmp_path: Path):
    root = tmp_path / "shadow"
    emit_event(_record(1), root)
    emit_event(_record(2), root)
    manifest = root / "manifest.jsonl"
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + "\nTAMPER", encoding="utf-8"
    )
    with pytest.raises(ValueError):
        verify_chain(root)


def test_sign_after_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "shadow_sign"
    counts: list[int] = []

    def _fake_sign(manifest, sig, key_env="COSIGN_KEY"):
        counts.append(len(manifest.read_text(encoding="utf-8").splitlines()))
        return "skip:cosign_missing"

    monkeypatch.setattr("scripts.shadow_audit_emit._sign_manifest", _fake_sign)
    emit_event(_record(1), root, sign=True)
    emit_event(_record(2), root, sign=True)
    assert counts == [1, 2]
    assert verify_chain(root)


def test_verify_signature_skips_when_sig_missing(tmp_path: Path):
    root = tmp_path / "shadow_sig_missing"
    emit_event(_record(1), root, sign=False)
    status = verify_manifest_signature(
        manifest=root / "manifest.jsonl", signature=root / "manifest.sig"
    )
    assert status == "skip:sig_missing"


def test_metrics_reports_signature_status(tmp_path: Path):
    root = tmp_path / "shadow_metrics"
    emit_event(_record(1), root, sign=False)
    metrics = calculate_metrics(root=root)
    assert metrics["event_signature_policy"] == "skip:sig_missing"
    assert metrics["unsigned_events"] == 1


def test_metrics_manifest_missing(tmp_path: Path):
    metrics = calculate_metrics(root=tmp_path / "missing")
    assert metrics["event_signature_policy"] == "N/A:manifest_missing"
