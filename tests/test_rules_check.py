"""rules_check の署名検証と version 計算を確認するテスト。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import rules_check


def _prepare_ssot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """一時ディレクトリに SSOT ファイル群を配置し、パスを差し替える。"""
    ssot_paths = [
        tmp_path / "rules" / "project_rules.yaml",
        tmp_path / "rules" / "agent" / "WORK_rules.yaml",
        tmp_path / "rules" / "agent" / "AUDIT_rules.yaml",
        tmp_path / "AGENTS.md",
        tmp_path / "監査・テスト方法.md",
        tmp_path / "作業方法.md",
    ]
    for path in ssot_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("dummy", encoding="utf-8")
    monkeypatch.setattr(rules_check, "SSOT_FILES", tuple(str(p) for p in ssot_paths))
    from scripts import shadow_audit_emit

    shadow_root = tmp_path / "shadow_audit"
    monkeypatch.setattr(shadow_audit_emit, "ROOT", shadow_root)
    monkeypatch.setattr(shadow_audit_emit, "MANIFEST", shadow_root / "manifest.jsonl")
    monkeypatch.setattr(shadow_audit_emit, "CHAIN", shadow_root / "manifest.sha256")
    monkeypatch.setattr(shadow_audit_emit, "SIG", shadow_root / "manifest.sig")
    monkeypatch.setattr(
        rules_check,
        "emit_event",
        lambda record, sign=False: shadow_audit_emit.emit_event(
            record, root=shadow_root, sign=sign
        ),
    )


def test_run_checks_allows_skip_with_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """allow_skip 指定時は署名未配備でも skip:* で成功扱いになる。"""
    _prepare_ssot(tmp_path, monkeypatch)
    monkeypatch.setenv("AGENT_VERSION", "test-agent-1.0")

    rule_hashes = tmp_path / "rule_hashes.jsonl"
    bundle = tmp_path / "policy_bundle.tar"
    bundle.write_text("bundle", encoding="utf-8")
    signature = tmp_path / "policy_bundle.sig"  # 敢えて未作成で skip を誘発

    status, code = rules_check._run_checks(
        rule_hashes_path=rule_hashes,
        bundle_path=bundle,
        sig_path=signature,
        allow_skip=True,
    )

    assert status.startswith("skip:")
    assert code == 0
    records = [json.loads(line) for line in rule_hashes.read_text(encoding="utf-8").splitlines()]
    assert records
    last = records[-1]
    assert last["rules_version"]
    assert last["agent_version"] == "test-agent-1.0"


def test_run_checks_fails_when_skip_disallowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """allow_skip 未指定では署名未配備を error として扱う。"""
    _prepare_ssot(tmp_path, monkeypatch)
    rule_hashes = tmp_path / "rule_hashes.jsonl"
    bundle = tmp_path / "policy_bundle.tar"
    bundle.write_text("bundle", encoding="utf-8")
    signature = tmp_path / "policy_bundle.sig"

    status, code = rules_check._run_checks(
        rule_hashes_path=rule_hashes,
        bundle_path=bundle,
        sig_path=signature,
        allow_skip=False,
    )

    assert status.startswith("error:skip")
    assert code == 1
