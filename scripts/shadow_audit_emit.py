from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("observability/policy/shadow_audit")
MANIFEST = ROOT / "manifest.jsonl"
CHAIN = ROOT / "manifest.sha256"
SIG = ROOT / "manifest.sig"


def _sha256(text: str) -> str:
    """文字列を SHA256 ハッシュに変換する。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _atomic_write(path: Path, content: str, *, validate_jsonl: bool = False) -> None:
    """一時ファイル経由で原子的に書き込む。必要に応じて JSONL を検証する。"""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    if validate_jsonl:
        for line in content.splitlines():
            if line.strip():
                json.loads(line)
    tmp.replace(path)


def _sign_manifest(manifest: Path, sig: Path, key_env: str = "COSIGN_KEY") -> str:
    """cosign を使って manifest を署名する。鍵や cosign が無ければスキップ扱い。"""
    cosign = shutil.which("cosign")
    if not cosign:
        return "skip:cosign_missing"
    if not manifest.exists():
        return "skip:manifest_missing"
    key = os.environ.get(key_env, "")
    if not key:
        return "skip:key_missing"
    try:
        result = subprocess.run(
            [
                cosign,
                "sign-blob",
                "--yes",
                "--key",
                key,
                "--output-signature",
                str(sig),
                str(manifest),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "error:timeout"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error:exception:{type(exc).__name__}"
    return "signed" if result.returncode == 0 else f"failed:{result.returncode}"


def sign_manifest(root: Path = ROOT) -> str:
    """Shadow Audit の manifest.jsonl を署名する。"""
    manifest = root / "manifest.jsonl"
    sig = root / "manifest.sig"
    return _sign_manifest(manifest, sig)


def verify_manifest_signature(
    manifest: Path = MANIFEST,
    signature: Path = SIG,
    key_env: str = "COSIGN_KEY_VERIFY",
) -> str:
    """cosign verify-blob で Shadow Audit manifest の署名検証を行う。"""
    if not manifest.exists():
        return "skip:manifest_missing"
    if not signature.exists():
        return "skip:sig_missing"
    if not shutil.which("cosign"):
        return "skip:cosign_missing"
    key = os.environ.get(key_env, "")
    if not key:
        return "skip:key_missing"
    try:
        result = subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--key",
                key,
                "--signature",
                str(signature),
                str(manifest),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "error:timeout"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error:exception:{type(exc).__name__}"
    return "verified" if result.returncode == 0 else f"failed:{result.returncode}"


def emit_event(record: dict, root: Path = ROOT, *, sign: bool = False) -> str:
    """Shadow Audit に 1 行 JSON イベントを追記し、チェーンを更新する。"""
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / "manifest.jsonl"
    chain = root / "manifest.sha256"
    sig = root / "manifest.sig"
    lines: list[str] = []
    if manifest.exists():
        lines = manifest.read_text(encoding="utf-8").splitlines()
    prev = chain.read_text(encoding="utf-8").strip() if chain.exists() else ""
    new_line = json.dumps(record, ensure_ascii=False)
    new_hash = _sha256(prev + "\n" + new_line if prev else new_line)
    manifest_content = "\n".join([*lines, new_line])
    _atomic_write(manifest, manifest_content, validate_jsonl=True)
    _atomic_write(chain, new_hash)
    if sign:
        _sign_manifest(manifest, sig)
    return new_hash


def verify_chain(root: Path = ROOT) -> bool:
    """manifest.jsonl と manifest.sha256 の整合性を検証する。"""
    manifest = root / "manifest.jsonl"
    chain = root / "manifest.sha256"
    if not manifest.exists():
        return True
    lines = manifest.read_text(encoding="utf-8").splitlines()
    expected = ""
    for line in lines:
        expected = _sha256(expected + "\n" + line if expected else line)
    current = chain.read_text(encoding="utf-8").strip() if chain.exists() else ""
    if expected != current:
        raise ValueError("shadow audit hash mismatch")
    return True


def rebuild_chain(root: Path = ROOT) -> str:
    """manifest.jsonl を読み直してチェーンを再計算する。"""
    manifest = root / "manifest.jsonl"
    chain = root / "manifest.sha256"
    if not manifest.exists():
        raise FileNotFoundError("manifest.jsonl not found")
    lines = [
        ln for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    expected = ""
    for line in lines:
        expected = _sha256(expected + "\n" + line if expected else line)
    _atomic_write(chain, expected)
    return expected


def calculate_metrics(root: Path = ROOT) -> dict[str, str | int | float]:
    """Shadow Audit の簡易メトリクスを算出する（N/A 理由も返す）。"""
    manifest = root / "manifest.jsonl"
    sig = root / "manifest.sig"
    if not manifest.exists():
        return {
            "explainability_rate": "N/A:manifest_missing",
            "unsigned_events": 0,
            "rule_drift": "N/A:manifest_missing",
            "approval_mismatch": "N/A:manifest_missing",
            "event_signature_policy": "N/A:manifest_missing",
        }
    records = [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    total = len(records)
    if total == 0:
        return {
            "explainability_rate": "N/A:no_events",
            "unsigned_events": 0,
            "rule_drift": "N/A:no_events",
            "approval_mismatch": "N/A:no_events",
            "event_signature_policy": "N/A:no_events",
        }
    reasoning_count = sum(
        1 for rec in records if str(rec.get("reasoning_digest", "")).strip()
    )
    explainability_rate = round((reasoning_count / total) * 100, 2)
    signature_status = verify_manifest_signature(manifest=manifest, signature=sig)
    unsigned_events = 0 if signature_status == "verified" else total
    has_rule_ids = any(rec.get("rule_ids") for rec in records)
    has_approval = any(rec.get("approval_state") not in (None, "none") for rec in records)
    return {
        "explainability_rate": explainability_rate,
        "unsigned_events": unsigned_events,
        "rule_drift": "N/A:rule_ids_not_tracked" if not has_rule_ids else "N/A:not_implemented",
        "approval_mismatch": "N/A:approval_state_not_tracked"
        if not has_approval
        else "N/A:not_implemented",
        "event_signature_policy": signature_status,
    }


def emit_rules_check_event(
    rules: list[dict],
    *,
    policy_bundle_hash: str | None = None,
    signature_status: str | None = None,
    actor: str = "WORK",
    rule_ids: list[str] | None = None,
    policy_refs: list[str] | None = None,
    reasoning_digest: str = "",
    inputs_hash: str = "",
    outputs_hash: str = "",
    approval_state: str = "none",
    approvals_row_id: str = "",
    root: Path = ROOT,
    dedupe_rules_check: bool = True,
) -> str:
    """rules_check イベントを1件に抑制しつつ追記する。"""
    if dedupe_rules_check and (root / "manifest.jsonl").exists():
        manifest = root / "manifest.jsonl"
        chain = root / "manifest.sha256"
        lines = [
            ln for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        filtered = [ln for ln in lines if json.loads(ln).get("event") != "rules_check"]
        if filtered != lines:
            _atomic_write(manifest, "\n".join(filtered), validate_jsonl=True)
            rebuild_chain(root=root) if filtered else chain.unlink(missing_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "event": "rules_check",
        "rules": rules,
        "policy_bundle_hash": policy_bundle_hash,
        "signature_status": signature_status,
        "rule_ids": rule_ids or [],
        "policy_refs": policy_refs or [],
        "reasoning_digest": reasoning_digest,
        "inputs_hash": inputs_hash,
        "outputs_hash": outputs_hash,
        "approval_state": approval_state,
        "approvals_row_id": approvals_row_id,
    }
    return emit_event(record, root=root)


def emit_rollback_event(
    *,
    snapshot_path: str,
    reason: str,
    status: str,
    actor: str = "WORK",
    root: Path = ROOT,
) -> str:
    """rollback_executed を Shadow Audit に記録する。"""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "event": "rollback_executed",
        "snapshot_path": snapshot_path,
        "reason": reason,
        "status": status,
    }
    return emit_event(record, root=root)


if __name__ == "__main__":
    emit_event(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": "WORK",
            "event": "PLAN",
            "rule_ids": [],
            "policy_refs": [],
            "reasoning_digest": "",
            "inputs_hash": "",
            "outputs_hash": "",
            "approval_state": "none",
            "approvals_row_id": "",
        }
    )
