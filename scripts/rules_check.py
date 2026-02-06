"""SSOT ルールのハッシュ計測と policy_bundle 署名検証を行うスクリプト。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from scripts.shadow_audit_emit import emit_event

# 署名検証対象の SSOT ファイル一覧
SSOT_FILES = (
    "rules/project_rules.yaml",
    "rules/agent/WORK_rules.yaml",
    "rules/agent/AUDIT_rules.yaml",
    "AGENTS.md",
    "監査・テスト方法.md",
    "作業方法.md",
)


def _sha256_file(path: Path) -> str:
    """ファイルの SHA256 を計算する。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write_jsonl(path: Path, records: list[dict]) -> None:
    """JSONL を一時ファイル経由で原子的に書き込む。"""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    tmp.replace(path)


def verify_bundle(bundle: Path, signature: Path) -> str:
    """cosign verify-blob で署名検証する。キー未設定等は skip:* を返す。"""
    if not bundle.exists():
        return "skip:bundle_missing"
    if not signature.exists():
        return "skip:sig_missing"
    if not shutil.which("cosign"):
        return "skip:cosign_missing"
    key = os.environ.get("COSIGN_KEY_VERIFY", "")
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
                str(bundle),
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


def _compute_rules_version(entries: list[dict]) -> str:
    """ルールハッシュ一覧から version を算出する。"""
    concat = "|".join(sorted(e["rule_sha256"] for e in entries))
    return hashlib.sha256(concat.encode("utf-8")).hexdigest()


def _compute_agent_version(
    policy_bundle_hash: str, prompt_hash: str, model_id: str
) -> tuple[str, str]:
    """policy_bundle_hash/prompt_hash/model_id から agent_version とステータスを返す。"""
    if not policy_bundle_hash:
        return "", "skip:policy_bundle_hash_missing"
    if not prompt_hash:
        return "", "skip:prompt_hash_missing"
    if not model_id:
        return "", "skip:model_id_missing"
    concat = "|".join([policy_bundle_hash, prompt_hash, model_id])
    return hashlib.sha256(concat.encode("utf-8")).hexdigest(), "ok"


def _run_checks(
    rule_hashes_path: Path,
    bundle_path: Path,
    sig_path: Path,
    *,
    allow_skip: bool,
    prompt_hash: str = "",
    model_id: str = "",
) -> tuple[str, int]:
    """ハッシュ計測と署名検証を実行し、(signature_status, exit_code) を返す。"""
    paths = [Path(p) for p in SSOT_FILES]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError(f"missing: {', '.join(missing)}")

    entries = [{"rule_file": str(p), "rule_sha256": _sha256_file(p)} for p in paths]
    project_rules_sha = next(
        (
            e["rule_sha256"]
            for e in entries
            if Path(e["rule_file"]).name == "project_rules.yaml"
        ),
        "",
    )

    bundle_hash = _sha256_file(bundle_path) if bundle_path.exists() else ""
    signature_status = verify_bundle(bundle_path, sig_path)
    if signature_status.startswith("skip") and not allow_skip:
        signature_status = f"error:{signature_status}"

    rules_version = _compute_rules_version(entries)
    env_agent_version = os.environ.get("AGENT_VERSION", "")
    agent_version, agent_version_status = _compute_agent_version(
        bundle_hash, prompt_hash, model_id
    )
    if env_agent_version:
        agent_version = env_agent_version
        agent_version_status = "override:env"

    # rule_hashes.jsonl へ追記
    rule_hashes_path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict] = []
    if rule_hashes_path.exists():
        existing = [
            json.loads(line)
            for line in rule_hashes_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    ts = datetime.now(timezone.utc).isoformat()
    records = [
        {
            "ts_utc": ts,
            "agent": "WORK",
            "agent_version": agent_version,
            "agent_version_status": agent_version_status,
            "prompt_hash": prompt_hash,
            "model_id": model_id,
            "rules_version": rules_version,
            "rule_file": e["rule_file"],
            "rule_sha256": e["rule_sha256"],
            "project_rules_sha256": project_rules_sha,
            "policy_bundle_hash": bundle_hash,
            "signature_status": signature_status,
        }
        for e in entries
    ]
    _atomic_write_jsonl(rule_hashes_path, [*existing, *records])

    emit_event(
        {
            "ts": ts,
            "actor": "WORK",
            "event": "rules_check",
            "rules": entries,
            "rules_version": rules_version,
            "agent_version": agent_version,
            "policy_bundle_hash": bundle_hash,
            "signature_status": signature_status,
            "rule_ids": [],
            "policy_refs": ["scripts/rules_check.py"],
            "reasoning_digest": "rules_check hash and policy_bundle verification",
            "inputs_hash": "",
            "outputs_hash": str(rule_hashes_path),
            "approval_state": "none",
            "approvals_row_id": "",
        }
    )

    allowed_status = {"verified"}
    if allow_skip:
        allowed_status |= {
            "skip:bundle_missing",
            "skip:sig_missing",
            "skip:cosign_missing",
            "skip:key_missing",
        }
    exit_code = 0 if signature_status in allowed_status else 1
    return signature_status, exit_code


def run() -> int:
    """ルールハッシュ計測と署名検証を実行し、rule_hashes.jsonl と Shadow Audit を更新する。"""
    parser = argparse.ArgumentParser(description="rules_check: hash + signature verify")
    parser.add_argument(
        "--rule-hashes",
        default="observability/policy/rule_hashes.jsonl",
        help="ハッシュを書き込む先",
    )
    parser.add_argument(
        "--bundle",
        default="observability/policy/policy_bundle.tar",
        help="署名検証するポリシーバンドル",
    )
    parser.add_argument(
        "--signature",
        default="observability/policy/policy_bundle.sig",
        help="署名ファイル",
    )
    parser.add_argument(
        "--allow-skip",
        action="store_true",
        help="署名未配備などの skip:* を許容する（デフォルトは許容しない）",
    )
    parser.add_argument(
        "--prompt-hash",
        default=os.environ.get("PROMPT_HASH", ""),
        help="テンプレートの prompt_hash（環境変数 PROMPT_HASH も可）",
    )
    parser.add_argument(
        "--model-id",
        default=os.environ.get("MODEL_ID", ""),
        help="実行モデル ID（環境変数 MODEL_ID も可）",
    )
    args = parser.parse_args()

    signature_status, exit_code = _run_checks(
        Path(args.rule_hashes),
        Path(args.bundle),
        Path(args.signature),
        allow_skip=args.allow_skip,
        prompt_hash=args.prompt_hash,
        model_id=args.model_id,
    )
    if exit_code != 0:
        print(f"rules_check: signature_status={signature_status} (fail)")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(run())
