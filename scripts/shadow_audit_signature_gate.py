from __future__ import annotations

import argparse
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from scripts.shadow_audit_emit import sign_manifest, verify_manifest_signature
from src.mcp_gateway import evidence


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="shadow_audit_signature_gate: sign/verify Shadow Audit manifest"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("observability/policy/shadow_audit"),
        help="Shadow Audit root directory (contains manifest.jsonl).",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign manifest.jsonl (uses COSIGN_KEY/COSIGN_PASSWORD).",
    )
    parser.add_argument(
        "--require-verified",
        action="store_true",
        help="Fail (exit 1) unless signature_status == verified.",
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        default=Path("observability/policy/ci_evidence.jsonl"),
        help="Evidence JSONL path to append results to.",
    )
    args = parser.parse_args()

    root = args.root
    manifest = root / "manifest.jsonl"
    signature = root / "manifest.sig"

    sign_status = ""
    if args.sign:
        sign_status = sign_manifest(root=root)

    signature_status = verify_manifest_signature(
        manifest=manifest, signature=signature, key_env="COSIGN_KEY_VERIFY"
    )

    # M5.1-P2-1: Add signer tracking for audit trail
    signer = os.environ.get("GITHUB_ACTOR", "unknown")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_number = os.environ.get("GITHUB_RUN_NUMBER", "")

    event = {
        "event": "shadow_audit_manifest_signature",
        "actor": "CI",
        "trigger_source": "ci",
        "component": "shadow_audit",
        "signature_status": signature_status,
        "sign_status": sign_status,
        "manifest_sha256": _sha256_file(manifest) if manifest.exists() else "",
        "manifest_path": str(manifest),
        "signature_path": str(signature),
        "signature_present": signature.exists(),
        "require_verified": bool(args.require_verified),
        "signer": signer,
        "signer_type": "github_actions" if signer != "unknown" else "local",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "run_number": run_number,
    }
    evidence.append(event, path=args.evidence)

    if args.require_verified and signature_status != "verified":
        print(f"shadow_audit_signature_gate: signature_status={signature_status} (fail)")
        return 1
    print(f"shadow_audit_signature_gate: signature_status={signature_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

