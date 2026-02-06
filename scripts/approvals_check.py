#!/usr/bin/env python
"""Validate APPROVALS ledger against rules/APPROVALS.yaml.

Checks:
- required fields are present and non-empty
- status is approved (case-insensitive)
- expiry_utc is valid ISO-8601 and not expired
- two_person_rule / forbid_self_approval are enforced (requested_by != approver)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml  # type: ignore[import-untyped]


@dataclass
class ApprovalRule:
    ledger: Path
    required_fields: list[str]
    two_person_rule: bool
    forbid_self_approval: bool


def load_rules(rules_path: Path) -> ApprovalRule:
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    ledger = Path(data.get("ledger") or "APPROVALS.md")
    required_fields = [
        str(f).strip() for f in data.get("required_fields", []) if str(f).strip()
    ]
    return ApprovalRule(
        ledger=ledger,
        required_fields=required_fields,
        two_person_rule=bool(data.get("two_person_rule", False)),
        forbid_self_approval=bool(data.get("forbid_self_approval", False)),
    )


def parse_markdown_table(text: str) -> list[dict[str, str]]:
    headers: list[str] = []
    rows: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or all(not c for c in cells):
            continue
        # detect separator (----) row
        if all(set(c) <= {"-"} for c in cells):
            continue
        if not headers:
            headers = [h.lower() for h in cells]
            continue
        row = {
            headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))
        }
        rows.append(row)
    return rows


def _is_expired(value: str) -> bool:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return True
    return ts < datetime.now(timezone.utc)


def validate_rows(rules: ApprovalRule, rows: Iterable[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    found_ids: set[str] = set()
    for row in rows:
        row_id = row.get("id", "").strip()
        if not row_id:
            errors.append("row: missing id")
            continue
        row_lower = {k.lower(): v for k, v in row.items()}
        found_ids.add(row_id)
        # required fields
        for field in rules.required_fields:
            if not row_lower.get(field.lower(), "").strip():
                errors.append(f"{row_id}: missing required field {field}")
        status = row_lower.get("status", "").lower()
        if status != "approved":
            errors.append(
                f"{row_id}: status must be approved (got {status or 'empty'})"
            )
        expiry = row_lower.get("expiry_utc", "")
        if _is_expired(expiry):
            errors.append(f"{row_id}: expiry_utc expired or invalid ({expiry})")
        requested_by = row_lower.get("requested_by", "").lower()
        approver = row_lower.get("approver", "").lower()
        if rules.two_person_rule or rules.forbid_self_approval:
            if requested_by and approver and requested_by == approver:
                errors.append(
                    f"{row_id}: requested_by and approver must differ (two_person_rule/self_approval)"
                )
    if not found_ids:
        errors.append("ledger is empty or no rows parsed")
    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    rules_path = repo_root / "rules" / "APPROVALS.yaml"
    if not rules_path.exists():
        print("ERROR: rules/APPROVALS.yaml not found", file=sys.stderr)
        return 1
    rules = load_rules(rules_path)
    ledger_path = rules.ledger
    if not ledger_path.is_absolute():
        ledger_path = rules_path.parent / ledger_path
    if not ledger_path.exists():
        print(f"ERROR: ledger not found: {ledger_path}", file=sys.stderr)
        return 1
    rows = parse_markdown_table(ledger_path.read_text(encoding="utf-8"))
    errors = validate_rows(rules, rows)
    evidence_path = repo_root / "observability" / "policy" / "ci_evidence.jsonl"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    event: dict[str, object] = {
        "event": "approvals_check",
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ledger": str(ledger_path),
        "rules": str(rules_path),
    }
    if errors:
        print("APPROVALS validation failed:", file=sys.stderr)
        for e in errors:
            print(f"- {e}", file=sys.stderr)
        event["status"] = "fail"
        event["errors"] = errors
        evidence_path.write_text(
            (
                evidence_path.read_text(encoding="utf-8")
                + json.dumps(event, ensure_ascii=False)
                + "\n"
                if evidence_path.exists()
                else json.dumps(event, ensure_ascii=False) + "\n"
            ),
            encoding="utf-8",
        )
        return 1
    event["status"] = "pass"
    event["row_count"] = len(rows)
    evidence_path.write_text(
        (
            evidence_path.read_text(encoding="utf-8")
            + json.dumps(event, ensure_ascii=False)
            + "\n"
            if evidence_path.exists()
            else json.dumps(event, ensure_ascii=False) + "\n"
        ),
        encoding="utf-8",
    )
    print(f"✓ APPROVALS validation passed ({len(rows)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
