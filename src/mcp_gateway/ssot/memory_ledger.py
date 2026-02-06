"""Memory Ledger の最小 JSONL 書き込みユーティリティ。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

JsonValue = str | int | float | bool | None | dict[str, "JsonValue"] | list["JsonValue"]
LedgerOperation = Literal["propose", "commit", "retract", "gc"]
LedgerErrorPolicy = Literal["open", "closed"]
LEDGER_SCHEMA_VERSION = "v1"


def _now_utc_iso() -> str:
    """UTC の ISO8601 文字列を返す。"""

    return datetime.now(timezone.utc).isoformat()


def _canonical_payload(payload: dict[str, JsonValue]) -> str:
    """payload_normalized を安定化した JSON 文字列に変換する。"""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class LedgerSource:
    """Ledger の参照元(SSOTイベント)を保持する。"""

    stream_id: str
    offset: str
    event_hash: str

    def as_dict(self) -> dict[str, str]:
        """JSON へ書き込む辞書形式に変換する。"""

        return {"stream_id": self.stream_id, "offset": self.offset, "event_hash": self.event_hash}


@dataclass(frozen=True)
class MemoryLedgerEntry:
    """Memory Ledger 1行分のデータ。"""

    schema_version: str | None
    ts_utc: str
    op: LedgerOperation
    memory_kind: str
    source: LedgerSource
    payload_normalized: dict[str, JsonValue]
    entry_id: str | None = None
    ledger_seq: int | None = None
    retention: dict[str, JsonValue] | None = None
    privacy: dict[str, JsonValue] | None = None
    actor: str | None = None
    tags: list[str] | None = None

    def as_dict(self) -> dict[str, JsonValue]:
        """JSONL 出力用の辞書へ変換する。"""

        payload: dict[str, JsonValue] = {
            "ts_utc": self.ts_utc,
            "op": self.op,
            "memory_kind": self.memory_kind,
            "source": self.source.as_dict(),
            "payload_normalized": self.payload_normalized,
        }
        if self.schema_version is not None:
            payload["schema_version"] = self.schema_version
        if self.entry_id is not None:
            payload["entry_id"] = self.entry_id
        if self.ledger_seq is not None:
            payload["ledger_seq"] = self.ledger_seq
        if self.retention is not None:
            payload["retention"] = self.retention
        if self.privacy is not None:
            payload["privacy"] = self.privacy
        if self.actor is not None:
            payload["actor"] = self.actor
        if self.tags is not None:
            payload["tags"] = self.tags
        return payload


def new_memory_ledger_entry(
    *,
    op: LedgerOperation,
    memory_kind: str,
    source: LedgerSource,
    payload_normalized: dict[str, JsonValue],
    retention: dict[str, JsonValue] | None = None,
    privacy: dict[str, JsonValue] | None = None,
    actor: str | None = None,
    tags: list[str] | None = None,
) -> MemoryLedgerEntry:
    """入力を受け取って MemoryLedgerEntry を生成する。"""

    return MemoryLedgerEntry(
        schema_version=None,
        ts_utc=_now_utc_iso(),
        op=op,
        memory_kind=memory_kind,
        source=source,
        payload_normalized=payload_normalized,
        retention=retention,
        privacy=privacy,
        actor=actor,
        tags=tags,
    )


@dataclass(slots=True)
class MemoryLedgerWriter:
    """Memory Ledger を JSONL に追記する writer。"""

    path: Path
    enabled: bool = True
    error_policy: LedgerErrorPolicy = "open"

    def _resolve_entry_id(self, entry: MemoryLedgerEntry) -> str:
        """payload_normalized の memory_id を優先して entry_id を生成する。"""

        memory_id = entry.payload_normalized.get("memory_id")
        if isinstance(memory_id, str) and memory_id.strip():
            base = f"memory_id:{memory_id.strip()}"
        else:
            canonical_payload = _canonical_payload(entry.payload_normalized)
            base = (
                f"{entry.source.stream_id}|{entry.source.offset}|{entry.source.event_hash}|"
                f"{entry.memory_kind}|{canonical_payload}"
            )
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def _raise_if_closed(self, exc: Exception, message: str) -> None:
        """error_policy が closed の場合に例外を投げる。"""

        if self.error_policy == "closed":
            raise ValueError(message) from exc

    def _load_last_seq(self) -> int:
        """既存の ledger_seq を読み取り、末尾の番号を返す。"""

        if not self.path.exists():
            return 0
        last_seq = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    self._raise_if_closed(exc, "ledger json decode failed")
                    continue
                seq = data.get("ledger_seq")
                if isinstance(seq, int):
                    last_seq = max(last_seq, seq)
        return last_seq

    def _entry_exists(self, entry_id: str) -> bool:
        """entry_id の重複を検出する (旧行は再計算する)。"""

        if not self.path.exists():
            return False
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    self._raise_if_closed(exc, "ledger json decode failed")
                    continue
                if not isinstance(data, dict):
                    continue
                existing_entry_id = self._entry_id_from_data(data)
                if existing_entry_id == entry_id:
                    return True
        return False

    def _entry_id_from_data(self, data: dict[str, JsonValue]) -> str | None:
        """旧スキーマを含む ledger 行から entry_id を算出する。"""

        entry_id = data.get("entry_id")
        if isinstance(entry_id, str) and entry_id.strip():
            return entry_id.strip()
        payload = data.get("payload_normalized")
        if not isinstance(payload, dict):
            return None
        payload_normalized: dict[str, JsonValue] = payload
        memory_id = payload_normalized.get("memory_id")
        if isinstance(memory_id, str) and memory_id.strip():
            base = f"memory_id:{memory_id.strip()}"
            return hashlib.sha256(base.encode("utf-8")).hexdigest()
        source = data.get("source")
        memory_kind = data.get("memory_kind")
        if not isinstance(source, dict) or not isinstance(memory_kind, str):
            return None
        stream_id = source.get("stream_id")
        offset = source.get("offset")
        event_hash = source.get("event_hash")
        if not all(
            isinstance(value, str) and value.strip() for value in (stream_id, offset, event_hash)
        ):
            return None
        canonical_payload = _canonical_payload(payload_normalized)
        base = f"{stream_id}|{offset}|{event_hash}|{memory_kind}|{canonical_payload}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def append(self, entry: MemoryLedgerEntry) -> None:
        """1件の Ledger エントリを JSONL に追記する。"""

        if not self.enabled:
            return

        entry_id = entry.entry_id or self._resolve_entry_id(entry)
        if self._entry_exists(entry_id):
            return
        ledger_seq = entry.ledger_seq or (self._load_last_seq() + 1)
        entry = replace(
            entry,
            schema_version=entry.schema_version or LEDGER_SCHEMA_VERSION,
            entry_id=entry_id,
            ledger_seq=ledger_seq,
        )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            json.dump(entry.as_dict(), handle, ensure_ascii=False)
            handle.write("\n")
