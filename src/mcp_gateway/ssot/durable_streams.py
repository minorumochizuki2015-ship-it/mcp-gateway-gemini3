"""Durable Streams Protocol の最小クライアント実装。

追記ログ(オフセット再開)の SSOT 連携向けに、PUT/POST/GET/HEAD の最小操作を提供する。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import httpx

JsonValue = str | int | float | bool | None | dict[str, "JsonValue"] | list["JsonValue"]


class DurableStreamsError(RuntimeError):
    """Durable Streams 操作の失敗を表す例外。"""


def _require_header(response: httpx.Response, name: str) -> str:
    """指定ヘッダが無い場合に例外を投げる。"""

    value = response.headers.get(name)
    if value is None or not value.strip():
        raise DurableStreamsError(f"missing required header: {name}")
    return value.strip()


@dataclass(frozen=True)
class ReadResult:
    """GET で取得した読み取り結果。"""

    messages: list[JsonValue]
    next_offset: str
    up_to_date: bool


class DurableStreamsClient:
    """Durable Streams の HTTP クライアント。"""

    def __init__(self, *, timeout_seconds: float = 5.0, client: httpx.Client | None = None) -> None:
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        """内部 httpx.Client をクローズする。"""

        if self._owns_client:
            self._client.close()

    def head(self, stream_url: str) -> tuple[str, str]:
        """ストリームメタデータを取得する(HEAD)。"""

        resp = self._client.head(stream_url)
        if resp.status_code == 404:
            raise DurableStreamsError("stream not found")
        if resp.status_code >= 400:
            raise DurableStreamsError(f"head failed: status={resp.status_code}")

        content_type = _require_header(resp, "Content-Type")
        next_offset = _require_header(resp, "Stream-Next-Offset")
        return (content_type, next_offset)

    def ensure_json_stream(
        self, stream_url: str, *, ttl_seconds: int | None = None, expires_at: str | None = None
    ) -> str:
        """JSON ストリームを作成(または存在確認)する(PUT)。"""

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if ttl_seconds is not None:
            headers["Stream-TTL"] = str(ttl_seconds)
        if expires_at is not None:
            headers["Stream-Expires-At"] = expires_at

        resp = self._client.put(stream_url, headers=headers, content="[]")
        if resp.status_code in (200, 201, 204):
            try:
                return _require_header(resp, "Stream-Next-Offset")
            except DurableStreamsError:
                _, next_offset = self.head(stream_url)
                return next_offset
        if resp.status_code == 409:
            raise DurableStreamsError("stream exists but configuration mismatch (409)")
        raise DurableStreamsError(f"create failed: status={resp.status_code}")

    def append_json_messages(self, stream_url: str, messages: Iterable[JsonValue]) -> str:
        """JSON メッセージを追記する(POST)。"""

        batch = list(messages)
        if not batch:
            raise ValueError("messages must not be empty")

        resp = self._client.post(
            stream_url,
            headers={"Content-Type": "application/json"},
            json=batch,
        )
        if resp.status_code == 404:
            raise DurableStreamsError("stream not found")
        if resp.status_code == 409:
            raise DurableStreamsError("append conflict (content-type or sequence)")
        if resp.status_code >= 400:
            raise DurableStreamsError(f"append failed: status={resp.status_code}")

        return _require_header(resp, "Stream-Next-Offset")

    def read_json_messages(self, stream_url: str, *, offset: str | None = None) -> ReadResult:
        """指定オフセットから JSON メッセージを取得する(GET, catch-up)。"""

        params: dict[str, str] = {}
        if offset is not None:
            params["offset"] = offset

        resp = self._client.get(stream_url, params=params)
        if resp.status_code == 404:
            raise DurableStreamsError("stream not found")
        if resp.status_code == 410:
            raise DurableStreamsError("offset is gone (410)")
        if resp.status_code >= 400:
            raise DurableStreamsError(f"read failed: status={resp.status_code}")

        next_offset = _require_header(resp, "Stream-Next-Offset")
        up_to_date = resp.headers.get("Stream-Up-To-Date", "").lower() == "true"

        data = resp.json()
        if not isinstance(data, list):
            raise DurableStreamsError("invalid json response (expected array)")

        return ReadResult(messages=data, next_offset=next_offset, up_to_date=up_to_date)
