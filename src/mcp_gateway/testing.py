"""Test helpers for synchronous test calls into ASGI apps."""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

_AsyncClient = httpx.AsyncClient
_ASGITransport = httpx.ASGITransport


class TestClient:
    """Sync wrapper around httpx.AsyncClient using an ASGI transport."""

    __test__ = False

    def __init__(
        self,
        app: Any,
        *,
        base_url: str = "http://testserver",
        raise_app_exceptions: bool = True,
    ) -> None:
        self._loop = asyncio.new_event_loop()
        self._transport = _ASGITransport(
            app=app, raise_app_exceptions=raise_app_exceptions
        )
        self._client = _AsyncClient(
            transport=self._transport, base_url=base_url
        )
        self._closed = False

    def _run(self, coro):
        if self._closed:
            raise RuntimeError("TestClient is closed")
        return self._loop.run_until_complete(coro)

    def request(self, method: str, url: str, **kwargs):
        auth_token = os.getenv("MCP_GATEWAY_PROXY_TOKEN", "").strip()
        headers = kwargs.get("headers")
        if auth_token and (headers is None or "Authorization" not in headers):
            new_headers = {} if headers is None else dict(headers)
            new_headers["Authorization"] = f"Bearer {auth_token}"
            kwargs["headers"] = new_headers
        return self._run(self._client.request(method, url, **kwargs))

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._loop.is_closed():
            return
        coro = self._client.aclose()
        try:
            self._loop.run_until_complete(coro)
        except Exception:
            coro.close()
            raise
        finally:
            self._loop.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
