"""Dev entrypoint: serve Suite UI static files from the gateway process.

For hackathon demos, auto-injects the admin token into HTML responses
so judges never need to manually enter it.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .gateway import app

BASE_DIR = Path(__file__).resolve().parents[2]

UI_DIR_ENV = "MCP_GATEWAY_UI_DIR"
ADMIN_TOKEN_ENV = "MCP_GATEWAY_ADMIN_TOKEN"

# Auto-generate admin token for hackathon demos if not already set
if not os.getenv(ADMIN_TOKEN_ENV, "").strip():
    _auto_token = secrets.token_urlsafe(32)
    os.environ[ADMIN_TOKEN_ENV] = _auto_token


class _TokenInjectorMiddleware(BaseHTTPMiddleware):
    """Inject ``window.SUITE_ADMIN_TOKEN`` into HTML responses.

    This removes the need for judges to manually enter the admin token
    during hackathon demos.  Non-HTML responses pass through unchanged.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        ct = response.headers.get("content-type", "")
        if "text/html" not in ct:
            return response
        body = b""
        async for chunk in response.body_iterator:
            body += chunk if isinstance(chunk, bytes) else chunk.encode()
        token = os.getenv(ADMIN_TOKEN_ENV, "")
        if token:
            script = (
                f'<script>window.SUITE_ADMIN_TOKEN="{token}";</script>'
            )
            body = body.replace(b"</head>", script.encode() + b"\n</head>")
        return Response(
            content=body,
            status_code=response.status_code,
            media_type="text/html; charset=utf-8",
        )


app.add_middleware(_TokenInjectorMiddleware)


def _default_ui_dir() -> Path:
    return BASE_DIR.parent / "mcp-gateway-release" / "docs" / "ui_poc"


def _mount_ui(ui_dir: str) -> None:
    path = Path(ui_dir)
    if not path.is_dir():
        return

    @app.get("/")  # type: ignore[misc]
    async def _root_redirect() -> RedirectResponse:
        return RedirectResponse(url="/settings_environments.html")

    app.mount("/", StaticFiles(directory=str(path), html=True), name="suite_ui")


_mount_ui(os.getenv(UI_DIR_ENV, "").strip() or str(_default_ui_dir()))
