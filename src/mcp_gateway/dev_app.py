"""Dev entrypoint: serve Suite UI static files from the gateway process."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .gateway import app

BASE_DIR = Path(__file__).resolve().parents[2]

UI_DIR_ENV = "MCP_GATEWAY_UI_DIR"


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
