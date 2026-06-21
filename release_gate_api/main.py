"""
Vercel entrypoint for the release-gate API.

This is a thin, defensive wrapper around the real app in ``_app.py``. If the
real app fails to import (e.g. a dependency is missing in the serverless
environment), we fall back to a minimal app that reports the traceback as
plain text on every route — so the browser shows the actual error instead of
an opaque ``FUNCTION_INVOCATION_FAILED`` 500.
"""
from __future__ import annotations

import sys
import traceback

try:
    from release_gate_api._app import app  # noqa: F401  real FastAPI app
except Exception:  # pragma: no cover - only triggers on a broken deployment
    _TB = traceback.format_exc()
    print(_TB, file=sys.stderr)

    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse

    app = FastAPI(title="release-gate API (degraded)")

    @app.get("/{full_path:path}")
    async def _import_error(full_path: str):  # noqa: ANN001
        return PlainTextResponse(
            "release-gate API failed to start.\n\n" + _TB,
            status_code=500,
        )
