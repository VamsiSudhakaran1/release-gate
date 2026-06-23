"""
Vercel entrypoint for the release-gate API.

This is a thin, defensive wrapper around the real app in ``_app.py``. If the
real app fails to import (e.g. a dependency is missing in the serverless
environment), we fall back to a minimal app. The full traceback is always
logged to stderr (visible in the platform logs), but it is only echoed in the
HTTP response when ``RG_DEBUG`` is set — leaking a stack trace (file paths,
dependency versions, internal structure) to anonymous callers in production is
an information-disclosure risk.
"""
from __future__ import annotations

import os
import sys
import traceback

try:
    from release_gate_api._app import app  # noqa: F401  real FastAPI app
except Exception:  # pragma: no cover - only triggers on a broken deployment
    _TB = traceback.format_exc()
    print(_TB, file=sys.stderr)

    _DEBUG = os.environ.get("RG_DEBUG", "").strip().lower() in ("1", "true", "yes")

    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse

    app = FastAPI(title="release-gate API (degraded)")

    @app.get("/{full_path:path}")
    async def _import_error(full_path: str):  # noqa: ANN001
        if _DEBUG:
            body = "release-gate API failed to start.\n\n" + _TB
        else:
            body = (
                "release-gate API failed to start. The error has been logged. "
                "Set RG_DEBUG=1 to surface the traceback in this response."
            )
        return PlainTextResponse(body, status_code=500)
