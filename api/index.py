"""Vercel serverless entry point — exports the FastAPI app as 'app'."""
from release_gate_api.main import app  # noqa: F401  Vercel picks up 'app' automatically
