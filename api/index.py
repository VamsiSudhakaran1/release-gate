"""Vercel serverless entry point — exports the FastAPI app as 'app'."""
from api._main import app  # noqa: F401  Vercel picks up 'app' automatically
