"""Pricing lock file management for release-gate.

A ``pricing.lock.json`` is a committed, reproducible snapshot of model pricing.
It lets CI score releases without making a live network call on every run, while
still surfacing *staleness* so prices don't silently drift forever.

Lock file format (version 1)::

    {
      "version": 1,
      "source": "openrouter",
      "fetched_at": "2026-06-15T10:00:00Z",
      "models": {
        "openai/gpt-4-turbo": {
          "input_per_1m": 10.0,
          "output_per_1m": 30.0,
          "provider": "openai"
        }
      },
      "hash": "sha256:abc123..."
    }

The ``hash`` is computed over the canonical (sorted) ``models`` payload so a
tampered or hand-edited lock file can be detected.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


LOCK_VERSION = 1
DEFAULT_LOCK_FILENAME = "pricing.lock.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compute_models_hash(models: Dict[str, Any]) -> str:
    """Return a stable ``sha256:`` hash over the canonical models payload."""
    canonical = json.dumps(models, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class PricingLock:
    """Read, write, and validate a ``pricing.lock.json`` snapshot."""

    @staticmethod
    def write(
        path: str,
        models: Dict[str, Any],
        source: str,
        fetched_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Write a lock file to ``path`` and return the serialized payload."""
        payload = {
            "version": LOCK_VERSION,
            "source": source,
            "fetched_at": fetched_at or _utc_now_iso(),
            "models": models,
            "hash": compute_models_hash(models),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        return payload

    @staticmethod
    def load(path: str) -> Optional[Dict[str, Any]]:
        """Load a lock file. Returns ``None`` if the file does not exist."""
        if not path or not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def is_intact(lock: Dict[str, Any]) -> bool:
        """Return True if the lock's stored hash matches its models payload."""
        stored = lock.get("hash")
        if not stored:
            return False
        return stored == compute_models_hash(lock.get("models", {}))

    @staticmethod
    def age_days(lock: Dict[str, Any], now: Optional[datetime] = None) -> Optional[float]:
        """Return the age of the snapshot in days, or ``None`` if unknown."""
        fetched = lock.get("fetched_at")
        if not fetched:
            return None
        try:
            stamp = datetime.fromisoformat(fetched.replace("Z", "+00:00"))
        except ValueError:
            return None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return (current - stamp).total_seconds() / 86400.0

    @staticmethod
    def get_model(lock: Dict[str, Any], model_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single model's pricing inside a loaded lock file.

        Matches the exact id first, then falls back to a provider-prefixed key
        (e.g. ``gpt-4-turbo`` matches ``openai/gpt-4-turbo``).
        """
        models = lock.get("models", {})
        if model_id in models:
            return models[model_id]
        for key, value in models.items():
            if key.split("/", 1)[-1] == model_id:
                return value
        return None


__all__ = [
    "PricingLock",
    "compute_models_hash",
    "LOCK_VERSION",
    "DEFAULT_LOCK_FILENAME",
]
