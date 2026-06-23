"""Pricing Resolver for release-gate.

Resolves token pricing for a declared model from a *chain* of sources instead of
a single hardcoded table. A ``model:`` block in ``governance.yaml`` declares how
its price should be discovered::

    model:
      id: gpt-4-turbo
      provider: openai
      type: llm
      pricing:
        source: static          # static | custom | locked | openrouter | litellm
        max_age_days: 30        # WARN if a lock snapshot is older than this
        on_unknown: hold        # hold | warn | fail  (never silently pass)

Resolution rules
----------------
* ``custom``     — prices are declared inline (``input_per_1m`` / ``output_per_1m``).
* ``static``     — the built-in table (good for demos / pinned models).
* ``locked``     — read from a committed ``pricing.lock.json`` snapshot.
* ``openrouter`` — fetch live, fall back to lock, then static. Live success is
                   authoritative; a fallback downgrades status to ``WARN``.
* ``litellm``    — use LiteLLM's cost map if the package is installed.

The resolver never raises on a network or import failure — it degrades and
reports *why* via :class:`ResolvedPricing.status` / ``reason``. Unknown pricing
is surfaced as ``HOLD`` (or per ``on_unknown``) so cost is never silently zero.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from release_gate.pricing.budget_simulator import BudgetSimulator
from release_gate.pricing.lock import PricingLock, DEFAULT_LOCK_FILENAME


# Resolution status vocabulary.
STATUS_OK = "OK"        # price resolved from its declared source
STATUS_WARN = "WARN"    # resolved, but via a fallback or a stale snapshot
STATUS_HOLD = "HOLD"    # could not resolve — do not let cost pass silently
STATUS_FAIL = "FAIL"    # could not resolve and policy is on_unknown: fail (block)

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"


@dataclass
class ResolvedPricing:
    """The outcome of resolving one model's pricing."""

    model: str
    provider: str
    input_per_1m: Optional[float]
    output_per_1m: Optional[float]
    source: str          # where the price actually came from
    requested_source: str  # what the config asked for
    status: str          # OK | WARN | HOLD
    reason: str
    fetched_at: Optional[str] = None
    age_days: Optional[float] = None

    @property
    def resolved(self) -> bool:
        return self.input_per_1m is not None and self.output_per_1m is not None

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["resolved"] = self.resolved
        return data


class PricingResolver:
    """Resolve a model's pricing from a chain of sources with graceful fallback."""

    def __init__(self, allow_network: bool = True, timeout: float = 6.0):
        self.allow_network = allow_network
        self.timeout = timeout

    # -- public API ---------------------------------------------------------

    def resolve(
        self,
        model_block: Dict[str, Any],
        lock_path: Optional[str] = DEFAULT_LOCK_FILENAME,
    ) -> ResolvedPricing:
        """Resolve pricing for a ``model:`` block from ``governance.yaml``."""
        model_id = model_block.get("id") or model_block.get("model") or "unknown"
        provider = model_block.get("provider", "unknown")
        model_type = model_block.get("type", "llm")
        pricing = model_block.get("pricing", {}) or {}
        source = (pricing.get("source") or "static").lower()
        on_unknown = (pricing.get("on_unknown") or "hold").lower()
        max_age_days = pricing.get("max_age_days")

        # Self-hosted / zero-cost models may legitimately have no token price.
        if model_type in ("self_hosted", "predictive_model") and source not in (
            "custom",
            "static",
        ):
            return ResolvedPricing(
                model=model_id,
                provider=provider,
                input_per_1m=pricing.get("input_per_1m", 0.0),
                output_per_1m=pricing.get("output_per_1m", 0.0),
                source="declared",
                requested_source=source,
                status=STATUS_OK,
                reason=f"{model_type} uses runtime cost, not token pricing",
            )

        if source == "custom":
            return self._resolve_custom(model_id, provider, pricing, on_unknown)
        if source == "locked":
            return self._finalize_lock(
                model_id, provider, pricing, lock_path, max_age_days, on_unknown,
                requested_source="locked",
            )
        if source in ("openrouter", "live_provider"):
            return self._resolve_openrouter(
                model_id, provider, pricing, lock_path, max_age_days, on_unknown,
            )
        if source == "litellm":
            return self._resolve_litellm(
                model_id, provider, pricing, lock_path, max_age_days, on_unknown,
            )
        # Default: static table.
        return self._resolve_static(model_id, provider, on_unknown, requested_source=source)

    # -- individual sources -------------------------------------------------

    def _resolve_custom(self, model_id, provider, pricing, on_unknown) -> ResolvedPricing:
        inp = pricing.get("input_per_1m")
        out = pricing.get("output_per_1m")
        if inp is None or out is None:
            return self._unknown(
                model_id, provider, "custom", on_unknown,
                "pricing.source is 'custom' but input_per_1m/output_per_1m are missing",
            )
        return ResolvedPricing(
            model=model_id, provider=provider,
            input_per_1m=float(inp), output_per_1m=float(out),
            source="custom", requested_source="custom",
            status=STATUS_OK, reason="inline custom pricing",
        )

    def _resolve_static(self, model_id, provider, on_unknown, requested_source) -> ResolvedPricing:
        entry = BudgetSimulator.PRICING.get(model_id)
        if not entry:
            return self._unknown(
                model_id, provider, "static", on_unknown,
                f"model '{model_id}' not found in the built-in pricing table",
                requested_source=requested_source,
            )
        return ResolvedPricing(
            model=model_id, provider=entry.get("provider", provider),
            input_per_1m=float(entry["input"]), output_per_1m=float(entry["output"]),
            source="static", requested_source=requested_source,
            status=STATUS_OK, reason="built-in static pricing table",
        )

    def _resolve_openrouter(
        self, model_id, provider, pricing, lock_path, max_age_days, on_unknown
    ) -> ResolvedPricing:
        live = self._fetch_openrouter(model_id) if self.allow_network else None
        if live:
            return ResolvedPricing(
                model=model_id, provider=provider,
                input_per_1m=live["input_per_1m"], output_per_1m=live["output_per_1m"],
                source="openrouter", requested_source="openrouter",
                status=STATUS_OK, reason="live OpenRouter pricing",
            )
        # Fall back to lock, then static — both downgrade status to WARN.
        fallback = self._finalize_lock(
            model_id, provider, pricing, lock_path, max_age_days, on_unknown,
            requested_source="openrouter", fallback=True,
        )
        if fallback.resolved:
            return fallback
        static = self._resolve_static(model_id, provider, "warn", requested_source="openrouter")
        if static.resolved:
            static.status = STATUS_WARN
            static.reason = "OpenRouter unreachable — fell back to static table"
        return static

    def _resolve_litellm(
        self, model_id, provider, pricing, lock_path, max_age_days, on_unknown
    ) -> ResolvedPricing:
        entry = self._fetch_litellm(model_id)
        if entry:
            return ResolvedPricing(
                model=model_id, provider=provider,
                input_per_1m=entry["input_per_1m"], output_per_1m=entry["output_per_1m"],
                source="litellm", requested_source="litellm",
                status=STATUS_OK, reason="LiteLLM cost map",
            )
        fallback = self._finalize_lock(
            model_id, provider, pricing, lock_path, max_age_days, on_unknown,
            requested_source="litellm", fallback=True,
        )
        if fallback.resolved:
            return fallback
        static = self._resolve_static(model_id, provider, "warn", requested_source="litellm")
        if static.resolved:
            static.status = STATUS_WARN
            static.reason = "LiteLLM not available — fell back to static table"
        return static

    # -- lock helpers -------------------------------------------------------

    def _finalize_lock(
        self, model_id, provider, pricing, lock_path, max_age_days, on_unknown,
        requested_source, fallback=False,
    ) -> ResolvedPricing:
        lock = PricingLock.load(lock_path) if lock_path else None
        if not lock:
            if fallback:
                return self._unknown(
                    model_id, provider, "locked", on_unknown,
                    "no pricing.lock.json available for fallback",
                    requested_source=requested_source,
                )
            return self._unknown(
                model_id, provider, "locked", on_unknown,
                "pricing.source is 'locked' but no pricing.lock.json was found",
                requested_source=requested_source,
            )
        if not PricingLock.is_intact(lock):
            return self._unknown(
                model_id, provider, "locked", on_unknown,
                "pricing.lock.json hash mismatch — file may have been tampered with",
                requested_source=requested_source,
            )
        entry = PricingLock.get_model(lock, model_id)
        if not entry:
            return self._unknown(
                model_id, provider, "locked", on_unknown,
                f"model '{model_id}' not present in pricing.lock.json",
                requested_source=requested_source,
            )
        age = PricingLock.age_days(lock)
        status = STATUS_WARN if fallback else STATUS_OK
        reason = "pricing.lock.json snapshot"
        if fallback:
            reason = "live source unreachable — using pricing.lock.json snapshot"
        if max_age_days is not None and age is not None and age > float(max_age_days):
            status = STATUS_WARN
            reason = (
                f"pricing snapshot is {age:.0f} days old "
                f"(> max_age_days={max_age_days}) — refresh pricing.lock.json"
            )
        return ResolvedPricing(
            model=model_id, provider=entry.get("provider", provider),
            input_per_1m=float(entry["input_per_1m"]),
            output_per_1m=float(entry["output_per_1m"]),
            source="locked", requested_source=requested_source,
            status=status, reason=reason,
            fetched_at=lock.get("fetched_at"), age_days=age,
        )

    def _unknown(
        self, model_id, provider, source, on_unknown, reason, requested_source=None
    ) -> ResolvedPricing:
        status = {
            "fail": STATUS_FAIL,
            "hold": STATUS_HOLD,
            "warn": STATUS_WARN,
        }.get((on_unknown or "hold").lower(), STATUS_HOLD)
        return ResolvedPricing(
            model=model_id, provider=provider,
            input_per_1m=None, output_per_1m=None,
            source="unknown", requested_source=requested_source or source,
            status=status, reason=reason,
        )

    # -- live fetchers (best-effort, never raise) ---------------------------

    def _fetch_openrouter(self, model_id: str) -> Optional[Dict[str, float]]:
        """Fetch one model's pricing from OpenRouter. Returns None on any failure.

        OpenRouter prices are quoted per-token as strings; we convert to the
        per-1M-tokens convention used throughout release-gate.
        """
        try:
            req = urllib.request.Request(
                OPENROUTER_MODELS_URL,
                headers={"User-Agent": "release-gate-pricing-resolver"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

        for entry in payload.get("data", []):
            entry_id = entry.get("id", "")
            if entry_id == model_id or entry_id.split("/", 1)[-1] == model_id:
                price = entry.get("pricing", {}) or {}
                try:
                    prompt = float(price.get("prompt", 0))
                    completion = float(price.get("completion", 0))
                except (TypeError, ValueError):
                    return None
                return {
                    "input_per_1m": round(prompt * 1_000_000, 6),
                    "output_per_1m": round(completion * 1_000_000, 6),
                }
        return None

    def _fetch_litellm(self, model_id: str) -> Optional[Dict[str, float]]:
        """Read pricing from LiteLLM's cost map if the package is installed."""
        try:
            import litellm  # type: ignore
        except Exception:
            return None
        cost_map = getattr(litellm, "model_cost", {}) or {}
        entry = cost_map.get(model_id)
        if not entry:
            return None
        try:
            inp = entry.get("input_cost_per_token")
            out = entry.get("output_cost_per_token")
            if inp is None or out is None:
                return None
            return {
                "input_per_1m": round(float(inp) * 1_000_000, 6),
                "output_per_1m": round(float(out) * 1_000_000, 6),
            }
        except (TypeError, ValueError):
            return None


def fetch_pricing_snapshot(
    model_ids,
    source: str = "openrouter",
    allow_network: bool = True,
) -> Dict[str, Any]:
    """Build a ``models`` payload for a lock file from a live source.

    Used by ``release-gate pricing-lock`` to refresh ``pricing.lock.json``.
    Returns a dict keyed by model id; unresolved models are omitted.
    """
    resolver = PricingResolver(allow_network=allow_network)
    models: Dict[str, Any] = {}
    for model_id in model_ids:
        block = {"id": model_id, "pricing": {"source": source}}
        resolved = resolver.resolve(block, lock_path=None)
        if resolved.resolved:
            models[model_id] = {
                "input_per_1m": resolved.input_per_1m,
                "output_per_1m": resolved.output_per_1m,
                "provider": resolved.provider,
            }
    return models


__all__ = [
    "PricingResolver",
    "ResolvedPricing",
    "fetch_pricing_snapshot",
    "STATUS_OK",
    "STATUS_WARN",
    "STATUS_HOLD",
]
