"""
Runtime profiling for live agent runs.

Collects per-call latency (and optional token usage) as evals execute against
a real agent, then summarises it for the readiness report. Pure stdlib; no
external dependencies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class RuntimeProfile:
    """Accumulate live-call observations and produce summary statistics."""

    def __init__(self) -> None:
        self._latencies_ms: List[float] = []
        self._errors: int = 0
        self._calls: int = 0
        self._tokens_in: int = 0
        self._tokens_out: int = 0

    def record(
        self,
        latency_ms: float,
        *,
        error: bool = False,
        tokens_in: Optional[int] = None,
        tokens_out: Optional[int] = None,
    ) -> None:
        """Record a single agent invocation."""
        self._calls += 1
        if error:
            self._errors += 1
        else:
            self._latencies_ms.append(float(latency_ms))
        if tokens_in:
            self._tokens_in += int(tokens_in)
        if tokens_out:
            self._tokens_out += int(tokens_out)

    @staticmethod
    def _percentile(values: List[float], pct: float) -> float:
        """Nearest-rank percentile (pct in 0-100). values must be non-empty."""
        import math

        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]
        rank = max(1, min(len(ordered), math.ceil(pct / 100.0 * len(ordered))))
        return ordered[rank - 1]

    @property
    def calls(self) -> int:
        return self._calls

    @property
    def errors(self) -> int:
        return self._errors

    def summary(self) -> Dict[str, Any]:
        """Return an aggregated, JSON-serialisable summary."""
        lat = self._latencies_ms
        ok = len(lat)
        data: Dict[str, Any] = {
            "calls": self._calls,
            "successful": ok,
            "errors": self._errors,
            "error_rate": round(self._errors / self._calls * 100, 1) if self._calls else 0.0,
        }
        if lat:
            data.update(
                {
                    "avg_latency_ms": round(sum(lat) / ok, 1),
                    "p50_latency_ms": round(self._percentile(lat, 50), 1),
                    "p95_latency_ms": round(self._percentile(lat, 95), 1),
                    "max_latency_ms": round(max(lat), 1),
                }
            )
        else:
            data.update(
                {
                    "avg_latency_ms": None,
                    "p50_latency_ms": None,
                    "p95_latency_ms": None,
                    "max_latency_ms": None,
                }
            )
        if self._tokens_in or self._tokens_out:
            data["tokens_in"] = self._tokens_in
            data["tokens_out"] = self._tokens_out
        return data
