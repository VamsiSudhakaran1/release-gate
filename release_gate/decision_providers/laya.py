"""Laya, as a decision provider. Optional: imported only when asked for by name.

`RG_SEMANTIC_PROVIDER=laya` builds this. It is `DecisionHTTPProvider` under the
name `laya`, so an answer is recorded as Laya's and the independence analysis
can group Laya's readings with its other output.

It speaks `release-gate-decision/1` (see `release_gate/decision_providers`), not
an API of Laya's own: release-gate does not encode another system's interface it
cannot test against. A Laya deployment is reached through an endpoint serving
`/decide` (and, ideally, `/capabilities`) — natively or through a small adapter —
and whatever it declares about itself is what the verifier holds it to.
"""

from __future__ import annotations

from release_gate.decision_providers import DecisionHTTPProvider

__all__ = ["LayaProvider"]


class LayaProvider(DecisionHTTPProvider):
    provider_name = "laya"
