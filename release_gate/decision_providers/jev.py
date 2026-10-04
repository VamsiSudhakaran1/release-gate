"""Jev, as a decision provider. Optional: imported only when asked for by name.

`RG_SEMANTIC_PROVIDER=jev` builds this. It is `DecisionHTTPProvider` under the
name `jev`, so an answer is recorded as Jev's and the independence analysis can
group Jev's readings with its other output.

It speaks `release-gate-decision/1` (see `release_gate/decision_providers`), not
an API of Jev's own: release-gate does not encode another system's interface it
cannot test against. A Jev deployment is reached through an endpoint serving
`/decide` (and, ideally, `/capabilities`) — natively or through a small adapter —
and whatever it declares about itself is what the verifier holds it to.
"""

from __future__ import annotations

from release_gate.decision_providers import DecisionHTTPProvider

__all__ = ["JevProvider"]


class JevProvider(DecisionHTTPProvider):
    provider_name = "jev"
