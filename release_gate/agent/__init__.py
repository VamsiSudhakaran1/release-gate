"""
release-gate live agent runtime (Phase 2).

Lets release-gate run evals against a *real* agent instead of static stubs.
An agent is addressed by a small spec string and invoked through a common
interface, while latency is captured into a RuntimeProfile so the readiness
score reflects how the agent actually behaves — not just what its config
declares.

    from release_gate.agent import AgentClient, RuntimeProfile

    client  = AgentClient.from_spec("py:my_pkg.agent:handle")
    profile = RuntimeProfile()
    callable_ = client.as_eval_callable(profile)
    EvalRunner().run(evals, agent_callable=callable_)
    print(profile.summary())
"""

from .client import AgentClient, AgentResponse, AgentSpecError
from .runtime import RuntimeProfile

__all__ = [
    "AgentClient",
    "AgentResponse",
    "AgentSpecError",
    "RuntimeProfile",
]
