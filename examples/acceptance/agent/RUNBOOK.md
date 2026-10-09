# Refunds agent runbook

Owner: support-platform (on call through the support-platform rotation).

1. Turn the agent off: set `flags/refunds-agent-enabled` to `false`. Requests
   fall back to the human refunds queue.
2. Find the refunds the agent issued in the incident window in the ledger's
   `refunds_by_actor` view, actor `refunds-agent`.
3. Reverse any refund the processor has not settled; open a finance ticket for
   the rest.
