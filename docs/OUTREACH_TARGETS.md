# Outreach targets — high-visibility OSS agent repos

Curated shortlist of flagship, actively-maintained, **Python** agent repos where a
`release-gate audit` → `governance.yaml` + readiness badge PR could land. Star
counts are mid-2026, web-verified, rounded. Optimized for **reach/visibility**.

> ⚠️ **Base rate is low.** Cold PRs that add meta/config files (a `governance.yaml`
> + badge) to flagship repos have a single-digit merge rate on the biggest repos —
> they read as scope-creep or badge spam and get auto-closed. To improve odds:
> open an **issue first**, keep the PR tiny and self-contained, tie it to an
> existing security/CONTRIBUTING gap, sign any CLA, and favor the **mid-size,
> founder/small-team repos** over the 100k-star giants. Treat the giants as
> credibility long-shots, not the conversion engine.

| # | Repo | ~Stars | What it is | Reach value | Why it's hard |
|---|------|-------:|-----------|-------------|---------------|
| 1 | `assafelovic/gpt-researcher` | 27k | Autonomous deep-research agent (LangGraph/AG2) | Founder-led, PR-friendly | One dominant maintainer |
| 2 | `agno-agi/agno` | 40k | Build/run/manage agent platforms | Small org, approachable | Rapid refactors |
| 3 | `FoundationAgents/OpenManus` | 56k | Open Manus-style planner agent | Community-driven, viral | Meta PRs deprioritized |
| 4 | `BerriAI/litellm` | 50k | LLM gateway w/ cost tracking + guardrails | Governance is **on-brand** | Strict CI, company-owned |
| 5 | `Skyvern-AI/skyvern` | 13k | Browser-automation agent | Maintainer triages personally | Smaller reach |
| 6 | `letta-ai/letta` | 22k | Stateful agents w/ long-term memory | Mid-size, approachable | Opinionated arch |
| 7 | `run-llama/llama_index` | 50k | RAG / data-agent framework | Flagship visibility | Large org, likely CLA |
| 8 | `crewAIInc/crewAI` | 53k | Multi-agent orchestration | Huge mindshare | VC-backed, busy |
| 9 | `OpenInterpreter/open-interpreter` | 58k | NL code-execution agent | Broad community | Slowed cadence, PR backlog |
| 10 | `browser-use/browser-use` | 99k | Browser automation for agents | Massive velocity | Flooded PR queue |
| 11 | `langflow-ai/langflow` | 150k | Low-code agent builder (85% Py) | Top-tier visibility | IBM/DataStax process |
| 12 | `Significant-Gravitas/AutoGPT` | 184k | Autonomous-AI platform | Iconic star count | Monorepo, cold PRs ignored |
| 13 | `openai/openai-agents-python` | ~20k+ | OpenAI's official agent SDK | Reference SDK | OpenAI CLA, library-not-app |

## Recommended first 5 (likely to be noticed AND welcomed)

1. **`assafelovic/gpt-researcher`** — founder-led, active, human-reviewed. Best single bet.
2. **`agno-agi/agno`** — small fast-growing team; governance framing fits "manage agent platforms."
3. **`FoundationAgents/OpenManus`** — community/research-driven, high visibility for credibility.
4. **`BerriAI/litellm`** — guardrails is literally in its tagline; topically coherent.
5. **`Skyvern-AI/skyvern`** or **`letta-ai/letta`** — mid-size products, better signal-to-noise.

## Avoid / weak targets

- **`microsoft/autogen`** — in **maintenance mode** (Q1 2026); non-bugfix PRs won't merge. Live lineage is the smaller AG2 fork.
- **`langchain-ai/langchain` / `langgraph`** — enormous org, strict CLA, governance already in place. Near-zero odds.
- **`antonosika/gpt-engineer`** — effectively archived (points to Lovable).
- **Dify and many low-code builders** — often TS/Go in the deployable surface; verify language split first.

## The play per target

1. `release-gate audit https://github.com/<org>/<repo>` → capture the score/missing safeguards.
2. Open an **issue** ("AI deployment readiness: missing budget ceiling / kill switch?") to gauge interest.
3. If welcomed: `release-gate audit <url> --emit-config -o governance.yaml`, fill TODOs, open a small PR.
4. Include the `--badge` snippet so the score is visible on their README.
