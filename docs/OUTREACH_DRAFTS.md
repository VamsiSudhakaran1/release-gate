# Outreach issue drafts

Pre-written GitHub issue text for the two strongest deployed-app targets. Both
**open with a question to gauge interest** — do not attach a PR until a
maintainer responds. Keep it short, specific, and non-spammy. If they engage,
follow with `release-gate audit <url> --emit-config -o governance.yaml`.

---

## 1. `assafelovic/gpt-researcher` — framing: "formalize what you already have"

**Title:** Add an AI deployment-readiness config (governance.yaml)?

**Body:**

> Hi! I maintain [release-gate](https://github.com/VamsiSudhakaran1/release-gate),
> a small open-source tool that scores a repo's AI-deployment readiness before
> ship (budget ceilings, kill switch, auth, evals, trace policy → PROMOTE / HOLD / BLOCK).
>
> I ran it against gpt-researcher and it scored **60/100 (HOLD)** — which is
> actually a compliment. You already have:
>
> - ✅ Budget / cost ceiling
> - ✅ Kill switch / fallback
> - ✅ Auth & rate limiting
> - ✅ Eval evidence
>
> The only gaps it flagged are a **formal `governance.yaml`** that documents the
> above in one place, a **team-owner/on-call field**, and a **trace/tool policy**.
>
> Would a small PR adding a `governance.yaml` (documenting the safeguards you
> already have) + an optional readiness badge for the README be welcome? Happy
> to keep it to a single self-contained file — no code changes. Totally fine if
> it's not a fit; just wanted to check before opening anything.

---

## 2. `BerriAI/litellm` — framing: "model what you preach"

**Title:** Reference `governance.yaml` for the proxy — eat-our-own-cooking example?

**Body:**

> Hi team! litellm is the tool tens of thousands of teams use to put **cost
> controls, rate limiting, and guardrails** in front of their LLM calls — so
> you're closer to this problem than almost anyone.
>
> I ran [release-gate](https://github.com/VamsiSudhakaran1/release-gate) (an
> AI-deployment-readiness scorer) against this repo and it scored **60/100 (HOLD)**.
> It correctly detected the safeguards the proxy already supports:
>
> - ✅ Budget / cost ceiling
> - ✅ Kill switch / fallback
> - ✅ Auth & rate limiting
> - ✅ Eval evidence
>
> Gaps flagged: a **formal `governance.yaml`**, a **team-owner/on-call field**,
> and a **trace/tool policy**.
>
> Would you be open to a small PR adding a reference `governance.yaml` for the
> proxy deployment — a worked example your enterprise users could copy to
> document budgets/auth/fallback for their own gateway? Feels on-brand given the
> product, but I'll only open it if it's useful to you.

---

## Notes / honesty guardrails

- The "✅ detected" lists come from a shallow scan — **double-check each item is
  actually true** in the repo before posting, or a maintainer will catch an
  overclaim. (Auth/evals detection is reliable; budget/kill-switch can be noisy.)
- Do **not** post the BLOCK-scoring repos (skyvern 20, letta 40) with the same
  template — those scores may be scan-cap false negatives. Verify manually first.
- One issue at a time. If the first gets a positive reply, the PR + badge is the
  follow-up; if it's ignored or closed, don't escalate.
