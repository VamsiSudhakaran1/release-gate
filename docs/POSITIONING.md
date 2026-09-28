# Positioning

What release-gate says about itself, what each claim rests on, and what it will not
say. Every line in the first section is traceable to code that runs; the numbers are
measured, not remembered, and the section after it says how to re-measure them.

A claim that outruns its implementation is the failure this project exists to
prevent. Applying that to its own marketing is the cheapest possible test of whether
it means it.

---

## The three statements

### Primary

> Release-Gate builds the assurance case behind machine-generated results before a
> human accepts responsibility for them.

**Builds the assurance case.** `AssuranceCase` is the object: a subject, the evidence
collections, the coverage ledger, a sealed digest. `rg.create_case(...)` opens one and
`finalize()` decides it.

**Behind machine-generated results.** The input is what agents, tools and pipelines
produced — traces, test runs, proofs, replications, counterexamples. Release-gate
generates none of it.

**Before a human accepts responsibility.** Structural, not advisory. A case has no
decision until it is finalized — reading `outcome` beforehand raises *"this case has
not been finalized, so it has no decision"* — and a `BoundApproval` binds to that
sealed case's `case_digest`. When the state moves, the approval stops binding and says
why. Somebody accepting responsibility is a separate, recorded act; release-gate is
what exists before it.

**What it deliberately does not say.** Not "verifies". Not "certifies". *Builds the
case* is the whole claim: assembling an argument and its gaps is a different act from
warranting a conclusion.

### Secondary

> From one agent to thousands of parallel researchers, Release-Gate reconstructs the
> evidence behind a machine-generated result and tells the human what still requires
> judgment.

**One agent to thousands.** Two shipped demonstrations, one engine, one code path:

| | single-agent | frontier research |
|---|---|---|
| distinct producers | 4 | **10,254** |
| evidence records | 6 | 10,258 |
| claims | 0 | 2,420 |
| verdict | PROMOTE | BLOCK |
| items put to a person | 1 | 13 |

"Thousands" understates the second column. Separately, `Case.stream()` folds a
million events while growing resident memory by 0 MB, against roughly 850 MB per
million if they were held.

**Reconstructs the evidence.** `trace_verdict` walks verdict → condition →
subject/claim → evidence → source. Both demonstrations report **zero unexplained
steps**: no step in either chain is an assertion nothing supports. Where a chain stops
at a condition rather than reaching a source, it says so rather than implying it got
further.

**Tells the human what still requires judgment.** `HumanAttentionSet` is the list, and
each item carries what would resolve it. In the frontier case, 13 items of which 7 may
never be dropped — blocking, or on the critical path.

**What it deliberately does not say.** Not "tells the human what is wrong". Requiring
judgment and being wrong are different states, and most items are the first.

### Engineering

> Agents generate. Tools verify. Release-Gate determines whether the available
> evidence is sufficient to reach the next human authorization boundary.

**Agents generate. Tools verify.** Release-gate does neither. The verifier adapters
say it outright: *"Release-Gate does not replace these tools and does not check their
work."* A prover's output is recorded, not re-derived.

**Sufficient to reach the next human authorization boundary.** Read precisely, because
one reading is supported and one is not.

*Supported:* whether this evidence is structurally sound enough to be **put to a
person** — which is what PROMOTE / HOLD / BLOCK answers, and what the rules that fire
are about.

*Not supported:* whether the evidence is sufficient to **authorize the act**. That is a
domain question, and with no methodology stated release-gate says so in those words:
*"structural assurance is complete as far as it goes, but no methodology states what
evidence this decision requires. Domain sufficiency is NOT_ASSESSED."*

So the statement is about reaching the boundary, not about clearing it. With a
methodology stated, sufficiency is measured against that methodology and named as
such. Without one, the case holds and the gap is the reason.

---

## The six things it will not say

Each is refused in code, not in tone. "Refused in code" means a property that cannot
return anything else, or a rule that produces the opposite reading.

| Never claimed | Why, and where the refusal lives |
|---|---|
| **safe** | Release-gate holds no truth about whether an action is safe. `BenchmarkScope.measures_release_safety`, `DecisionLatency.is_a_safety_metric` and `HumanAttentionCompression.is_a_safety_metric` are unconditionally `False`. A verdict says *"structurally sound enough to put to a person"*, never *"safe to deploy"*. |
| **guaranteed correct** | An approval is authorization, not truth certification (Invariant 15). `Consultation.establishes_correctness` is unconditionally `False`; a vetted verifier's failing check is still a failure, and a vetted verifier's DECLARED result stays DECLARED. |
| **unhackable** | Nineteen attacks are run against the engine itself, and one of them — cross-tenant evidence mixing — is recorded `NOT_DEFENDED` with what bounds it instead. A threat model made of shrugs is worse than none, so a gap names its own limit rather than being left out. |
| **uncontested** | Contradictions, counterexamples, failed branches and adversarial review are first-class collections. A case that nobody tried to break reports adversarial review as NOT_ASSESSED rather than as clean. |
| **solves hallucinations** | Release-gate never inspects a model's output for truth. It records what was claimed, what checked it, and what nobody checked. An agent that lies consistently and alone is recorded as `OUTSIDE_VISIBILITY` in the threat model: internally coherent and entirely false, and release-gate cannot see it. |
| **replaces experts** | The output is a list of what needs a person, and an act's required authority is a name the *domain* supplies. `DomainAct.establishes_qualification` and `AuthorityReading.verifies_credentials` are unconditionally `False` — naming `clinician` records what a domain asks for and does not make release-gate a licensing board. |

There is a test, `tests/test_positioning.py`, that greps the documentation for these
phrasings in the affirmative. It is a **tripwire, not a proof**: a substring check
reads text, never meaning, and this project has been bitten by that often enough to
say so where the check lives.

---

## Re-measuring the numbers

```bash
python -c "
from release_gate.demos import frontier_research, single_agent
from release_gate.assurance.trace import trace_verdict
for name, mod in (('single_agent', single_agent), ('frontier', frontier_research)):
    out = mod.run().outcome
    producers = {getattr(getattr(r, 'producer', None), 'producer_id', '')
                 for r in out.case.collection('evidence').materialised}
    trace = trace_verdict(out)
    print(name, out.decision.value,
          'producers', len([p for p in producers if p]),
          'attention', len(out.attention.items),
          'unexplained', len(trace.unexplained))
"
```

Everything else in this document is pinned by the suite. The architecture behind each
claim is in [`docs/specs/universal-assurance-architecture.md`](specs/universal-assurance-architecture.md);
§10au records the audit this document came out of, including what the previous
positioning claimed and why it had to change.
