"""RG-PII-001 — sensitive context reaching the model unmasked on one path.

The rule's value is in what it REFUSES to say. "This project has no PII
masking" is a universal negative over the whole repo plus its deployment —
masking can live in middleware, a template renderer, or a gateway outside the
codebase — and asserting it is what made RG-GATE-001 wrong on ha-mcp in public.
So the rule fires only on divergence: masked at A, raw at B, both printed.

Most of these tests therefore assert SILENCE. They are the regression guards
that keep the precondition load-bearing.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from release_gate.verify import scan_code_findings

CLIENT = """from openai import OpenAI
client = OpenAI()
"""

MASKED = CLIENT + """from presidio_anonymizer import AnonymizerEngine
engine = AnonymizerEngine()

def answer(store, q):
    docs = store.similarity_search(q)
    clean = engine.anonymize(docs)
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": clean}], max_tokens=512)
"""

RAW = CLIENT + """
def summarize(store, topic):
    docs = store.similarity_search(topic)
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": docs}], max_tokens=512)
"""


def _pii(**files) -> list:
    """Scan a miniature repo, return only its RG-PII-001 findings."""
    with tempfile.TemporaryDirectory() as d:
        for name, src in files.items():
            Path(d, name + ".py").write_text(src)
        return [f for f in scan_code_findings(Path(d))
                if f.get("rule_id") == "RG-PII-001"]


# ── The precondition: no oracle in the repo means no finding ─────────────────

def test_no_masking_anywhere_is_silent():
    """A project that masks nothing gets nothing. This is the whole design.

    Two raw paths look exactly like the "vulnerable" case minus the masked
    exemplar — and we stay quiet, because without it we would be asserting an
    opinion about what the project owes rather than an inconsistency it proves.
    """
    assert _pii(a=RAW, b=RAW) == []


def test_all_paths_masked_is_silent():
    assert _pii(a=MASKED, b=MASKED) == []


def test_single_masked_path_alone_is_silent():
    assert _pii(a=MASKED) == []


def test_central_masking_does_not_self_incriminate():
    """The ha-mcp shape: masking hoisted into one wrapper both paths call.

    Neither call site shows a local sanitizer, so the precondition fails and we
    stay silent — the rule is structurally unable to punish the fix it asks for.
    """
    wrapper = CLIENT + """from presidio_anonymizer import AnonymizerEngine
engine = AnonymizerEngine()

def ask(text):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": engine.anonymize(text)}],
        max_tokens=512)
"""
    caller = """from .wrapper import ask

def answer(store, q):
    return ask(store.similarity_search(q))
"""
    assert _pii(wrapper=wrapper, caller=caller) == []


# ── The positive case, and the evidence it must carry ───────────────────────

def test_divergence_is_reported_across_files():
    found = _pii(safe=MASKED, raw=RAW)
    assert len(found) == 1
    f = found[0]
    assert f["file"] == "raw.py"
    assert f["severity"] == "high" and f["basis"] == "confirmed"


def test_finding_cites_both_paths_and_a_checkable_chain():
    """A HIGH must be reproducible from the report alone: the masked exemplar
    to compare against, and origin -> value -> sink for the unmasked path."""
    f = _pii(safe=MASKED, raw=RAW)[0]
    ev = f["evidence"]
    assert "masked:" in ev and "unmasked:" in ev
    assert "safe.py" in ev and "raw.py" in ev
    assert "engine.anonymize()" in ev
    assert "store.similarity_search" in ev
    prov = f["provenance"]
    assert prov["origin_expr"] == "store.similarity_search"
    assert prov["value"] == "docs"
    assert prov["origin_line"] < prov["sink_line"]


# ── Tier discipline: a name is a guess and may not mint a HIGH ──────────────

def test_name_only_sanitizer_caps_at_medium():
    """`mask_pii()` might mask nothing — the tier ceiling exists for exactly
    this, so a helper recognised only by spelling cannot produce a HIGH."""
    named = CLIENT + """from myapp.pii import mask_pii

def answer(store, q):
    docs = store.similarity_search(q)
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": mask_pii(docs)}],
        max_tokens=512)
"""
    f = _pii(named=named, raw=RAW)[0]
    assert f["severity"] == "medium" and f["basis"] == "inferred"


# ── What counts as a redaction ──────────────────────────────────────────────

def test_regex_masking_confirms():
    """Regex masking is what most teams actually ship; recognised by the
    replacement's shape, not by anyone's naming discipline."""
    regex = CLIENT + """import re

def answer(store, q):
    docs = store.similarity_search(q)
    clean = re.sub(r"\\S+@\\S+", "***", docs)
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": clean}], max_tokens=512)
"""
    f = _pii(regex=regex, raw=RAW)[0]
    assert f["severity"] == "high" and f["basis"] == "confirmed"


def test_whitespace_resub_is_not_a_mask():
    """`re.sub(r"\\s+", " ", t)` normalizes whitespace. Treating it as redaction
    would invent an oracle and make every other path in the repo a finding."""
    tidy = CLIENT + """import re

def answer(store, q):
    docs = store.similarity_search(q)
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": re.sub(r"\\s+", " ", docs)}],
        max_tokens=512)
"""
    assert _pii(tidy=tidy, raw=RAW) == []


def test_inline_mask_in_the_argument_counts():
    inline = CLIENT + """from presidio_anonymizer import AnonymizerEngine
engine = AnonymizerEngine()

def answer(store, q):
    docs = store.similarity_search(q)
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": engine.anonymize(docs)}],
        max_tokens=512)
"""
    # Recognised as the masked oracle: it is never itself reported, and it is
    # what lets the raw path be graded confirmed.
    assert _pii(inline=inline) == []
    found = _pii(inline=inline, raw=RAW)
    assert [f["file"] for f in found] == ["raw.py"]
    assert found[0]["basis"] == "confirmed"


# ── Scope: only untrusted context is egress ─────────────────────────────────

def test_constant_prompt_is_not_an_egress_site():
    """A developer-authored constant is not sensitive context, so a masked path
    beside a hardcoded prompt must not implicate the constant."""
    greet = CLIENT + """
def greet():
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "say hello"}],
        max_tokens=512)
"""
    assert _pii(safe=MASKED, greet=greet) == []


def test_masked_value_keeps_untrusted_provenance():
    """Redaction removes PII; it does not make retrieved text trustworthy.
    The masked var must stay untrusted so injection rules still see it, and so
    the masked path can still print a full chain."""
    from release_gate.agent_analysis import analyze_python
    egress: list = []
    analyze_python(MASKED, "safe.py", egress=egress)
    assert len(egress) == 1
    e = egress[0]
    assert e["sanitized"] is True
    assert e["origin_expr"] == "store.similarity_search"
    assert e["origin_line"] > 0


def test_sanitized_state_does_not_leak_between_functions():
    """A masked `docs` in one function must not silence a raw `docs` in another
    — otherwise one careful function immunizes the whole file by name alone."""
    mixed = CLIENT + """from presidio_anonymizer import AnonymizerEngine
engine = AnonymizerEngine()

def safe_path(store, q):
    docs = store.similarity_search(q)
    docs = engine.anonymize(docs)
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": docs}], max_tokens=512)

def raw_path(store, q):
    docs = store.similarity_search(q)
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": docs}], max_tokens=512)
"""
    found = _pii(mixed=mixed)
    assert len(found) == 1
    assert found[0]["line"] > 8      # the raw_path call site, not the safe one


# ── Sink reach: the model call is usually the project's own wrapper ──────────

def test_project_defined_llm_wrapper_is_an_egress_sink():
    """Real code calls `call_llm(system, user_msg)`, a local function that POSTs
    to a provider host. An SDK-shaped sink detector never sees it — the same
    gap the deployed-agent corpus found blocking gpt-engineer."""
    from release_gate.agent_analysis import analyze_python
    src = '''import httpx

def call_llm(system_prompt, user_message):
    url = "https://generativelanguage.googleapis.com/v1beta/models/x:generateContent"
    with httpx.Client() as c:
        return c.post(url, json={"system": system_prompt, "user": user_message})

def answer(store, q):
    docs = store.similarity_search(q)
    return call_llm("be helpful", docs)
'''
    egress: list = []
    analyze_python(src, "w.py", egress=egress)
    assert len(egress) == 1
    assert egress[0]["origin_expr"] == "store.similarity_search"
    assert egress[0]["sanitized"] is False


def test_wrapper_without_a_provider_host_is_not_a_sink():
    """A function that POSTs somewhere unrelated is not a model call. Without
    the host gate every HTTP helper in a repo becomes an egress site."""
    from release_gate.agent_analysis import analyze_python
    src = '''import httpx

def send_webhook(payload):
    with httpx.Client() as c:
        return c.post("https://hooks.internal.example.com/notify", json=payload)

def answer(store, q):
    docs = store.similarity_search(q)
    return send_webhook(docs)
'''
    egress: list = []
    analyze_python(src, "w.py", egress=egress)
    assert egress == []
