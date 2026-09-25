"""The line between local use and enterprise dependencies, measured.

`pip install release-gate` is meant to be a lean CLI a security team can vet in
an afternoon, and the assurance engine is meant to run on the standard library
alone. Both are claims about an import graph, and an import graph drifts the
first time someone adds a convenient helper. So these tests measure rather than
assert: the decision path runs in a subprocess with every third-party module
blocked, and the boundary fails loudly the moment something crosses it.

A subprocess, not a fixture, because `sys.modules` is already populated by the
time a test runs — pytest itself imports third-party code — and a guard checked
inside this process would pass on modules that were already in.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from release_gate.assurance.ports import (
    CaseStore, Deployment, DeploymentProfile, EventLog, InMemoryCaseStore,
    InMemoryEventLog, InMemoryWorkQueue, LocalFileCaseStore,
    LocalFileObjectStore, ObjectStore, Port, PortBinding, PortError, StoredCase,
    WorkQueue, WorkUnit, enterprise_profile, local_profile,
)
from release_gate.demos import single_agent

#: Everything in the base install plus every optional extra. Blocking the base
#: deps too is the point: the engine is supposed to need none of them.
BLOCKED = ("yaml", "jsonschema", "cryptography", "cffi", "_cffi_backend",
           "fastapi", "starlette", "uvicorn", "pydantic", "jose", "passlib",
           "bcrypt", "httpx", "psycopg2", "jwt", "fpdf", "mcp", "requests",
           "urllib3", "numpy", "openai", "anthropic")

_PREAMBLE = """
import builtins, sys
BLOCK = set({blocked!r})
_real = builtins.__import__
def _guard(name, *a, **k):
    if name.split(".")[0] in BLOCK:
        raise ModuleNotFoundError("blocked by the production boundary: " + name)
    return _real(name, *a, **k)
for _m in [m for m in sys.modules if m.split(".")[0] in BLOCK]:
    del sys.modules[_m]
builtins.__import__ = _guard
"""


def run_sealed(body: str, blocked=BLOCKED) -> subprocess.CompletedProcess:
    """Run `body` in a fresh interpreter with `blocked` imports unavailable."""
    script = _PREAMBLE.format(blocked=list(blocked)) + textwrap.dedent(body)
    return subprocess.run([sys.executable, "-c", script], capture_output=True,
                          text=True, cwd=str(Path(__file__).resolve().parent.parent))


# ── the engine needs nothing ──────────────────────────────────────────────────

class TestStandardLibraryOnly:

    def test_the_assurance_package_imports_sealed(self):
        found = run_sealed("""
            import release_gate.assurance
            print("OK")
        """)
        assert found.returncode == 0, found.stderr[-2000:]
        assert "OK" in found.stdout

    def test_the_whole_decision_path_runs_sealed(self):
        """Ingest, analyse, assess, decide and render, on no dependencies."""
        found = run_sealed("""
            import json, tempfile, pathlib
            from release_gate.demos import single_agent
            from release_gate.assurance.zero_config import assure, render_text
            root = pathlib.Path(tempfile.mkdtemp())
            path = root / "case.json"
            path.write_text(json.dumps(single_agent.build_document()))
            outcome = assure(str(path))
            print("DECISION", outcome.case.verdict.decision.value,
                  outcome.exit_code, len(render_text(outcome).splitlines()))
        """)
        assert found.returncode == 0, found.stderr[-2000:]
        decision, code, lines = found.stdout.split("DECISION")[1].split()
        assert decision in ("PROMOTE", "HOLD", "BLOCK")
        assert int(code) in (0, 10, 1)
        assert int(lines) > 20

    def test_every_port_binds_sealed(self):
        found = run_sealed("""
            import tempfile
            from release_gate.assurance.ports import (
                InMemoryCaseStore, InMemoryEventLog, InMemoryWorkQueue,
                LocalFileCaseStore, LocalFileObjectStore, local_profile)
            root = tempfile.mkdtemp()
            LocalFileCaseStore(root + "/cases"); LocalFileObjectStore(root + "/obj")
            InMemoryCaseStore(); InMemoryEventLog(); InMemoryWorkQueue()
            print("PORTS", local_profile().requires_third_party)
        """)
        assert found.returncode == 0, found.stderr[-2000:]
        assert "PORTS False" in found.stdout

    def test_the_approval_and_identity_surfaces_run_sealed(self):
        """The newest layers too, not just the original decision path."""
        found = run_sealed("""
            from release_gate.demos import single_agent
            from release_gate.assurance.approval_view import build_view, render_view
            from release_gate.assurance.verdict import explain_verdict
            from release_gate.assurance.identity import claim_from, IdentityProvider
            outcome = single_agent.run().outcome
            view = build_view(outcome)
            statement = explain_verdict(outcome)
            claim = claim_from(IdentityProvider.SELF_ASSERTED, {"approver": "a"})
            print("SURFACES", len(view.displays), statement.decision.value,
                  claim.authenticates)
        """)
        assert found.returncode == 0, found.stderr[-2000:]
        assert "SURFACES 9" in found.stdout
        assert "False" in found.stdout

    def test_the_guard_itself_works(self):
        """A test that cannot fail is not a guard. This proves the seal bites."""
        found = run_sealed("import yaml")
        assert found.returncode != 0
        assert "blocked by the production boundary" in found.stderr


# ── the CLI degrades rather than dying ───────────────────────────────────────

class TestCliDegradation:
    """A broken optional backend must not take the CLI with it. It did once: a
    `cryptography` wheel that fails to initialise raises `PanicException`, which
    derives from BaseException and slipped past guards catching `Exception`."""

    def test_the_cli_imports_without_cryptography(self):
        """Blocking only `cryptography`, since the CLI genuinely needs `yaml`."""
        found = run_sealed("""
            import release_gate.cli as cli
            print("CLI_OK", sorted(cli.OPTIONAL_FAILURES))
        """, blocked=("cryptography", "cffi", "_cffi_backend"))
        assert found.returncode == 0, found.stderr[-2000:]
        assert "crypto" in found.stdout

    def test_and_records_why_rather_than_going_quiet(self):
        found = run_sealed("""
            import release_gate.cli as cli
            print("WHY", cli.OPTIONAL_FAILURES.get("crypto"))
        """, blocked=("cryptography", "cffi", "_cffi_backend"))
        assert "ModuleNotFoundError" in found.stdout

    def test_the_cli_does_need_yaml(self):
        """Measured, not assumed: three declared base dependencies, and this is
        the only one the CLI cannot start without."""
        assert run_sealed("import release_gate.cli",
                          blocked=("yaml",)).returncode != 0
        assert run_sealed("import release_gate.cli",
                          blocked=("jsonschema",)).returncode == 0

    def test_a_failed_optional_import_is_diagnosable(self):
        """Recorded, not silently absent — `assure --diagnostics` reads this."""
        import release_gate.cli as cli
        assert isinstance(cli.OPTIONAL_FAILURES, dict)


# ── a store is not an authority ──────────────────────────────────────────────

class TestStoreIsNotAnAuthority:

    @pytest.fixture
    def outcome(self):
        return single_agent.run().outcome

    @pytest.mark.parametrize("store", [InMemoryCaseStore(),
                                       "file"], ids=["memory", "file"])
    def test_retrieval_never_establishes_validity(self, store, tmp_path):
        if store == "file":
            store = LocalFileCaseStore(tmp_path / "cases")
        assert store.retrieval_establishes_validity is False

    def test_a_row_must_be_matched_against_the_case_in_hand(self, outcome, tmp_path):
        store = LocalFileCaseStore(tmp_path / "cases")
        key = store.put(StoredCase.of(outcome.case))
        assert store.get(key).matches(outcome.case)

    def test_a_row_for_another_case_does_not_match(self, outcome, tmp_path):
        from release_gate.demos import frontier_research
        other = frontier_research.run(
            scenario=frontier_research.ResearchScenario(workers=40)).outcome
        store = LocalFileCaseStore(tmp_path / "cases")
        store.put(StoredCase.of(outcome.case))
        stored = store.get(StoredCase.of(outcome.case).key)
        assert not stored.matches(other.case)

    def test_a_stored_case_needs_the_digests_it_was_decided_on(self):
        with pytest.raises(PortError) as exc:
            StoredCase(case_id="c", case_version=1, case_digest="",
                       subject_digest="d")
        assert "a row, not a record" in str(exc.value)

    def test_versions_are_kept_apart(self, outcome, tmp_path):
        """A case that moved is a different thing to bind an approval to."""
        store = LocalFileCaseStore(tmp_path / "cases")
        base = StoredCase.of(outcome.case)
        store.put(base)
        import dataclasses
        store.put(dataclasses.replace(base, case_version=2))
        assert store.versions(base.case_id) == (1, 2)

    def test_absence_reads_as_none_not_as_an_empty_case(self, tmp_path):
        assert LocalFileCaseStore(tmp_path / "cases").get("nothing@1") is None

    def test_a_key_cannot_escape_the_store_root(self, tmp_path):
        store = LocalFileCaseStore(tmp_path / "cases")
        for key in ("../escape@1", "/etc/passwd@1", ".hidden@1"):
            with pytest.raises(PortError):
                store.get(key)

    def test_a_write_is_atomic(self, outcome, tmp_path):
        """No half-written file, because a truncated case reads as evidence
        having been absent."""
        root = tmp_path / "cases"
        store = LocalFileCaseStore(root)
        store.put(StoredCase.of(outcome.case))
        assert not list(root.glob("*.tmp"))

    def test_a_local_store_states_what_it_is(self, tmp_path):
        assert LocalFileCaseStore(tmp_path / "c").durable
        assert not InMemoryCaseStore().durable


# ── the address is the check ──────────────────────────────────────────────────

class TestObjectStore:

    def test_put_computes_the_digest_rather_than_accepting_one(self, tmp_path):
        store = LocalFileObjectStore(tmp_path / "obj")
        digest = store.put(b"a large trace nobody wants in a pack")
        assert digest.startswith("sha256:") and len(digest) == 71

    def test_it_round_trips(self, tmp_path):
        store = LocalFileObjectStore(tmp_path / "obj")
        data = b"x" * 5000
        assert store.get(store.put(data)) == data

    def test_the_same_bytes_store_once(self, tmp_path):
        store = LocalFileObjectStore(tmp_path / "obj")
        assert store.put(b"same") == store.put(b"same")

    def test_tampered_bytes_are_caught_on_read(self, tmp_path):
        """The property the whole design rests on: a locator alone says where to
        look, not whether what is there is what was argued."""
        store = LocalFileObjectStore(tmp_path / "obj")
        digest = store.put(b"the verified artifact")
        store._path(digest).write_bytes(b"something else entirely")
        with pytest.raises(PortError) as exc:
            store.get(digest)
        assert "not what was argued" in str(exc.value)

    def test_a_missing_object_is_a_gap_not_a_clean_read(self, tmp_path):
        store = LocalFileObjectStore(tmp_path / "obj")
        with pytest.raises(PortError) as exc:
            store.get("sha256:" + "0" * 64)
        assert "coverage gap, not a clean read" in str(exc.value)

    def test_it_refuses_a_non_content_address(self, tmp_path):
        store = LocalFileObjectStore(tmp_path / "obj")
        for bad in ("../../etc/passwd", "md5:abc", "sha256:xyz"):
            with pytest.raises(PortError):
                store.get(bad)

    def test_has_is_false_for_a_malformed_address(self, tmp_path):
        assert not LocalFileObjectStore(tmp_path / "obj").has("not-a-digest")

    def test_a_locator_can_be_carried_on_an_external_reference(self, tmp_path):
        from release_gate.assurance.pack import ExternalReference
        store = LocalFileObjectStore(tmp_path / "obj")
        digest = store.put(b"raw trace")
        ref = ExternalReference(record_id="ev_1", kind="trace",
                                locator=store.locator(digest), digest=digest)
        assert ref.resolvable


# ── delivery is at least once ────────────────────────────────────────────────

class TestEventLog:

    def test_exactly_once_is_never_claimed(self):
        assert InMemoryEventLog().delivery_is_exactly_once is False

    def test_append_and_read_with_a_cursor(self):
        log = InMemoryEventLog()
        log.append([{"record_type": "evidence", "i": i} for i in range(5)])
        first, cursor = log.read(limit=2)
        second, _ = log.read(cursor=cursor, limit=10)
        assert len(first) == 2 and len(second) == 3

    def test_a_duplicate_batch_folds_once_because_records_are_addressed(self):
        """What the arrival-clock fix bought: at-least-once ingestion that
        converges."""
        from release_gate.assurance.evidence import EvidenceRecord, Producer, ProducerKind
        agent = Producer("agent://a", ProducerKind.AGENT)
        one = EvidenceRecord.declared(evidence_type="TOOL_RESULT", source="s",
                                      producer=agent, content={"exit_code": 0})
        two = EvidenceRecord.declared(evidence_type="TOOL_RESULT", source="s",
                                      producer=agent, content={"exit_code": 0})
        log = InMemoryEventLog()
        log.append([one.to_dict()])
        log.append([two.to_dict()])
        rows, _ = log.read()
        assert len(rows) == 2
        assert len({r["record_id"] for r in rows}) == 1

    def test_a_cursor_cannot_be_negative(self):
        with pytest.raises(PortError):
            InMemoryEventLog().read(cursor=-1)


# ── a worker is a producer ───────────────────────────────────────────────────

class TestWorkQueue:

    def test_results_are_never_verified(self):
        assert InMemoryWorkQueue().results_are_verified is False

    def test_a_unit_must_say_what_it_is(self):
        with pytest.raises(PortError):
            WorkUnit(kind="  ")

    def test_the_same_work_submitted_twice_is_one_unit(self):
        queue = InMemoryWorkQueue()
        unit = WorkUnit(kind="verify", payload={"target": "claim_a"})
        queue.submit(unit)
        queue.submit(WorkUnit(kind="verify", payload={"target": "claim_a"}))
        assert queue.depth == 1

    def test_claim_then_complete(self):
        queue = InMemoryWorkQueue()
        queue.submit(WorkUnit(kind="verify", payload={"t": 1}))
        (claimed,) = queue.claim()
        queue.complete(claimed.unit_id, {"status": "PASSED"})
        assert queue.result(claimed.unit_id)["status"] == "PASSED"

    def test_a_result_for_unclaimed_work_is_refused(self):
        queue = InMemoryWorkQueue()
        with pytest.raises(PortError) as exc:
            queue.complete("wu_nothing", {"status": "PASSED"})
        assert "somewhere unaccounted for" in str(exc.value)


# ── the deployment record ────────────────────────────────────────────────────

class TestDeployment:

    def test_a_port_left_out_is_refused(self):
        """A port missing from the list reads as one nobody thought about."""
        with pytest.raises(PortError) as exc:
            Deployment(profile=DeploymentProfile.LOCAL, bindings=(
                PortBinding(Port.API, "x", limitations=("y",)),))
        assert "nobody thought about" in str(exc.value)

    def test_a_binding_must_state_its_limits(self):
        with pytest.raises(PortError) as exc:
            PortBinding(Port.CASE_STORE, "PostgreSQL")
        assert "trust furthest" in str(exc.value)

    def test_an_unbound_port_may_still_state_what_is_missing(self):
        assert PortBinding(Port.EVENT_LOG, "none", bound=False,
                           limitations=("no streaming",)).limitations

    def test_a_port_cannot_be_bound_twice(self):
        with pytest.raises(PortError):
            Deployment(profile=DeploymentProfile.LOCAL, bindings=tuple(
                [PortBinding(p, "x", limitations=("y",)) for p in Port]
                + [PortBinding(Port.API, "z", limitations=("w",))]))

    def test_local_needs_nothing_third_party(self):
        assert local_profile().requires_third_party is False

    def test_enterprise_says_it_does(self):
        assert enterprise_profile().requires_third_party is True

    def test_local_names_the_three_ports_it_does_not_bind(self):
        assert set(local_profile().unbound) == {Port.API, Port.EVENT_LOG,
                                                Port.WORK_QUEUE}

    def test_every_deployment_can_say_what_it_cannot_do(self):
        for deployment in (local_profile(), enterprise_profile()):
            assert len(deployment.cannot()) >= 8

    def test_ports_never_change_the_verdict(self):
        """Ports are I/O. A deployment that decided differently would mean the
        authoritative path was not deterministic after all."""
        for deployment in (local_profile(), enterprise_profile()):
            assert deployment.decides_differently is False
            assert deployment.to_dict()["decides_differently"] is False

    def test_the_same_case_reaches_the_same_verdict_either_way(self, tmp_path):
        """Measured, not asserted: decide, store, reload, and compare."""
        outcome = single_agent.run().outcome
        store = LocalFileCaseStore(tmp_path / "cases")
        key = store.put(StoredCase.of(outcome.case))
        reloaded = store.get(key)
        assert reloaded.verdict["decision"] == outcome.case.verdict.decision.value
        assert reloaded.case_digest == outcome.case.case_digest

    def test_the_enterprise_backends_are_labels_not_imports(self):
        """Naming PostgreSQL does not import psycopg2. The names are for a
        report; the adapters live outside this package, where a driver
        dependency belongs."""
        from release_gate.assurance import ports as module
        source = Path(module.__file__).read_text()
        for driver in ("psycopg2", "boto3", "kafka", "celery", "redis",
                       "sqlalchemy", "requests", "httpx", "pymongo"):
            assert f"import {driver}" not in source, driver
        assert "PostgreSQL" in enterprise_profile().to_dict()["bindings"][1]["backend"]
