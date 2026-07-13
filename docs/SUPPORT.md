# Support & Versioning Policy

This document states what you can rely on if you put release-gate in a pipeline —
especially a **blocking** one, where a surprise change or a bad release costs you
a red build. The goal is simple: nothing about how this project ships should be a
guess.

For **security** reporting and supported-version windows, see
[`../SECURITY.md`](../SECURITY.md).

---

## Versioning

release-gate follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
While the project is pre-1.0, the contract is:

| Bump | What changes | What it can mean for your build |
| --- | --- | --- |
| **PATCH** (`0.8.5 → 0.8.6`) | Bug fixes, new *clean-case* benchmark guards, doc updates. | Same findings on the same code, or *fewer* false positives. Safe to take automatically. |
| **MINOR** (`0.8.x → 0.9.0`) | New rules, wider coverage, new CLI flags. | May surface **new findings** on code that previously passed. A pinned gate can start blocking. Read the changelog before upgrading a blocking gate. |
| **MAJOR** (`0.x → 1.0`) | Changed defaults, removed flags, changed exit-code semantics. | Behaviour you script against may change. Never automatic for a blocking gate. |

**A finding's stable rule id (`RG-EXEC-001`) never changes meaning across
versions.** If a rule's behaviour materially changes, it gets a new id and the
old one is deprecated — so a suppression you write today keeps meaning what you
meant.

## What counts as a breaking change

For a gate, "breaking" is broader than an API signature. We treat all of these as
**MAJOR**, called out explicitly in the changelog:

- A change to exit-code semantics (`0` PROMOTE / `10` HOLD / `1` BLOCK).
- Removing or renaming a CLI flag, command, or a documented config key.
- Changing a decision mode's default (`audit` / `ci` / `strict` / `public-advisory`).
- Changing the meaning of an existing rule id (a new id is issued instead).

New rules and *wider* detection are **MINOR**, not MAJOR — but because they can
turn a green build red, they are always listed under "may surface new findings"
in the changelog.

## Pinning guidance for a blocking gate

If a red build blocks a deploy, **pin the minor series and upgrade deliberately**:

```bash
# pip — allow patch fixes, hold the minor
pip install "release-gate>=0.8,<0.9"
```

```yaml
# GitHub Action — pin the tag
- uses: VamsiSudhakaran1/release-gate@v0.8.5
```

For maximum reproducibility, pin hashes with
`pip install release-gate --require-hashes`. Take MINOR upgrades on your own
schedule, after reading the changelog — never let a blocking gate float across a
minor bump.

## Release cadence

- **Patch releases** ship as fixes land — typically within days of a confirmed
  false positive or bug.
- **Minor releases** are batched and announced, with the "new findings you may
  see" section of the changelog filled in **before** release.
- Every release is tagged on GitHub and published to PyPI from the same commit,
  and the version is enforced consistent across `pyproject.toml`, the package,
  the API, and the Action by `scripts/check_version_sync.py` in CI. There is no
  such thing as a release where the Action and the package disagree.

## Deprecation policy

Anything user-facing that we intend to remove is:

1. Marked deprecated in the changelog and in `--help` output for **at least one
   full minor series** before removal.
2. Kept working (with a warning) during that window.
3. Removed only on a MAJOR bump.

## Accuracy is versioned too

Detection accuracy is not a claim — it's a checked-in artifact. Every release
runs [`benchmark/`](../benchmark/) against a labeled corpus and must hold
**100% precision** and **100% clean-case quiet rate** (`tests/test_benchmark.py`
fails the build otherwise). When we fix a false positive, the look-alike becomes
a permanent regression guard in that corpus, so a later version cannot silently
bring the false positive back. You can re-run the numbers yourself:

```bash
python benchmark/run.py
```

## Project maturity & maintainership

Honesty is part of the contract, so: **release-gate is currently maintained by a
single author.** If you are evaluating it as a hard blocking gate, that is a real
factor and you should weigh it. Here is what de-risks depending on it, concretely:

- **Reproducible accuracy.** You don't have to trust the precision claim — the
  benchmark and its ground truth are in the repo and run in CI (above).
- **A real disclosure process.** 48-hour acknowledgement, 7-day timeline, 14-day
  patch target for critical issues — see [`../SECURITY.md`](../SECURITY.md).
- **Pin-and-upgrade-deliberately.** The pinning guidance above means a bad
  release can't reach your pipeline until you choose to take it.
- **Local-first, no lock-in.** The static gate makes no network calls and reads
  only the directory it's pointed at; there is no server it depends on to run,
  so your CI does not hang on our uptime.
- **Contributors welcome.** Reducing the bus factor is an explicit goal. Rules
  live in a single registry (`release_gate/rules.py`) and every rule is backed by
  benchmark cases — a good on-ramp is documented in
  [`CONTRIBUTING.md`](CONTRIBUTING.md).

If depending on a single-maintainer project is a blocker for your organization,
start with the **`public-advisory`** decision mode (report, don't block) and move
to a blocking mode as the track record and contributor base grow. The tool is
designed to be useful at both settings.
