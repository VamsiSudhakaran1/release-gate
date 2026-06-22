# SLSA Provenance

release-gate targets **SLSA Level 2** for its release builds.

## Build Description

| Property         | Value                                           |
| ---------------- | ----------------------------------------------- |
| SLSA Level       | 2 (scripted, versioned build, hosted CI)        |
| Build platform   | GitHub Actions (ubuntu-latest)                  |
| Builder          | `pypa/build` via `setuptools`                   |
| Source           | `github.com/VamsiSudhakaran1/release-gate`      |
| Dependency lock  | pinned in `requirements.txt` + `pyproject.toml` |
| Signed releases  | planned (Sigstore / GitHub OIDC)                |

## How Releases Are Built

1. A maintainer pushes a version tag (`v0.7.x`) to the repository.
2. The `.github/workflows/publish.yml` workflow triggers automatically — no manual build steps.
3. Dependencies are installed from pinned versions; the wheel is built with `python -m build`.
4. The resulting distribution is uploaded to PyPI via the `pypa/gh-action-pypi-publish` action
   using OpenID Connect (OIDC) — no long-lived PyPI tokens are stored in secrets.

## SHA-Pinned Action Reference Example

Action steps in `action.yml` are pinned to full commit SHAs to prevent supply-chain attacks
via mutable tags:

```yaml
- uses: actions/setup-python@0a5c61591373683505ea898e09424647f5f1c7db  # v5.4.0
- uses: actions/upload-artifact@6f51ac03b9356f520e9adb1b1b7802705f340c2b  # v4.6.0
- uses: github/codeql-action/upload-sarif@65c74964a9ed8c44ed9f19d4bbc5757a6a8af9e4  # v3.25.0
```

Pinning to a SHA rather than a tag ensures that even if the upstream action's tag is moved
(e.g., by a compromised maintainer), the exact, audited code continues to run.

## Roadmap to SLSA Level 3

- [ ] Generate and attach SLSA provenance attestations via `slsa-framework/slsa-github-generator`
- [ ] Sign release artifacts with Sigstore (`cosign`)
- [ ] Publish build provenance to the Sigstore transparency log
