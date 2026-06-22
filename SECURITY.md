# Security Policy

## Supported Versions

Only the latest release series receives security fixes.

| Version | Supported |
| ------- | :-------: |
| v0.7.x  | ✅        |
| < v0.7  | ❌        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by email to **Vamsi.sudhakaran@gmail.com** with the subject line:

> `release-gate security`

Include a description of the issue, steps to reproduce, and the potential impact. You will
receive an acknowledgement within 48 hours and a resolution timeline within 7 days.

For critical vulnerabilities, we aim to ship a patch release within 14 days of confirmation.
After the fix is released, we will publish a [GitHub Security Advisory](https://github.com/VamsiSudhakaran1/release-gate/security/advisories)
crediting the reporter (unless you prefer to remain anonymous).

## Security Policy

- **No code stored:** release-gate performs all analysis locally or in ephemeral containers.
  Your source code is never persisted on our servers.
- **Read-only GitHub App:** the release-gate GitHub App requests only `contents: read` and
  `pull_requests: write` (for PR comments) permissions. It never writes to your repository.
- **No training on your code:** your repository contents are never used to train models or
  improve any ML system.
- **Dependency pinning:** production installs should pin hashes via
  `pip install release-gate --require-hashes` (see `pyproject.toml` for guidance).

## GitHub Security Advisories

Published advisories are available at:
<https://github.com/VamsiSudhakaran1/release-gate/security/advisories>
