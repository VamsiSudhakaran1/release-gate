# release-gate — AI Agent Readiness

Inline AI deployment safeguard feedback as you code. The extension runs `release-gate audit` against your workspace or active file and surfaces findings directly in VS Code's Problems panel, so you catch missing governance, unbounded loops, hardcoded secrets, and unsafe tool usage before you push. A status bar item shows your live readiness score and PROMOTE / HOLD / BLOCK decision at a glance.

## Setup

**Option A — CLI (recommended for local dev)**

Install the release-gate CLI and the extension picks it up automatically:

```bash
pip install release-gate
```

**Option B — API token (no CLI required)**

1. Sign up at [release-gate.com](https://release-gate.com) and go to **Settings → API**.
2. Copy your token and paste it into `release-gate.apiToken` in VS Code settings.

## Configuration

| Setting | Type | Default | Description |
|---|---|---|---|
| `release-gate.apiUrl` | `string` | `https://api.release-gate.com` | release-gate API base URL |
| `release-gate.apiToken` | `string` | `""` | API token from release-gate.com (Settings → API) |
| `release-gate.runOnSave` | `boolean` | `false` | Auto-audit on every file save |
| `release-gate.minSeverity` | `"high"` \| `"medium"` \| `"low"` | `"medium"` | Minimum severity level shown as Problems |

## Screenshots

_Screenshots coming soon._

<!-- TODO: add screenshot of Problems panel with release-gate findings -->
<!-- TODO: add screenshot of status bar showing score and decision -->
