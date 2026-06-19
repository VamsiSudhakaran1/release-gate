# GitHub App Setup — release-gate

## What it does

When installed on a repo, the GitHub App:
1. Runs `release-gate audit` on every PR
2. Posts a **Check Run** — ✅ PROMOTE / ⚠️ HOLD / 🚫 BLOCK
3. Posts a **PR comment** with the full safeguard table + fix instructions
4. Optionally opens a `governance.yaml` PR on HOLD/BLOCK repos (set `GITHUB_APP_OPEN_PR=1`)

---

## Step 1 — Register the GitHub App

Go to: **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**

Fill in:

| Field | Value |
|---|---|
<<<<<<< HEAD
| **App name** | `release-gate-ai` |
=======
| **App name** | `release-gate` |
>>>>>>> origin/main
| **Homepage URL** | `https://release-gate.com` |
| **Webhook URL** | `https://release-gate.com/api/github/webhook` |
| **Webhook secret** | Generate a random string (save it — this is `GITHUB_WEBHOOK_SECRET`) |

**Permissions (Repository):**
- Contents: **Read & Write** (to create governance.yaml PR)
- Pull requests: **Read & Write** (to post comments)
- Checks: **Read & Write** (to create check runs)
- Metadata: **Read**

**Subscribe to events:**
- Pull request
- Installation

**Where can this app be installed?** → Any account

Click **Create GitHub App**.

---

## Step 2 — Generate a private key

On the app settings page → **Generate a private key** → downloads a `.pem` file.

Convert it to a single-line string for the env var:
```bash
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' your-app.pem
```
Copy the output — this is `GITHUB_APP_PRIVATE_KEY`.

---

## Step 3 — Set environment variables in Vercel

In Vercel → Settings → Environment Variables, add:

| Variable | Value |
|---|---|
| `GITHUB_APP_ID` | The numeric App ID from the app settings page |
| `GITHUB_APP_PRIVATE_KEY` | The single-line PEM string from Step 2 |
| `GITHUB_WEBHOOK_SECRET` | The secret you set in Step 1 |
| `GITHUB_APP_OPEN_PR` | `1` to auto-open governance.yaml PRs (optional) |

Redeploy: `vercel --prod`

---

## Step 4 — Install the app

<<<<<<< HEAD
Go to: `https://github.com/apps/release-gate-ai` → Install → choose repos.
=======
Go to: `https://github.com/apps/release-gate` → Install → choose repos.
>>>>>>> origin/main

After install, open a PR on any installed repo — you'll see:
- A **release-gate check** in the PR status bar
- A **comment** with the safeguard table and fix instructions

---

## Webhook endpoint

`POST /api/github/webhook`

Handles:
- `pull_request` (opened / synchronize / reopened) → runs audit, posts check + comment
- `installation` → acknowledged

All other events → ignored (returns `{"skipped": true}`)

---

## Testing locally

```bash
# Install smee for local webhook forwarding
npm install -g smee-client
smee --url https://smee.io/your-channel --target http://localhost:8001/api/github/webhook

# Run the API
uvicorn api.main:app --port 8001

# Set env vars
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY="$(cat your-app.pem | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}')"
export GITHUB_WEBHOOK_SECRET=your-secret
```

Then open a PR on a repo where the app is installed — the webhook fires through smee to your local server.
