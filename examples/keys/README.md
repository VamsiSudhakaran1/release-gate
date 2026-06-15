# Demo keys

`demo-governance-key.pub` is a **public** key, safe to share, provided only so you
can try `release-gate validate-and-lock --verify` against the demo signatures.

## Never commit private keys

- Private keys (`*.pem`, `*.key`) are git-ignored at the repo root.
- Generate your own key pair for real use:

  ```bash
  openssl genrsa -out governance-key.pem 2048
  openssl rsa -in governance-key.pem -pubout -out governance-key.pub
  ```

- Store the **private** key in your secrets manager (GitHub Secrets, Vault, etc.).
  Only the public key belongs in version control.

> If you ever see a private `.pem` committed to a repository, treat that key as
> compromised and rotate it immediately.
