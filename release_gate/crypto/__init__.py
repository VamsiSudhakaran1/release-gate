"""
release-gate's host-boundary cryptography.

- governance_signer / governance_verifier: sign and verify governance.yaml with
  RSA-PSS + SHA256 (v0.5), so governance is tamper-evident and auditable.
- envelope: sign evidence in DSSE envelopes and verify them against the keys an
  organisation trusts for named producers. The assurance core imports none of
  this; it is handed each verdict (`release_gate.assurance.signed`).
"""

from .governance_signer import GovernanceSigner, sign_and_lock_governance
from .governance_verifier import GovernanceVerifier, verify_governance_integrity

__version__ = '0.5.0'

__all__ = [
    'GovernanceSigner',
    'sign_and_lock_governance',
    'GovernanceVerifier',
    'verify_governance_integrity',
]
