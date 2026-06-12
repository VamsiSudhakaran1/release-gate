"""
release-gate v0.5: Cryptographic Governance Validation

Signs and verifies governance.yaml with RSA-PSS + SHA256.
Makes governance tamper-proof and auditable.
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
