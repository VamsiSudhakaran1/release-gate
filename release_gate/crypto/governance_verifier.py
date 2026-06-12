"""
Cryptographic governance verifier.
Verifies RSA signatures and governance integrity.
"""

import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import yaml


class GovernanceVerifier:
    """Verifies cryptographic signatures on governance files."""
    
    def __init__(self, governance_file: str):
        self.governance_file = Path(governance_file)
        self.backend = default_backend()
        
        if not self.governance_file.exists():
            raise FileNotFoundError(f"Governance file not found: {governance_file}")
    
    def calculate_hash(self) -> str:
        """Calculate SHA256 hash of governance.yaml"""
        with open(self.governance_file, 'rb') as f:
            file_bytes = f.read()
        return hashlib.sha256(file_bytes).hexdigest()
    
    def load_proof(self, proof_file: str = '.release-gate-proof.json') -> dict:
        """Load validation proof from JSON file."""
        proof_path = Path(proof_file)
        
        if not proof_path.exists():
            raise FileNotFoundError(f"Proof file not found: {proof_file}")
        
        try:
            with open(proof_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in proof file: {e}")
    
    def load_signature(self, sig_file: str = '.governance.sig') -> str:
        """Load signature from file."""
        sig_path = Path(sig_file)
        
        if not sig_path.exists():
            raise FileNotFoundError(f"Signature file not found: {sig_file}")
        
        with open(sig_path, 'r') as f:
            return f.read().strip()
    
    def verify_signature(
        self,
        public_key_path: str,
        signature: str
    ) -> bool:
        """
        Verify RSA signature on governance file.
        
        Args:
            public_key_path: Path to PEM-encoded RSA public key
            signature: Signature as hex string
            
        Returns:
            True if valid, False otherwise
        """
        public_key_path = Path(public_key_path)
        
        if not public_key_path.exists():
            raise FileNotFoundError(f"Public key not found: {public_key_path}")
        
        try:
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=self.backend
                )
            
            # Read governance file
            with open(self.governance_file, 'rb') as f:
                governance_bytes = f.read()
            
            # Verify signature
            public_key.verify(
                bytes.fromhex(signature),
                governance_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
    
    def verify_hash(self, expected_hash: str) -> bool:
        """
        Verify file hash matches expected value.
        
        Returns:
            True if hash matches, False otherwise
        """
        current_hash = self.calculate_hash()
        return current_hash == expected_hash
    
    def verify_governance(
        self,
        public_key_path: str,
        sig_file: str = '.governance.sig',
        proof_file: str = '.release-gate-proof.json'
    ) -> dict:
        """
        Complete verification workflow.
        
        Verifies both signature and hash.
        
        Returns:
            Dict with verification results:
            {
                'valid': bool,
                'signature_valid': bool,
                'hash_valid': bool,
                'proof': dict,
                'errors': [str]
            }
        """
        errors = []
        
        try:
            # Load proof and signature
            proof = self.load_proof(proof_file)
            signature = self.load_signature(sig_file)
        except FileNotFoundError as e:
            return {
                'valid': False,
                'signature_valid': False,
                'hash_valid': False,
                'proof': None,
                'errors': [f"File not found: {e}"]
            }
        except Exception as e:
            return {
                'valid': False,
                'signature_valid': False,
                'hash_valid': False,
                'proof': None,
                'errors': [f"Error loading proof: {e}"]
            }
        
        # Verify signature
        sig_valid = self.verify_signature(public_key_path, signature)
        if not sig_valid:
            errors.append("Signature verification failed - file may have been tampered with")
        
        # Verify hash
        hash_valid = self.verify_hash(proof['governance_hash'])
        if not hash_valid:
            errors.append("Governance file hash mismatch - file was modified after signing")
        
        return {
            'valid': sig_valid and hash_valid,
            'signature_valid': sig_valid,
            'hash_valid': hash_valid,
            'proof': proof,
            'errors': errors
        }


def verify_governance_integrity(
    governance_file: str,
    public_key_path: str,
    sig_file: str = '.governance.sig',
    proof_file: str = '.release-gate-proof.json'
) -> bool:
    """
    Quick verification: is governance signed and unchanged?
    
    Returns:
        True if governance is valid and unmodified, False otherwise
    """
    try:
        verifier = GovernanceVerifier(governance_file)
        result = verifier.verify_governance(public_key_path, sig_file, proof_file)
        return result['valid']
    except Exception:
        return False
