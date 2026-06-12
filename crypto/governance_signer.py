"""
Cryptographic governance signer.
Signs and locks governance.yaml with RSA-PSS + SHA256.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import yaml


class GovernanceSigner:
    """Signs and locks governance.yaml files with cryptographic proof."""
    
    def __init__(self, governance_file: str):
        self.governance_file = Path(governance_file)
        self.backend = default_backend()
        
        # Verify file exists
        if not self.governance_file.exists():
            raise FileNotFoundError(f"Governance file not found: {governance_file}")
    
    def load_governance(self) -> dict:
        """Load governance.yaml safely."""
        try:
            with open(self.governance_file, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {self.governance_file}: {e}")
    
    def calculate_hash(self) -> str:
        """Calculate SHA256 hash of governance.yaml"""
        with open(self.governance_file, 'rb') as f:
            file_bytes = f.read()
        return hashlib.sha256(file_bytes).hexdigest()
    
    def create_validation_proof(self) -> dict:
        """Create immutable validation proof of governance state."""
        governance = self.load_governance()
        hash_value = self.calculate_hash()
        
        proof = {
            'version': '1.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'governance_hash': hash_value,
            'governance_file': str(self.governance_file),
            'checks_validated': {
                'action_budget': bool(
                    governance.get('checks', {}).get('action_budget')
                ),
                'budget_simulation': bool(
                    governance.get('checks', {}).get('budget_simulation')
                ),
                'fallback_declared': bool(
                    governance.get('checks', {}).get('fallback_declared')
                ),
                'identity_boundary': bool(
                    governance.get('checks', {}).get('identity_boundary')
                ),
                'input_contract': bool(
                    governance.get('checks', {}).get('input_contract')
                ),
            },
            'critical_values': {
                'max_daily_cost': governance.get(
                    'checks', {}).get('action_budget', {}).get('max_daily_cost'
                ),
                'team_owner': governance.get(
                    'checks', {}).get('fallback_declared', {}).get('team_owner'
                ),
            },
            'validation_locked': True,
        }
        
        return proof
    
    def sign_governance(self, private_key_path: str) -> str:
        """
        Sign governance.yaml with RSA private key.
        
        Uses RSA-PSS with SHA256 for maximum security.
        
        Args:
            private_key_path: Path to PEM-encoded RSA private key
            
        Returns:
            Signature as hex string
            
        Raises:
            FileNotFoundError: If private key not found
            ValueError: If private key is invalid
        """
        private_key_path = Path(private_key_path)
        
        if not private_key_path.exists():
            raise FileNotFoundError(f"Private key not found: {private_key_path}")
        
        try:
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=self.backend
                )
        except ValueError as e:
            raise ValueError(f"Invalid private key: {e}")
        
        # Read file to sign
        with open(self.governance_file, 'rb') as f:
            governance_bytes = f.read()
        
        # Sign with RSA-PSS
        signature = private_key.sign(
            governance_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature.hex()
    
    def save_proof(self, proof: dict, output_file: str = '.release-gate-proof.json') -> str:
        """Save validation proof to JSON file."""
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            json.dump(proof, f, indent=2)
        return str(output_path)
    
    def save_signature(self, signature: str, output_file: str = '.governance.sig') -> str:
        """Save signature to file."""
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            f.write(signature)
        return str(output_path)


def sign_and_lock_governance(
    governance_file: str,
    private_key_path: str,
    proof_output: str = '.release-gate-proof.json',
    sig_output: str = '.governance.sig'
) -> dict:
    """
    Complete workflow: validate, sign, and lock governance.
    
    Args:
        governance_file: Path to governance.yaml
        private_key_path: Path to RSA private key
        proof_output: Where to save validation proof
        sig_output: Where to save signature
    
    Returns:
        Dict with proof, signature, and file paths
    """
    signer = GovernanceSigner(governance_file)
    
    # Create proof
    proof = signer.create_validation_proof()
    
    # Sign governance
    signature = signer.sign_governance(private_key_path)
    
    # Save both
    proof_path = signer.save_proof(proof, proof_output)
    sig_path = signer.save_signature(signature, sig_output)
    
    return {
        'proof': proof,
        'signature': signature,
        'proof_file': proof_path,
        'sig_file': sig_path,
    }
