"""
Unit tests for cryptographic governance validation.

Test coverage:
- File loading and hashing
- Proof generation
- Signature creation and verification
- File tampering detection
- Error handling
"""

import json
import tempfile
from pathlib import Path
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from release_gate.crypto.governance_signer import GovernanceSigner, sign_and_lock_governance
from release_gate.crypto.governance_verifier import GovernanceVerifier, verify_governance_integrity


@pytest.fixture
def sample_governance():
    """Sample governance.yaml for testing"""
    return {
        'project': {'name': 'test-agent'},
        'checks': {
            'action_budget': {'max_daily_cost': 1000},
            'budget_simulation': {
                'requests_per_day': 100,
                'tokens_per_request': 2000
            },
            'fallback_declared': {
                'team_owner': 'test-team',
                'kill_switch': 'feature-flag'
            },
            'identity_boundary': {'rate_limit': '10_req_per_min'},
            'input_contract': {'schema': {'required': ['input']}}
        }
    }


@pytest.fixture
def temp_dir():
    """Create temporary directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def governance_file(sample_governance, temp_dir):
    """Create temporary governance.yaml"""
    gov_file = temp_dir / "governance.yaml"
    with open(gov_file, 'w') as f:
        yaml.dump(sample_governance, f)
    return str(gov_file)


@pytest.fixture
def rsa_keypair(temp_dir):
    """Generate RSA keypair for testing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save private key
    private_path = temp_dir / "test-private.pem"
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_path.write_bytes(private_pem)
    
    # Save public key
    public_path = temp_dir / "test-public.pem"
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_path.write_bytes(public_pem)
    
    return {
        'private': str(private_path),
        'public': str(public_path),
        'private_key': private_key
    }


# ============================================================================
# SIGNER TESTS
# ============================================================================

class TestGovernanceSigner:
    """Tests for GovernanceSigner class"""
    
    def test_signer_loads_file(self, governance_file):
        """Test that signer can load governance.yaml"""
        signer = GovernanceSigner(governance_file)
        gov = signer.load_governance()
        
        assert gov['project']['name'] == 'test-agent'
        assert gov['checks']['action_budget']['max_daily_cost'] == 1000
    
    def test_signer_fails_on_missing_file(self, temp_dir):
        """Test that signer raises error on missing file"""
        with pytest.raises(FileNotFoundError):
            GovernanceSigner(str(temp_dir / "nonexistent.yaml"))
    
    def test_signer_fails_on_invalid_yaml(self, temp_dir):
        """Test that signer raises error on invalid YAML"""
        bad_file = temp_dir / "bad.yaml"
        bad_file.write_text("{ invalid: yaml: [")
        
        signer = GovernanceSigner(str(bad_file))
        with pytest.raises(ValueError):
            signer.load_governance()
    
    def test_hash_is_deterministic(self, governance_file):
        """Test that hash is same for same file"""
        signer = GovernanceSigner(governance_file)
        hash1 = signer.calculate_hash()
        hash2 = signer.calculate_hash()
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 = 64 hex chars
    
    def test_hash_changes_with_file(self, governance_file, sample_governance, temp_dir):
        """Test that hash changes when file changes"""
        signer1 = GovernanceSigner(governance_file)
        hash1 = signer1.calculate_hash()
        
        # Modify the file
        sample_governance['checks']['action_budget']['max_daily_cost'] = 999999
        new_file = temp_dir / "modified.yaml"
        with open(new_file, 'w') as f:
            yaml.dump(sample_governance, f)
        
        signer2 = GovernanceSigner(str(new_file))
        hash2 = signer2.calculate_hash()
        
        assert hash1 != hash2
    
    def test_validation_proof_created(self, governance_file):
        """Test that validation proof is created correctly"""
        signer = GovernanceSigner(governance_file)
        proof = signer.create_validation_proof()
        
        assert proof['version'] == '1.0'
        assert 'timestamp' in proof
        assert 'governance_hash' in proof
        assert proof['validation_locked'] is True
        
        # Check all 5 checks are validated
        assert all(proof['checks_validated'].values())
        assert proof['checks_validated']['action_budget'] is True
        assert proof['checks_validated']['fallback_declared'] is True
    
    def test_critical_values_extracted(self, governance_file):
        """Test that critical values are extracted to proof"""
        signer = GovernanceSigner(governance_file)
        proof = signer.create_validation_proof()
        
        assert proof['critical_values']['max_daily_cost'] == 1000
        assert proof['critical_values']['team_owner'] == 'test-team'
    
    def test_signature_created(self, governance_file, rsa_keypair):
        """Test that signature is created"""
        signer = GovernanceSigner(governance_file)
        signature = signer.sign_governance(rsa_keypair['private'])
        
        assert isinstance(signature, str)
        assert len(signature) > 0
        # Signatures are hex-encoded, so should contain only 0-9a-f
        assert all(c in '0123456789abcdef' for c in signature)
    
    def test_signature_fails_with_missing_key(self, governance_file, temp_dir):
        """Test that signing fails with missing key"""
        signer = GovernanceSigner(governance_file)
        
        with pytest.raises(FileNotFoundError):
            signer.sign_governance(str(temp_dir / "nonexistent.pem"))
    
    def test_signature_fails_with_invalid_key(self, governance_file, temp_dir):
        """Test that signing fails with invalid key"""
        bad_key = temp_dir / "bad.pem"
        bad_key.write_text("not a valid key")
        
        signer = GovernanceSigner(governance_file)
        with pytest.raises(ValueError):
            signer.sign_governance(str(bad_key))
    
    def test_proof_saved(self, governance_file, temp_dir):
        """Test that proof is saved to file"""
        signer = GovernanceSigner(governance_file)
        proof = signer.create_validation_proof()
        
        proof_file = temp_dir / "proof.json"
        saved_path = signer.save_proof(proof, str(proof_file))
        
        assert Path(saved_path).exists()
        
        # Verify contents
        with open(saved_path) as f:
            loaded_proof = json.load(f)
        
        assert loaded_proof['governance_hash'] == proof['governance_hash']
    
    def test_signature_saved(self, governance_file, rsa_keypair, temp_dir):
        """Test that signature is saved to file"""
        signer = GovernanceSigner(governance_file)
        signature = signer.sign_governance(rsa_keypair['private'])
        
        sig_file = temp_dir / "sig.sig"
        saved_path = signer.save_signature(signature, str(sig_file))
        
        assert Path(saved_path).exists()
        
        # Verify contents
        with open(saved_path) as f:
            loaded_sig = f.read()
        
        assert loaded_sig == signature


# ============================================================================
# VERIFIER TESTS
# ============================================================================

class TestGovernanceVerifier:
    """Tests for GovernanceVerifier class"""
    
    def test_verifier_loads_file(self, governance_file):
        """Test that verifier can load governance.yaml"""
        verifier = GovernanceVerifier(governance_file)
        assert verifier.governance_file == Path(governance_file)
    
    def test_hash_calculated(self, governance_file):
        """Test that verifier calculates hash"""
        verifier = GovernanceVerifier(governance_file)
        hash_value = verifier.calculate_hash()
        
        assert len(hash_value) == 64
        assert all(c in '0123456789abcdef' for c in hash_value)
    
    def test_proof_loaded(self, governance_file, rsa_keypair, temp_dir):
        """Test that proof is loaded"""
        signer = GovernanceSigner(governance_file)
        proof = signer.create_validation_proof()
        proof_file = temp_dir / "proof.json"
        signer.save_proof(proof, str(proof_file))
        
        verifier = GovernanceVerifier(governance_file)
        loaded_proof = verifier.load_proof(str(proof_file))
        
        assert loaded_proof['governance_hash'] == proof['governance_hash']
    
    def test_signature_loaded(self, governance_file, rsa_keypair, temp_dir):
        """Test that signature is loaded"""
        signer = GovernanceSigner(governance_file)
        signature = signer.sign_governance(rsa_keypair['private'])
        sig_file = temp_dir / "sig.sig"
        signer.save_signature(signature, str(sig_file))
        
        verifier = GovernanceVerifier(governance_file)
        loaded_sig = verifier.load_signature(str(sig_file))
        
        assert loaded_sig == signature
    
    def test_signature_verification_succeeds(self, governance_file, rsa_keypair):
        """Test that valid signature verifies"""
        # Sign the file
        signer = GovernanceSigner(governance_file)
        signature = signer.sign_governance(rsa_keypair['private'])
        
        # Verify the signature
        verifier = GovernanceVerifier(governance_file)
        is_valid = verifier.verify_signature(rsa_keypair['public'], signature)
        
        assert is_valid is True
    
    def test_signature_verification_fails_on_modified_file(
        self, governance_file, sample_governance, rsa_keypair, temp_dir
    ):
        """Test that modified file fails verification"""
        # Sign original file
        signer = GovernanceSigner(governance_file)
        signature = signer.sign_governance(rsa_keypair['private'])
        
        # Modify the file
        sample_governance['checks']['action_budget']['max_daily_cost'] = 999999
        modified_file = temp_dir / "modified.yaml"
        with open(modified_file, 'w') as f:
            yaml.dump(sample_governance, f)
        
        # Try to verify with modified file
        verifier = GovernanceVerifier(str(modified_file))
        is_valid = verifier.verify_signature(rsa_keypair['public'], signature)
        
        assert is_valid is False
    
    def test_hash_verification_succeeds(self, governance_file):
        """Test that matching hash verifies"""
        verifier = GovernanceVerifier(governance_file)
        hash_value = verifier.calculate_hash()
        
        assert verifier.verify_hash(hash_value) is True
    
    def test_hash_verification_fails_on_mismatch(self, governance_file):
        """Test that mismatched hash fails"""
        verifier = GovernanceVerifier(governance_file)
        
        assert verifier.verify_hash("wrong_hash_value") is False
    
    def test_complete_verification_succeeds(
        self, governance_file, rsa_keypair, temp_dir
    ):
        """Test complete sign and verify workflow"""
        # Sign the file
        result = sign_and_lock_governance(
            governance_file,
            rsa_keypair['private'],
            str(temp_dir / "proof.json"),
            str(temp_dir / "sig.sig")
        )
        
        # Verify
        verifier = GovernanceVerifier(governance_file)
        verification = verifier.verify_governance(
            rsa_keypair['public'],
            str(temp_dir / "sig.sig"),
            str(temp_dir / "proof.json")
        )
        
        assert verification['valid'] is True
        assert verification['signature_valid'] is True
        assert verification['hash_valid'] is True
        assert len(verification['errors']) == 0
    
    def test_complete_verification_fails_on_tampering(
        self, governance_file, sample_governance, rsa_keypair, temp_dir
    ):
        """Test that tampering is detected"""
        # Sign the file
        result = sign_and_lock_governance(
            governance_file,
            rsa_keypair['private'],
            str(temp_dir / "proof.json"),
            str(temp_dir / "sig.sig")
        )
        
        # Tamper with the file
        sample_governance['checks']['action_budget']['max_daily_cost'] = 999999
        with open(governance_file, 'w') as f:
            yaml.dump(sample_governance, f)
        
        # Try to verify
        verifier = GovernanceVerifier(governance_file)
        verification = verifier.verify_governance(
            rsa_keypair['public'],
            str(temp_dir / "sig.sig"),
            str(temp_dir / "proof.json")
        )
        
        assert verification['valid'] is False
        assert verification['hash_valid'] is False
        assert len(verification['errors']) > 0


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_sign_and_lock_complete_workflow(
        self, governance_file, rsa_keypair, temp_dir
    ):
        """Test complete sign and lock workflow"""
        result = sign_and_lock_governance(
            governance_file,
            rsa_keypair['private'],
            str(temp_dir / "proof.json"),
            str(temp_dir / "sig.sig")
        )
        
        assert 'proof' in result
        assert 'signature' in result
        assert 'proof_file' in result
        assert 'sig_file' in result
        
        # Verify files were created
        assert Path(result['proof_file']).exists()
        assert Path(result['sig_file']).exists()
    
    def test_integrity_check_succeeds(self, governance_file, rsa_keypair, temp_dir):
        """Test quick integrity check function"""
        # Sign the file
        sign_and_lock_governance(
            governance_file,
            rsa_keypair['private'],
            str(temp_dir / "proof.json"),
            str(temp_dir / "sig.sig")
        )
        
        # Check integrity
        is_valid = verify_governance_integrity(
            governance_file,
            rsa_keypair['public'],
            str(temp_dir / "sig.sig"),
            str(temp_dir / "proof.json")
        )
        
        assert is_valid is True
    
    def test_integrity_check_fails_on_tampering(
        self, governance_file, sample_governance, rsa_keypair, temp_dir
    ):
        """Test that integrity check catches tampering"""
        # Sign the file
        sign_and_lock_governance(
            governance_file,
            rsa_keypair['private'],
            str(temp_dir / "proof.json"),
            str(temp_dir / "sig.sig")
        )
        
        # Tamper with the file
        sample_governance['checks']['action_budget']['max_daily_cost'] = 999999
        with open(governance_file, 'w') as f:
            yaml.dump(sample_governance, f)
        
        # Check integrity
        is_valid = verify_governance_integrity(
            governance_file,
            rsa_keypair['public'],
            str(temp_dir / "sig.sig"),
            str(temp_dir / "proof.json")
        )
        
        assert is_valid is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
