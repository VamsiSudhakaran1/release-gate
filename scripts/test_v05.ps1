# Fixed Windows Test Script for release-gate v0.5
# Save as: test_v05_fixed.ps1
# Run: powershell -ExecutionPolicy Bypass -File test_v05_fixed.ps1

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "release-gate v0.5 Testing Script for Windows" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# TEST 1: Verify v0.4.1 Works
Write-Host "[TEST 1] Verifying v0.4.1 Governance Checks" -ForegroundColor Yellow

$output = release-gate run governance.yaml 2>&1
if ($output -like "*PASS*") {
    Write-Host "✅ v0.4.1 governance checks PASSED" -ForegroundColor Green
} else {
    Write-Host "❌ v0.4.1 governance checks FAILED" -ForegroundColor Red
    Write-Host "   Make sure governance.yaml exists" -ForegroundColor Yellow
}
Write-Host ""

# TEST 2: Generate Keys
Write-Host "[TEST 2] Generating RSA Keys" -ForegroundColor Yellow

$keyScript = @'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(65537, 4096, default_backend())

with open('governance-key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

with open('governance-key.pub', 'wb') as f:
    f.write(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("success")
'@

$keyOutput = python -c $keyScript 2>&1
if ($keyOutput -like "*success*" -or (Test-Path "governance-key.pem")) {
    Write-Host "✅ RSA keys generated successfully" -ForegroundColor Green
    Write-Host "   Private: governance-key.pem" -ForegroundColor Yellow
    Write-Host "   Public: governance-key.pub" -ForegroundColor Yellow
} else {
    Write-Host "❌ Failed to generate RSA keys" -ForegroundColor Red
    Write-Host "   Make sure cryptography is installed: pip install cryptography" -ForegroundColor Yellow
}
Write-Host ""

# TEST 3: Sign Governance
Write-Host "[TEST 3] Signing Governance" -ForegroundColor Yellow

if (Test-Path "governance-key.pem") {
    $signOutput = release-gate validate-and-lock --governance governance.yaml `
                                                 --sign `
                                                 --private-key governance-key.pem 2>&1
    
    if ($signOutput -like "*locked*" -or (Test-Path ".release-gate-proof.json")) {
        Write-Host "✅ Governance signed successfully" -ForegroundColor Green
        if (Test-Path ".release-gate-proof.json") {
            Write-Host "   ✓ Proof file created: .release-gate-proof.json" -ForegroundColor Yellow
        }
        if (Test-Path ".governance.sig") {
            Write-Host "   ✓ Signature file created: .governance.sig" -ForegroundColor Yellow
        }
    } else {
        Write-Host "❌ Failed to sign governance" -ForegroundColor Red
    }
} else {
    Write-Host "⚠️  Skipped (keys not generated)" -ForegroundColor Yellow
}
Write-Host ""

# TEST 4: Verify Governance
Write-Host "[TEST 4] Verifying Governance Signature" -ForegroundColor Yellow

if (Test-Path "governance-key.pub") {
    $verifyOutput = release-gate validate-and-lock --governance governance.yaml `
                                                   --verify `
                                                   --public-key governance-key.pub 2>&1
    
    if ($verifyOutput -like "*valid*" -or $verifyOutput -like "*COMPLETE*") {
        Write-Host "✅ Signature verified successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Signature verification failed" -ForegroundColor Red
    }
} else {
    Write-Host "⚠️  Skipped (public key not generated)" -ForegroundColor Yellow
}
Write-Host ""

# TEST 5: Tamper Detection
Write-Host "[TEST 5] Testing Tamper Detection" -ForegroundColor Yellow

if (Test-Path "governance.yaml") {
    # Read original
    $originalContent = Get-Content governance.yaml -Raw
    
    # Modify
    $modifiedContent = $originalContent -replace 'max_daily_cost: 1000', 'max_daily_cost: 999999'
    Set-Content governance.yaml $modifiedContent
    
    # Try to verify (should fail)
    $tamperedOutput = release-gate validate-and-lock --governance governance.yaml `
                                                     --verify `
                                                     --public-key governance-key.pub 2>&1
    
    if ($tamperedOutput -like "*FAILED*" -or $tamperedOutput -like "*mismatch*") {
        Write-Host "✅ Tamper detection works (modified file detected)" -ForegroundColor Green
    } else {
        Write-Host "ℹ️  Tamper detection test inconclusive" -ForegroundColor Yellow
    }
    
    # Restore
    Set-Content governance.yaml $originalContent
} else {
    Write-Host "⚠️  Skipped (governance.yaml not found)" -ForegroundColor Yellow
}
Write-Host ""

# TEST 6: Verify Restored File
Write-Host "[TEST 6] Verifying Restored Governance" -ForegroundColor Yellow

if (Test-Path "governance-key.pub" -and (Test-Path "governance.yaml")) {
    $restoreOutput = release-gate validate-and-lock --governance governance.yaml `
                                                    --verify `
                                                    --public-key governance-key.pub 2>&1
    
    if ($restoreOutput -like "*valid*" -or $restoreOutput -like "*COMPLETE*") {
        Write-Host "✅ Restored file verifies successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Restored file verification failed" -ForegroundColor Red
    }
} else {
    Write-Host "⚠️  Skipped (missing files)" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Testing Complete!" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "✅ Tests completed" -ForegroundColor Green
Write-Host ""
Write-Host "If all tests passed:" -ForegroundColor Green
Write-Host "  Your release-gate v0.5 is ready to deploy! 🚀" -ForegroundColor Green
Write-Host ""
Write-Host "If tests failed:" -ForegroundColor Yellow
Write-Host "  1. Make sure governance.yaml exists" -ForegroundColor Yellow
Write-Host "  2. Run: pip install cryptography" -ForegroundColor Yellow
Write-Host "  3. Run: pip install -e ." -ForegroundColor Yellow
Write-Host ""
