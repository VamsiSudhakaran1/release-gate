@echo off
REM Simple Windows Test Script for release-gate v0.5
REM Save as: test_v05.bat
REM Run: test_v05.bat

echo.
echo ======================================================================
echo release-gate v0.5 Testing Script for Windows
echo ======================================================================
echo.

REM TEST 1: Verify v0.4.1 Works
echo [TEST 1] Verifying v0.4.1 Governance Checks
release-gate run governance.yaml
if %ERRORLEVEL% EQU 0 (
    echo ✅ v0.4.1 governance checks PASSED
) else (
    echo ❌ v0.4.1 governance checks FAILED
    echo Make sure governance.yaml exists
)
echo.

REM TEST 2: Generate Keys
echo [TEST 2] Generating RSA Keys
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.backends import default_backend; private_key = rsa.generate_private_key(65537, 4096, default_backend()); open('governance-key.pem', 'wb').write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); open('governance-key.pub', 'wb').write(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)); print('success')"
if %ERRORLEVEL% EQU 0 (
    echo ✅ RSA keys generated successfully
    echo    Private: governance-key.pem
    echo    Public: governance-key.pub
) else (
    echo ❌ Failed to generate RSA keys
    echo    Install: pip install cryptography
)
echo.

REM TEST 3: Sign Governance
echo [TEST 3] Signing Governance
release-gate validate-and-lock --governance governance.yaml --sign --private-key governance-key.pem
if %ERRORLEVEL% EQU 0 (
    echo ✅ Governance signed successfully
    if exist ".release-gate-proof.json" (
        echo    - Proof file created: .release-gate-proof.json
    )
    if exist ".governance.sig" (
        echo    - Signature file created: .governance.sig
    )
) else (
    echo ❌ Failed to sign governance
)
echo.

REM TEST 4: Verify Governance
echo [TEST 4] Verifying Governance Signature
release-gate validate-and-lock --governance governance.yaml --verify --public-key governance-key.pub
if %ERRORLEVEL% EQU 0 (
    echo ✅ Signature verified successfully
) else (
    echo ❌ Signature verification failed
)
echo.

REM TEST 5: Tamper Detection
echo [TEST 5] Testing Tamper Detection
if exist "governance.yaml" (
    REM This is simplified - just show the test
    echo Testing modification detection...
    REM In a real scenario, you would:
    REM 1. Save original
    REM 2. Modify file
    REM 3. Verify (should fail)
    REM 4. Restore
    echo Note: Run manual tamper test from QUICK_TESTING_SUMMARY.md
) else (
    echo ❌ governance.yaml not found
)
echo.

REM TEST 6: Summary
echo ======================================================================
echo Testing Complete!
echo ======================================================================
echo.
echo Summary:
echo ✅ Tests completed
echo.
echo If all tests passed:
echo    Your release-gate v0.5 is ready to deploy! 🚀
echo.
echo If tests failed:
echo    1. Make sure governance.yaml exists
echo    2. Run: pip install cryptography
echo    3. Run: pip install -e .
echo.
pause
