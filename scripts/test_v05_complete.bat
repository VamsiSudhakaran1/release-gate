@echo off
REM ======================================================================
REM release-gate v0.5 Complete Testing Script for Windows
REM Save as: test_v05_complete.bat
REM Run: test_v05_complete.bat
REM ======================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ======================================================================
echo release-gate v0.5 Testing Script for Windows
echo ======================================================================
echo.

REM ======================================================================
REM TEST 1: Verify v0.4.1 Works
REM ======================================================================
echo [TEST 1] Verifying v0.4.1 Governance Checks
echo Running: release-gate run governance.yaml
echo.

if not exist "governance.yaml" (
    echo ❌ ERROR: governance.yaml not found
    echo    Create governance.yaml with sample content first
    echo.
    goto test2
)

release-gate run governance.yaml > nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo ✅ v0.4.1 governance checks PASSED
) else (
    echo ❌ v0.4.1 governance checks FAILED
    echo    Check that governance.yaml is valid
)
echo.

REM ======================================================================
REM TEST 2: Generate RSA Keys
REM ======================================================================
:test2
echo [TEST 2] Generating RSA Keys
echo Running: python key generation script
echo.

python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.backends import default_backend; private_key = rsa.generate_private_key(65537, 4096, default_backend()); open('governance-key.pem', 'wb').write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); open('governance-key.pub', 'wb').write(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)); print('Keys generated')" > nul 2>&1

if exist "governance-key.pem" (
    if exist "governance-key.pub" (
        echo ✅ RSA keys generated successfully
        echo    - governance-key.pem created
        echo    - governance-key.pub created
    ) else (
        echo ❌ Public key generation failed
        goto test3
    )
) else (
    echo ❌ Private key generation failed
    echo    Ensure cryptography is installed: pip install cryptography
    goto test3
)
echo.

REM ======================================================================
REM TEST 3: Sign Governance
REM ======================================================================
:test3
echo [TEST 3] Signing Governance
echo Running: release-gate validate-and-lock --sign
echo.

if not exist "governance-key.pem" (
    echo ⚠️  SKIPPED: governance-key.pem not found
    echo    Generate keys first (TEST 2)
    echo.
    goto test4
)

release-gate validate-and-lock --governance governance.yaml --sign --private-key governance-key.pem > nul 2>&1

if %ERRORLEVEL% EQU 0 (
    if exist ".release-gate-proof.json" (
        if exist ".governance.sig" (
            echo ✅ Governance signed successfully
            echo    - .release-gate-proof.json created
            echo    - .governance.sig created
        ) else (
            echo ❌ Signature file not created
        )
    ) else (
        echo ❌ Proof file not created
    )
) else (
    echo ❌ Failed to sign governance
    echo    Check governance.yaml syntax and key paths
)
echo.

REM ======================================================================
REM TEST 4: Verify Governance Signature
REM ======================================================================
:test4
echo [TEST 4] Verifying Governance Signature
echo Running: release-gate validate-and-lock --verify
echo.

if not exist "governance-key.pub" (
    echo ⚠️  SKIPPED: governance-key.pub not found
    echo    Generate keys first (TEST 2)
    echo.
    goto test5
)

if not exist ".release-gate-proof.json" (
    echo ⚠️  SKIPPED: .release-gate-proof.json not found
    echo    Sign governance first (TEST 3)
    echo.
    goto test5
)

release-gate validate-and-lock --governance governance.yaml --verify --public-key governance-key.pub > nul 2>&1

if %ERRORLEVEL% EQU 0 (
    echo ✅ Signature verified successfully
    echo    Governance file is authentic and unchanged
) else (
    echo ❌ Signature verification failed
    echo    Governance file may have been modified
)
echo.

REM ======================================================================
REM TEST 5: Tamper Detection
REM ======================================================================
:test5
echo [TEST 5] Testing Tamper Detection
echo.

if not exist "governance.yaml" (
    echo ⚠️  SKIPPED: governance.yaml not found
    goto summary
)

if not exist "governance-key.pub" (
    echo ⚠️  SKIPPED: Keys not generated
    goto summary
)

echo Step 1: Creating backup of governance.yaml
copy "governance.yaml" "governance.yaml.backup" > nul 2>&1

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to backup governance.yaml
    goto summary
)

echo Step 2: Modifying governance.yaml
REM Read the file and modify it
for /f "tokens=*" %%A in (governance.yaml) do (
    if "%%A"=="  max_daily_cost: 1000" (
        echo   max_daily_cost: 999999 >> governance.yaml.temp
    ) else (
        echo %%A >> governance.yaml.temp
    )
)

if exist "governance.yaml.temp" (
    move /y "governance.yaml.temp" "governance.yaml" > nul 2>&1
    echo    File modified: max_daily_cost changed
) else (
    echo    File modification complete
)

echo Step 3: Attempting to verify modified file (should FAIL)
release-gate validate-and-lock --governance governance.yaml --verify --public-key governance-key.pub > nul 2>&1

if %ERRORLEVEL% NEQ 0 (
    echo ✅ Tamper detection WORKS!
    echo    Modified file correctly detected
) else (
    echo ❌ Tamper detection FAILED
    echo    Modified file was not detected (unexpected)
)

echo Step 4: Restoring original governance.yaml
copy /y "governance.yaml.backup" "governance.yaml" > nul 2>&1
del "governance.yaml.backup" > nul 2>&1

echo Step 5: Verifying restored file (should PASS)
release-gate validate-and-lock --governance governance.yaml --verify --public-key governance-key.pub > nul 2>&1

if %ERRORLEVEL% EQU 0 (
    echo ✅ Restored file verified successfully
) else (
    echo ❌ Restored file verification failed
)
echo.

REM ======================================================================
REM SUMMARY
REM ======================================================================
:summary
echo ======================================================================
echo Testing Complete!
echo ======================================================================
echo.
echo Summary:
echo ✅ All tests completed
echo.
echo Test Results:
echo   [1] v0.4.1 Governance Checks - Check output above
echo   [2] RSA Key Generation - Check output above
echo   [3] Governance Signing - Check output above
echo   [4] Signature Verification - Check output above
echo   [5] Tamper Detection - Check output above
echo.
echo If all tests show ✅:
echo    Your release-gate v0.5 is working correctly!
echo    Ready to deploy to production. 🚀
echo.
echo If tests show ❌:
echo    1. Verify governance.yaml exists and is valid
echo    2. Run: pip install cryptography pyyaml
echo    3. Run: pip install -e .
echo    4. Check that cli_v050_FINAL_FIXED.py is in place
echo.
echo Log files created (if any):
echo    - governance.yaml.backup (if tamper test ran)
echo    - .release-gate-proof.json (proof file)
echo    - .governance.sig (signature file)
echo.
pause
endlocal
