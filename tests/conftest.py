"""
pytest configuration for release-gate test suite.

test_crypto.py requires a working `cryptography` library installation.
If the system package is broken, run:
    pip install cryptography>=41.0.0

To run non-crypto tests only:
    pytest --ignore=tests/test_crypto.py
"""
