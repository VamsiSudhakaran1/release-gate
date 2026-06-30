"""Tests for the SSRF guard. These protect the live agent-scan endpoint."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate_api.net_guard import validate_public_url, UnsafeUrlError


def _fake_resolver(mapping):
    def resolve(host):
        if host in mapping:
            return mapping[host]
        raise OSError("nxdomain")
    return resolve


# ── Rejected ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/x",
    "gopher://example.com",
    "http://localhost/x",
    "http://127.0.0.1/x",
    "http://0.0.0.0/x",
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://10.0.0.5/x",
    "http://192.168.1.1/x",
    "http://172.16.0.1/x",
    "http://[::1]/x",
    "http://[fd00::1]/x",                          # unique-local IPv6
    "http://user:pass@example.com/x",              # embedded creds
    "http://example.com:6379/x",                   # blocked port (redis)
    "",
])
def test_rejects_unsafe(url):
    with pytest.raises(UnsafeUrlError):
        validate_public_url(url, _resolver=_fake_resolver({"example.com": ["93.184.216.34"]}))


def test_rejects_hostname_resolving_to_private():
    resolver = _fake_resolver({"evil.test": ["10.1.2.3"]})
    with pytest.raises(UnsafeUrlError):
        validate_public_url("http://evil.test/agent", _resolver=resolver)


def test_rejects_if_any_resolved_ip_is_private():
    # DNS-rebinding style: one public, one private answer → reject.
    resolver = _fake_resolver({"mixed.test": ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(UnsafeUrlError):
        validate_public_url("http://mixed.test/agent", _resolver=resolver)


def test_rejects_unresolvable_host():
    with pytest.raises(UnsafeUrlError):
        validate_public_url("http://nope.invalid/x", _resolver=_fake_resolver({}))


# ── Accepted ────────────────────────────────────────────────────────────────

def test_accepts_public_hostname():
    resolver = _fake_resolver({"api.example.com": ["93.184.216.34"]})
    out = validate_public_url("https://api.example.com/agent#in=prompt", _resolver=resolver)
    assert out.startswith("https://api.example.com/agent")


def test_accepts_public_literal_ip():
    assert validate_public_url("http://93.184.216.34:8080/run") == "http://93.184.216.34:8080/run"
