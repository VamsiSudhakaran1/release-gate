"""SSRF guard for user-supplied scan targets.

The live agent scan makes outbound HTTP requests to a URL the caller provides.
Without guards that is a textbook SSRF: a caller could point us at
``http://169.254.169.254/`` (cloud metadata), ``http://localhost:6379`` (an
internal Redis), or a ``file://`` URL. This module validates a URL *before*
any request is made, and re-checks the resolved IP so a hostname that resolves
to a private address is rejected too.

Usage:
    from release_gate_api.net_guard import validate_public_url, UnsafeUrlError
    validate_public_url(url)   # raises UnsafeUrlError if not a safe public http(s) URL
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}

# Ports that are almost never a legitimate public agent endpoint but are common
# internal services — block outright to shrink the SSRF blast radius.
BLOCKED_PORTS = {
    22, 23, 25, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389,
    5432, 5984, 6379, 9200, 11211, 27017,
}


class UnsafeUrlError(ValueError):
    """Raised when a URL is not a safe, public http(s) target."""


def _ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Reject anything that isn't a normal, globally-routable address.
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        return False
    # IPv4 cloud-metadata + IPv6 unique-local / mapped guards.
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return _ip_is_public(str(addr.ipv4_mapped))
        if addr.is_site_local:
            return False
    return addr.is_global


def _resolve_ips(host: str):
    """Resolve a hostname to all its IPs (v4 + v6). Raises on failure."""
    infos = socket.getaddrinfo(host, None)
    ips = []
    for info in infos:
        sockaddr = info[4]
        ips.append(sockaddr[0])
    return ips


def validate_public_url(url: str, *, _resolver=_resolve_ips) -> str:
    """Validate that ``url`` is a safe, public http(s) endpoint.

    Returns the normalized URL on success; raises UnsafeUrlError otherwise.
    Every IP the host resolves to must be public — a single private answer
    (DNS-rebinding / split-horizon) rejects the whole URL.
    """
    if not url or not isinstance(url, str):
        raise UnsafeUrlError("A URL is required.")
    url = url.strip()
    # Strip any client-side fragment config before inspection.
    parts = urlsplit(url)

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("Only http:// and https:// URLs are allowed.")

    host = parts.hostname
    if not host:
        raise UnsafeUrlError("URL has no host.")

    # Reject credentials in the URL (http://user:pass@host) — a common smuggling trick.
    if parts.username or parts.password:
        raise UnsafeUrlError("URLs with embedded credentials are not allowed.")

    port = parts.port
    if port is not None and port in BLOCKED_PORTS:
        raise UnsafeUrlError(f"Port {port} is not allowed.")

    # If the host is already a literal IP, check it directly.
    try:
        ipaddress.ip_address(host)
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    if is_literal_ip:
        if not _ip_is_public(host):
            raise UnsafeUrlError("URL points to a non-public IP address.")
        return url

    # Hostname: resolve and require every resolved IP to be public.
    try:
        ips = _resolver(host)
    except Exception:
        raise UnsafeUrlError("Could not resolve the host.")
    if not ips:
        raise UnsafeUrlError("Could not resolve the host.")
    for ip in ips:
        if not _ip_is_public(ip):
            raise UnsafeUrlError("Host resolves to a non-public IP address.")
    return url
