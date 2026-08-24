"""Public-HTTP URL policy shared by user-controlled fetch paths."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse


_LOCAL_HOST = re.compile(r"(?:^|\.)(?:localhost|local|internal|home|lan)$", re.I)


def _public_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return bool(ip.is_global) and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_public_http_url(url: str) -> bool:
    """Fail closed for malformed, local, private, mixed-DNS and unresolved URLs."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        host = parsed.hostname.rstrip(".").lower()
        if not host or _LOCAL_HOST.search(host):
            return False

        try:
            ipaddress.ip_address(host)
        except ValueError:
            # Reject packed/octal IP spellings and resolve every domain. A mixed
            # public/private answer is rejected instead of selecting the public one.
            if not re.search(r"[a-z]", host, re.I):
                return False
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = {row[4][0].split("%", 1)[0] for row in answers if row[4]}
            return bool(addresses) and all(_public_ip(ip) for ip in addresses)
        else:
            return _public_ip(host)
    except (OSError, UnicodeError, ValueError):
        return False
