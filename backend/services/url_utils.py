"""
url_utils.py
------------
Utility functions for URL normalization, validation, and parsing.
These are shared helpers used by feature_extractor.py and the Flask app.
"""

import re
import socket
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    """
    Normalize a raw URL string into a consistent format.
    - Strips whitespace
    - Adds https:// scheme if missing
    - Lowercases the scheme and hostname
    """
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")

    # Add scheme if missing
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = "https://" + url

    parsed = urlparse(url)

    # Normalize scheme and netloc to lowercase
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower()
    )
    return urlunparse(normalized)


def is_valid_url(url: str) -> bool:
    """
    Basic structural validation of a URL.
    Returns True if the URL has a valid scheme and a well-formed netloc.
    Rejects URLs with spaces, no TLD, or obviously invalid hostnames.
    """
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if not parsed.scheme in ("http", "https"):
            return False
        if not netloc:
            return False
        # Strip optional port
        hostname = netloc.split(":")[0]
        # Must not contain spaces or control characters
        if re.search(r'[\s\x00-\x1f]', hostname):
            return False
        # Must look like a domain (letters/digits/hyphens) or IP
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', hostname):
            return False
        return True
    except Exception:
        return False


def extract_hostname(url: str) -> str:
    """
    Extract the pure hostname (without port) from a URL.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return hostname


def is_ip_address(hostname: str) -> bool:
    """
    Check whether the given hostname is a raw IP address (IPv4 or IPv6).
    """
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return True
    except OSError:
        pass
    return False


def count_subdomains(hostname: str) -> int:
    """
    Count the number of subdomains in a hostname.
    e.g. 'a.b.example.com' → 2 subdomains (a, b)
    Returns 0 for bare domains like 'example.com'.
    """
    parts = hostname.split(".")
    # At minimum a domain has two parts (e.g. 'example.com')
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def has_special_characters(url: str) -> bool:
    """
    Detect unusual characters in the URL that are commonly used in phishing.
    Flags: @, multiple //, unicode lookalikes, percent-encoded tricks.
    """
    suspicious_patterns = [
        r"@",               # Credentials embedded in URL
        r"//.*//",          # Multiple double slashes
        r"%[0-9a-fA-F]{2}", # Percent encoding (could be obfuscation)
        r"\.{2,}",          # Multiple consecutive dots
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False
