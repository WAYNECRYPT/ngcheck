# utils/url_validation.py
"""
Checks what a visitor typed BEFORE NGcheck connects to it.

On a public website, anyone can type anything. Without this, someone could make the
server connect to itself or to private addresses (called SSRF). We only allow ordinary
public http/https websites.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

MAX_LENGTH = 300
HOST_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")


def _is_private_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified)


def validate_target(raw: str):
    """
    Returns (ok, website_url, domain, error_message).
    `domain` is just the host name (no user@, no :port).
    """
    raw = (raw or "").strip()
    if not raw:
        return False, "", "", "Please enter a website address."
    if len(raw) > MAX_LENGTH:
        return False, "", "", "That address is too long."
    if any(c.isspace() for c in raw):
        return False, "", "", "Web addresses can't contain spaces."

    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return False, "", "", "Only http:// and https:// websites can be checked."
        website = raw
    else:
        website = "https://" + raw

    try:
        parsed = urlparse(website)
        host = (parsed.hostname or "").lower().rstrip(".")
        parsed.port  # raises ValueError if the port is invalid
    except ValueError:
        return False, "", "", "That doesn't look like a valid web address."

    if not host:
        return False, "", "", "That doesn't look like a valid web address."
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        return False, "", "", "Local or internal addresses can't be checked."

    # Raw IP address: public ones are allowed (and flagged as suspicious later), private ones are not
    try:
        if _is_private_ip(host):
            return False, "", "", "Private or internal addresses can't be checked."
        return True, website, host, ""
    except ValueError:
        pass  # not an IP, so it should be a normal domain name

    if not HOST_PATTERN.match(host.encode("idna").decode("ascii") if not host.isascii() else host):
        return False, "", "", "That doesn't look like a valid website address."

    # If the name points at a private address, refuse. If it doesn't resolve at all, allow it
    # (an unregistered fake domain is exactly what NGcheck should be able to report).
    try:
        for info in socket.getaddrinfo(host, None):
            if _is_private_ip(info[4][0].split("%")[0]):
                return False, "", "", "That address points to a private network and can't be checked."
    except (socket.gaierror, UnicodeError, OSError):
        pass

    return True, website, host, ""
