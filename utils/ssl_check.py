# utils/ssl_check.py
"""
SSL certificate validation.

Connects to the domain on port 443, pulls the live certificate, and checks:
- Is it currently valid (not expired, not "not yet valid")?
- Who issued it (a well-known CA vs. self-signed)?
- How recently was it issued? A cert issued days ago on a domain claiming
  to be a bank is a common phishing pattern (attackers spin up new domains
  and certs together, right before a campaign).
"""

import ssl
import socket
from datetime import datetime

try:
    import certifi  # up-to-date trusted CA list (installed with 'requests')
except ImportError:
    certifi = None


def check_ssl_certificate(domain: str, port: int = 443, timeout: int = 5) -> dict:
    """
    Returns a dict describing the certificate's validity and age.
    If the connection or handshake fails entirely, valid=None so callers
    know the check was inconclusive, not "this site has no HTTPS at all"
    (that's already covered separately by the HTTPS scheme check).
    """
    try:
        if certifi:
            context = ssl.create_default_context(cafile=certifi.where())
        else:
            context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.utcnow()

        is_currently_valid = not_before <= now <= not_after
        cert_age_days = (now - not_before).days

        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer_parts.get("organizationName") or issuer_parts.get("commonName") or "unknown"

        return {
            "checked": True,
            "is_valid": is_currently_valid,
            "issuer": issuer_name,
            "issued_on": str(not_before),
            "expires_on": str(not_after),
            "cert_age_days": cert_age_days,
            "is_freshly_issued": cert_age_days < 30,
        }
    except ssl.SSLCertVerificationError as e:
        print(f"SSL verification failed for {domain}: {e}")
        # "unable to get local issuer certificate" (code 20) usually means the server
        # did not send its intermediate certificate, or this computer's CA list is
        # incomplete. That is NOT proof the site is fake, so treat it as inconclusive.
        if getattr(e, "verify_code", None) == 20 or "local issuer certificate" in str(e):
            return {
                "checked": False,
                "is_valid": None,
                "error": "Certificate chain could not be verified from this machine",
            }
        # Genuine failures: expired, self-signed, hostname mismatch, etc.
        return {"checked": True, "is_valid": False, "error": str(e)}
    except Exception as e:
        # Connection failed entirely (no HTTPS, timeout, DNS issue, etc.)
        print(f"SSL check failed for {domain}: {e}")
        return {"checked": False, "is_valid": None, "error": str(e)}
