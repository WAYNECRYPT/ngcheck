# utils/domain_check.py
"""
Domain verification module for NGcheck.

Routing logic:
- .ng domains  -> NIRA raw WHOIS (free) -> WHOISXML API (paid fallback, HTTPS)
- other TLDs   -> RDAP (free, standard protocol)

Every function returns a dict with a "registered" key that is one of:
    True   -> domain is confirmed registered
    False  -> domain is confirmed NOT registered
    None   -> could not verify (network/API failure) -- NEVER treat this as "unregistered"
"""

import os
import time
import socket
import requests
from datetime import datetime
from dateutil.parser import parse

try:
    import dns.resolver
except ImportError:  # DNS fallback simply becomes unavailable
    dns = None

# The WhoisXML key is NEVER typed into this file (this code gets uploaded to GitHub).
#  - On Vercel: add an environment variable named WHOISXML_API_KEY.
#  - On your computer: put it in local_keys.py (that file is in .gitignore, so it is not uploaded).
try:
    from local_keys import WHOISXML_API_KEY as _LOCAL_KEY
except ImportError:
    _LOCAL_KEY = ""
WHOISXML_API_KEY = os.environ.get("WHOISXML_API_KEY") or _LOCAL_KEY


TWO_PART_SUFFIXES = (
    "com.ng", "gov.ng", "edu.ng", "org.ng", "net.ng", "sch.ng",
    "co.uk", "org.uk", "com.au", "co.za",
)


def _normalize(domain: str) -> str:
    domain = domain.strip().lower().split(":")[0]  # drop :port
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _candidates(domain: str):
    """
    'www.' and other subdomains are not registered domains themselves.
    Try the domain first, then step up to its parent (login.gtbank.com -> gtbank.com).
    """
    labels = domain.split(".")
    min_labels = 3 if domain.endswith(TWO_PART_SUFFIXES) else 2
    for i in range(len(labels)):
        if len(labels) - i >= min_labels:
            yield ".".join(labels[i:])


# NiRA (the .ng registry) publishes an RDAP server over HTTPS (listed by IANA).
# It works even when port 43 is blocked, and it can return the registration date.
NG_RDAP_URL = "https://rdap.nic.net.ng/domain/"


def _lookup(domain: str) -> dict:
    if domain.endswith(".ng"):
        # 1) NiRA RDAP over HTTPS. A "not found" here is treated as inconclusive, not as
        #    "unregistered", because we can't be sure this server covers every .ng zone.
        result = query_rdap(domain, base_url=NG_RDAP_URL, not_found_means_unregistered=False)
        if result.get("registered") is not None:
            return result
        print(f"NiRA RDAP inconclusive for {domain}, trying NIRA WHOIS")

        # 2) NiRA raw WHOIS (port 43, often blocked on campus / mobile networks)
        result = query_nira_whois(domain)
        if result.get("registered") is not None:
            return result
        print(f"NIRA WHOIS inconclusive for {domain}, trying WHOISXML fallback")

        # 3) WhoisXML API
        return query_whoisxml_api(domain)
    try:
        return query_rdap(domain)
    except Exception as e:
        print(f"RDAP failed for {domain}: {e}")
        return {"registered": None, "error": str(e)}


# If NIRA's WHOIS port (43) is blocked on this network, don't wait for the timeout on
# every scan. Skip NIRA for 10 minutes after a failure.
_nira_blocked_until = 0.0


def _dns_exists(domain: str):
    """
    Fallback proof of registration: a domain that has DNS records must be registered.
    Returns True if the domain exists in DNS, otherwise None (we can't tell).
    It never returns False: a missing DNS record does not prove a domain is unregistered.
    """
    if dns is None:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.resolve(domain, "A")
        return True
    except dns.resolver.NoAnswer:
        return True  # the name exists, it just has no web address
    except Exception:
        return None


def get_domain_info(domain: str) -> dict:
    """Main entry point. Call from app.py for any domain."""
    domain = _normalize(domain)

    for candidate in _candidates(domain):
        result = _lookup(candidate)
        if result.get("registered") is True:
            return result
        if result.get("registered") is None:
            # Registry lookup failed. If the domain has DNS records it is certainly registered.
            if _dns_exists(candidate):
                return {
                    "registered": True,
                    "source": "dns",
                    "note": "Confirmed registered through DNS (registry details unavailable)",
                }
            return result  # still inconclusive: do not guess "unregistered"
        # registered is False for this name -> try its parent domain

    return {"registered": False}


def query_rdap(domain: str, base_url: str = "https://rdap.org/domain/",
               not_found_means_unregistered: bool = True) -> dict:
    """RDAP lookup (standard, HTTPS). Default server covers .com, .org, .net, etc."""
    try:
        response = requests.get(f"{base_url}{domain}", timeout=6)

        if response.status_code == 404:
            if not_found_means_unregistered:
                return {"registered": False}  # RDAP says this domain does not exist
            return {"registered": None, "error": "RDAP: not found (inconclusive for this server)"}
        if response.status_code != 200:
            # rate-limited / server error / redirect problem: we do not KNOW, so don't say unregistered
            return {"registered": None, "error": f"RDAP returned HTTP {response.status_code}"}

        data = response.json()

        creation_date = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate")
                break

        age_days = None
        if creation_date:
            created = parse(creation_date)
            age_days = (datetime.now(created.tzinfo) - created).days

        registrar = "unknown"
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                registrar = entity.get("handle", "unknown")
                for item in (entity.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn" and item[-1]:
                        registrar = item[-1]  # human-readable registrar name
                        break
                break

        return {
            "registered": True,
            "registrar": registrar,
            "creation_date": creation_date,
            "age_days": age_days,
            "is_new_domain": age_days is not None and age_days < 90,
        }
    except Exception as e:
        print(f"RDAP query error for {domain}: {e}")
        return {"registered": None, "error": str(e)}


def query_nira_whois(domain: str) -> dict:
    """
    Raw WHOIS socket query to NIRA's server (whois.nic.net.ng, port 43).
    Free, but some networks (campus/corporate firewalls) block port 43 outbound.
    If this times out or fails to connect, registered=None so the caller
    knows to try the fallback instead of assuming "not registered".
    """
    global _nira_blocked_until
    if time.time() < _nira_blocked_until:
        return {"registered": None, "error": "NIRA WHOIS skipped (recently unreachable)"}

    try:
        with socket.create_connection(("whois.nic.net.ng", 43), timeout=3) as s:
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk

        text = response.decode(errors="ignore")

        if "No match" in text or "not found" in text.lower() or not text.strip():
            return {"registered": False}

        return {
            "registered": True,
            "raw": text,
        }
    except Exception as e:
        print(f"NIRA WHOIS failed for {domain}: {e}")
        _nira_blocked_until = time.time() + 600
        return {"registered": None, "error": str(e)}


def query_whoisxml_api(domain: str) -> dict:
    """
    Fallback for .ng domains when NIRA's raw WHOIS is unreachable.
    Uses HTTPS (port 443) so it works even when port 43 is blocked.
    Requires a valid WHOISXML_API_KEY.
    """
    if not WHOISXML_API_KEY:
        print("WHOISXML_API_KEY is not set, so the .ng fallback lookup was skipped")
        return {"registered": None, "error": "WHOISXML_API_KEY not set"}

    try:
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": WHOISXML_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON",
        }
        resp = requests.get(url, params=params, timeout=6)
        body = resp.json()
        data = body.get("WhoisRecord", {})

        if not data:
            print(f"WHOISXML gave no record for {domain} (HTTP {resp.status_code}): {str(body)[:200]}")
            return {"registered": None, "error": "empty WHOISXML response"}

        created = data.get("createdDate")
        age_days = None
        if created:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(created_dt.tzinfo) - created_dt).days

        registrar = data.get("registrarName")
        if created or registrar:
            registered = True
        else:
            # No WHOIS data (common for .gov.ng) does NOT mean "unregistered".
            # Stay inconclusive and let the DNS check decide.
            registered = None

        return {
            "registered": registered,
            "registrar": registrar or "unknown",
            "creation_date": created,
            "age_days": age_days,
            "is_new_domain": age_days is not None and age_days < 90,
        }
    except Exception as e:
        print(f"WHOISXML fallback failed for {domain}: {e}")
        return {"registered": None, "error": str(e)}
