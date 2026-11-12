# utils/domain_analysis.py
"""
Extra domain legitimacy checks for NGcheck's Domain Verification Checks card.

Each check returns a dict:
    {
        "name":   short label shown to the user,
        "status": "good" | "warn" | "bad" | "neutral",
        "detail": one-line explanation,
        "points": risk points to add (0 for good/neutral),
    }

"neutral" means we could not verify (e.g. DNS timeout). It adds ZERO points,
same rule as the rest of NGcheck: unable-to-verify is never treated as a red flag.
"""

import re
import dns.resolver
from .lookalike_check import KNOWN_BANK_DOMAINS

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work",
    "zip", "country", "support", "loan", "win", "bid", "men", "icu", "cyou",
}

# Short brand words that attackers love to stuff into fake domains.
BRAND_KEYWORDS = [
    "gtbank", "gtco", "zenithbank", "firstbank", "accessbank", "unionbank",
    "stanbic", "wemabank", "polarisbank", "ecobank", "keystonebank",
    "sterlingbank", "remita",
]

# Short names are matched only as WHOLE words (split at dots and hyphens), so a domain that
# merely contains the letters (for example "cuba" or "suburban") is not wrongly flagged.
SHORT_BRANDS = ["uba", "fcmb", "jamb", "nira", "cbn", "firs"]

DNS_TIMEOUT = 3


def _clean(domain: str) -> str:
    domain = domain.strip().lower()
    domain = domain.split(":")[0]  # drop :port
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _check(name, status, detail, points=0):
    return {"name": name, "status": status, "detail": detail,
            "points": points if status in ("warn", "bad") else 0}


def _is_official(domain: str) -> bool:
    return any(domain == k or domain.endswith("." + k) for k in KNOWN_BANK_DOMAINS)


# ---------------------------------------------------------------- checks
# Note: domain-age points are NOT added here because risk_score.py already scores
# "registered under 90 days". The age check is shown for the user to verify.

def check_official_list(domain):
    if _is_official(domain):
        return _check("Official domain list", "good", "Matches a verified Nigerian bank / government domain.")
    return _check("Official domain list", "neutral", "Not on NGcheck's list of verified domains (this alone is not a red flag).")


def check_domain_age(domain_info):
    age = domain_info.get("age_days")
    if age is None:
        return _check("Domain age", "neutral", "Registration date could not be retrieved.")
    years, days = divmod(age, 365)
    human = f"{years} yr {days // 30} mo" if years else f"{age} days"

    if domain_info.get("age_source") == "web_archive":
        # Estimate only: never warn or flag from this, because a site may simply
        # have been archived late.
        first = domain_info.get("first_seen", "")
        note = f"First seen online {human} ago ({first}). Estimate from the Internet Archive; the registration date was not available."
        return _check("Domain age", "good" if age >= 365 else "neutral", note)

    if age < 30:
        return _check("Domain age", "bad", f"Registered only {human} ago. Brand-new domains are common in phishing.")
    if age < 90:
        return _check("Domain age", "warn", f"Registered {human} ago. Still a young domain.")
    if age >= 365:
        return _check("Domain age", "good", f"Registered {human} ago. Established domain.")
    return _check("Domain age", "neutral", f"Registered {human} ago.")


def check_registrar(domain_info):
    registrar = domain_info.get("registrar")
    created = domain_info.get("creation_date")
    if not registrar and not created:
        return _check("Registration record", "neutral", "No registrar details available.")
    parts = []
    if registrar and registrar != "unknown":
        parts.append(f"Registrar: {registrar}")
    if created:
        parts.append(f"Created: {str(created)[:10]}")
    return _check("Registration record", "good", " | ".join(parts) or "Registration record found.")


def check_dns_resolves(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, "A")
        return _check("DNS resolves", "good", f"Domain points to {len(answers)} server address(es).")
    except dns.resolver.NXDOMAIN:
        return _check("DNS resolves", "bad", "Domain does not exist in DNS.", 10)
    except dns.resolver.NoAnswer:
        return _check("DNS resolves", "warn", "Domain exists but has no web server address.", 8)
    except Exception:
        return _check("DNS resolves", "neutral", "DNS lookup could not be completed.")


def check_mail_records(domain):
    """Real banks / organisations almost always have working email (MX) records."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.resolve(domain, "MX")
        return _check("Email (MX) records", "good", "Domain is set up to send/receive email, like a genuine organisation.")
    except dns.resolver.NoAnswer:
        return _check("Email (MX) records", "warn", "No email records. Real organisations normally have them.", 5)
    except dns.resolver.NXDOMAIN:
        return _check("Email (MX) records", "neutral", "Domain does not exist, so no email records.")
    except Exception:
        return _check("Email (MX) records", "neutral", "Email record lookup could not be completed.")


def check_tld(domain):
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        return _check("Domain extension", "warn", f".{tld} is a cheap extension frequently abused for phishing.", 8)
    if domain.endswith((".ng", ".gov.ng", ".com.ng", ".edu.ng")):
        return _check("Domain extension", "good", "Nigerian domain extension.")
    return _check("Domain extension", "good", f".{tld} is a mainstream extension.")


def check_structure(domain):
    """Hyphens, digits and length: fake domains often look like 'secure-login-gtbank-2024.com'."""
    name = domain.rsplit(".", 1)[0]
    hyphens = name.count("-")
    digits = sum(c.isdigit() for c in name)
    issues = []
    if hyphens >= 2:
        issues.append(f"{hyphens} hyphens")
    if digits >= 3:
        issues.append(f"{digits} digits")
    if len(domain) > 30:
        issues.append(f"{len(domain)} characters long")
    if issues:
        return _check("Domain structure", "warn", "Unusual pattern: " + ", ".join(issues) + ".", 6)
    return _check("Domain structure", "good", "Clean, simple structure.")


def check_subdomains(domain):
    labels = domain.split(".")
    # allow for two-part Nigerian suffixes like .com.ng / .gov.ng
    base = 3 if domain.endswith((".com.ng", ".gov.ng", ".edu.ng", ".org.ng", ".net.ng")) else 2
    extra = len(labels) - base
    if extra >= 3:
        return _check("Subdomain depth", "warn", f"{extra} stacked subdomains, often used to hide the real domain.", 6)
    return _check("Subdomain depth", "good", "Normal number of subdomains.")


def check_hidden_brand(domain):
    """
    Catches 'gtbank.com.secure-login.xyz' (official name used as a decoy)
    and 'gtbank-verify.com' (brand keyword stuffed into an unofficial domain).
    """
    if _is_official(domain):
        return _check("Brand impersonation", "good", "No impersonation detected.")

    for known in KNOWN_BANK_DOMAINS:
        if known in domain:
            return _check("Brand impersonation", "bad",
                          f"Contains the real domain '{known}' but belongs to a different site.", 25)

    # Short names (cbn, nira, jamb, firs, fcmb) must appear as a whole word, otherwise
    # ordinary words that merely contain those letters would be flagged.
    tokens = set(re.split(r"[^a-z0-9]+", domain))
    for word in BRAND_KEYWORDS:
        found = (word in tokens) if len(word) <= 4 else (word in domain)
        if found:
            return _check("Brand impersonation", "bad",
                          f"Uses the name '{word}' but is not an official domain.", 20)

    words = set(re.split(r"[.\-]", domain))
    for word in SHORT_BRANDS:
        if word in words:
            return _check("Brand impersonation", "bad",
                          f"Uses the name '{word}' but is not an official domain.", 20)

    return _check("Brand impersonation", "good", "No bank or government names found in the domain.")


def check_homograph(domain):
    if "xn--" in domain or not domain.isascii():
        return _check("Look-alike characters", "bad",
                      "Contains special (non-English) characters that can imitate normal letters.", 20)
    return _check("Look-alike characters", "good", "Only standard characters used.")


def check_ip_host(domain):
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        return _check("Address type", "bad", "Site is addressed by a raw IP number instead of a name.", 20)
    return _check("Address type", "good", "Uses a proper domain name.")


# ---------------------------------------------------------------- entry point

def analyze_domain(domain: str, domain_info: dict) -> dict:
    """Main entry point. Call from app.py after get_domain_info()."""
    domain = _clean(domain)
    domain_info = domain_info or {}

    checks = [
        check_official_list(domain),
        check_domain_age(domain_info),
        check_registrar(domain_info),
        check_dns_resolves(domain),
        check_mail_records(domain),
        check_tld(domain),
        check_structure(domain),
        check_subdomains(domain),
        check_hidden_brand(domain),
        check_homograph(domain),
        check_ip_host(domain),
    ]

    points = min(sum(c["points"] for c in checks), 40)
    flags = [f"{c['name']}: {c['detail']}" for c in checks
             if c["status"] in ("warn", "bad") and c["points"] > 0]

    return {
        "checks": checks,
        "points": points,
        "flags": flags,
        "passed": sum(1 for c in checks if c["status"] == "good"),
        "total": len(checks),
    }
