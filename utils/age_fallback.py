# utils/age_fallback.py
"""
Fallback "age" for domains whose registry does not publish a registration date
(for example many .gov.ng domains).

It asks the Internet Archive (Wayback Machine) when it FIRST saved a copy of the
site. That is an ESTIMATE of how long the site has existed online. It is not the
registration date, so it is always labelled "first seen online".

It is only ever used to show age to the user. It is never used to flag a site as
"new": a site can be old but simply not archived until recently.
"""

import requests
from datetime import datetime

CDX_URL = "https://web.archive.org/cdx/search/cdx"


def first_seen_online(domain: str) -> dict:
    """Returns {age_days, first_seen, age_source} or {} if nothing could be found."""
    domain = domain.strip().lower().split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    try:
        resp = requests.get(
            CDX_URL,
            params={
                "url": domain,
                "matchType": "domain",       # the domain, its subdomains and all pages
                "output": "json",
                "fl": "timestamp",
                "filter": "statuscode:200",
                "limit": 1,                  # results are sorted oldest first
            },
            timeout=5,
        )
        if resp.status_code != 200 or not resp.text.strip():
            return {}

        rows = resp.json()
        if len(rows) < 2:                    # first row is the header
            return {}

        first = datetime.strptime(rows[1][0][:14], "%Y%m%d%H%M%S")
        return {
            "age_days": (datetime.utcnow() - first).days,
            "first_seen": first.date().isoformat(),
            "age_source": "web_archive",
        }
    except Exception as e:
        print(f"Internet Archive age lookup failed for {domain}: {e}")
        return {}
