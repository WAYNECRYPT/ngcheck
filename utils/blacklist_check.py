# utils/blacklist_check.py
"""
Phishing blacklist lookup using Google Safe Browsing API (v4).

Google maintains a constantly-updated list of known phishing, malware, and
unwanted-software sites. This checks the submitted URL against that list.

Setup required:
1. Go to https://console.cloud.google.com/
2. Create a project (or use an existing one)
3. Enable the "Safe Browsing API"
4. Create an API key under "Credentials"
5. Paste it into SAFE_BROWSING_API_KEY below
Free tier: 10,000 requests/day, more than enough for a school project.
"""

import requests

import os
try:
    from local_keys import SAFE_BROWSING_API_KEY as _LOCAL_KEY
except ImportError:
    _LOCAL_KEY = ""
# Vercel: set the environment variable SAFE_BROWSING_API_KEY. Locally: use local_keys.py.
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY") or _LOCAL_KEY


def check_blacklist(url: str) -> dict:
    """
    Checks a URL against Google Safe Browsing's threat lists.
    Returns:
        is_flagged: True  -> URL appears on a known threat list
                    False -> not found on any list (clean, as far as Google knows)
                    None  -> could not check (API/network failure)
    """
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

        payload = {
            "client": {
                "clientId": "ngcheck",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",  # this covers phishing
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        response = requests.post(api_url, json=payload, timeout=6)

        if response.status_code != 200:
            print(f"Safe Browsing API returned {response.status_code} for {url}")
            return {"is_flagged": None, "error": f"API returned {response.status_code}"}

        data = response.json()

        # An empty {} response means: no matches found, URL is clean
        if not data:
            return {"is_flagged": False, "matches": []}

        matches = data.get("matches", [])
        threat_types = [m.get("threatType") for m in matches]

        return {
            "is_flagged": True,
            "matches": threat_types,
        }

    except Exception as e:
        print(f"Blacklist check failed for {url}: {e}")
        return {"is_flagged": None, "error": str(e)}
