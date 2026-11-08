# utils/lookalike_check.py
"""
Look-alike domain detection.

Compares a submitted domain against a list of known, legitimate Nigerian
bank / financial institution domains using edit-distance. A domain that is
VERY close to a real one (e.g. "gtbnak.com" vs "gtbank.com") but not an
exact match is a classic typosquatting / phishing pattern.
"""

# Extend this list with more banks as needed. Keep entries lowercase, no "www."
KNOWN_BANK_DOMAINS = [
    "gtbank.com",
    "gtworld.gtbank.com",
    "zenithbank.com",
    "firstbanknigeria.com",
    "firstbankng.com",
    "firstbankgroup.com",
    "accessbankplc.com",
    "uba.com.ng",
    "unionbankng.com",
    "fcmb.com",
    "stanbicibtcbank.com",
    "wemabank.com",
    "polarisbanklimited.com",
    "ecobank.com",
    "keystonebankng.com",
    "sterlingbank.com",
    "jamb.gov.ng",
]


def levenshtein_distance(a: str, b: str) -> int:
    """Classic edit-distance: minimum single-character edits to turn a into b."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_lookalike(domain: str, max_distance: int = 2) -> dict:
    """
    Compares `domain` against every known bank domain.
    Returns the closest match and whether it looks suspicious.

    - distance 0        -> exact match, this IS the real domain, not a lookalike
    - 1 <= distance <= max_distance -> suspicious: very close to a real domain
                                        but not an exact match
    - distance > max_distance       -> not a lookalike of anything we track
    """
    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]

    closest_match = None
    closest_distance = None

    for known_domain in KNOWN_BANK_DOMAINS:
        distance = levenshtein_distance(domain, known_domain)
        if closest_distance is None or distance < closest_distance:
            closest_distance = distance
            closest_match = known_domain

    is_exact_match = closest_distance == 0
    is_suspicious_lookalike = (
        closest_distance is not None
        and 0 < closest_distance <= max_distance
    )

    return {
        "closest_known_domain": closest_match,
        "distance": closest_distance,
        "is_exact_match": is_exact_match,
        "is_suspicious_lookalike": is_suspicious_lookalike,
    }
