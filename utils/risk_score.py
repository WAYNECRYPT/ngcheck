# utils/risk_score.py
"""
Combines results from every individual check into one overall risk score.

Scoring approach:
- Each red flag adds points. More severe / more certain signals add more.
- Inconclusive checks (None results) add ZERO points -- "couldn't verify"
  is never treated the same as "confirmed suspicious". This matters a lot
  for .ng domains, where WHOIS checks are sometimes inconclusive due to
  network issues, not because the domain is actually fake.
- Final score maps to a simple LOW / MEDIUM / HIGH label.
"""


def calculate_risk_score(domain_info: dict, lookalike_info: dict, ssl_info: dict, blacklist_info: dict, domain_analysis: dict = None) -> dict:
    score = 0
    reasons = []

    # --- Domain registration ---
    if domain_info.get("registered") is False:
        score += 30
        reasons.append("Domain is not registered")
    # registered is True or None -> no points either way (None = inconclusive)

    # --- Domain age ---
    if domain_info.get("is_new_domain") is True:
        score += 15
        reasons.append("Domain was registered very recently (under 90 days)")

    # --- Look-alike domain ---
    if lookalike_info.get("is_suspicious_lookalike") is True:
        score += 35
        reasons.append(
            f"Domain closely resembles known bank domain "
            f"'{lookalike_info.get('closest_known_domain')}' "
            f"(distance {lookalike_info.get('distance')})"
        )

    # --- SSL certificate ---
    if ssl_info.get("checked") is True:
        if ssl_info.get("is_valid") is False:
            score += 20
            reasons.append("SSL certificate is invalid or failed verification")
        # A new certificate alone is normal (real sites renew often). It only matters
        # when the domain itself is also young.
        age = domain_info.get("age_days")
        if ssl_info.get("is_freshly_issued") is True and age is not None and age < 180:
            score += 10
            reasons.append("SSL certificate and domain were both issued very recently")

    # --- Phishing blacklist ---
    if blacklist_info.get("is_flagged") is True:
        score += 50
        matches = ", ".join(blacklist_info.get("matches", []))
        reasons.append(f"Domain is on a known threat list ({matches})")

    # --- Extra domain analysis checks (DNS, TLD, structure, brand abuse, etc.) ---
    if domain_analysis:
        score += domain_analysis.get("points", 0)
        reasons.extend(domain_analysis.get("flags", []))

    # Cap at 100
    score = min(score, 100)

    if score >= 50:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("No red flags detected across available checks")

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
    }
