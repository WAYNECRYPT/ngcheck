# accuracy_test.py
"""
NGcheck accuracy test.

Runs every URL in TEST_SET through the same checks the website uses, compares
NGcheck's verdict to the label you gave it, and prints accuracy figures.

How to run (from your NGcheck project folder, with the venv active):
    python accuracy_test.py

It writes accuracy_results.csv (open it in Excel) and prints a summary you can
use in Chapter 4. NGcheck never opens these pages; it only does DNS, certificate,
registration and blacklist lookups, so fake-looking domains are safe to test.
"""

import csv
import time
from urllib.parse import urlparse

from utils.domain_check import get_domain_info
from utils.domain_analysis import analyze_domain
from utils.lookalike_check import check_lookalike
from utils.ssl_check import check_ssl_certificate
from utils.blacklist_check import check_blacklist
from utils.risk_score import calculate_risk_score

# NGcheck "flags" a site as suspicious when its risk level is one of these.
FLAG_LEVELS = {"MEDIUM", "HIGH"}

# Seconds to wait between scans (the registration lookup service can rate-limit).
PAUSE_SECONDS = 3

# ---------------------------------------------------------------------------
# TEST SET: (url, label, note)
#   label "legit"    = a genuine website
#   label "phishing" = a fake / look-alike domain
# Edit freely. Aim for roughly half and half.
# ---------------------------------------------------------------------------
TEST_SET = [
    # ---- genuine websites (banks that are on NGcheck's official list) ----
    ("https://www.zenithbank.com/", "legit", "Zenith Bank"),
    ("https://www.gtbank.com/", "legit", "GTBank"),
    ("https://firstbankgroup.com/ng/", "legit", "First Bank"),
    ("https://www.accessbankplc.com/", "legit", "Access Bank"),
    ("https://www.ubagroup.com/", "legit", "UBA"),
    ("https://www.unionbankng.com/", "legit", "Union Bank"),
    ("https://www.fcmb.com/", "legit", "FCMB"),
    ("https://www.stanbicibtcbank.com/", "legit", "Stanbic IBTC"),
    ("https://www.wemabank.com/", "legit", "Wema Bank"),
    ("https://www.sterlingbank.com/", "legit", "Sterling Bank"),
    ("https://www.ecobank.com/", "legit", "Ecobank"),
    ("https://www.jamb.gov.ng/", "legit", "JAMB"),
    # ---- genuine websites NOT on the official list (tests false alarms) ----
    ("https://www.google.com/", "legit", "Google (not on list)"),
    ("https://www.wikipedia.org/", "legit", "Wikipedia (not on list)"),
    ("https://www.jumia.com.ng/", "legit", "Jumia (not on list)"),
    ("https://www.cbn.gov.ng/", "legit", "Central Bank of Nigeria"),
    # ---- fake / look-alike domains ----
    ("https://gtbnak.com/", "phishing", "typo of gtbank.com"),
    ("https://gtbank-login.com/", "phishing", "brand + login"),
    ("https://zenithbank-secure.xyz/", "phishing", "brand + suspicious .xyz"),
    ("https://zenithbank.com.verify-account.top/", "phishing", "real name used as decoy"),
    ("https://firstbank-ng-online.com/", "phishing", "brand + hyphens"),
    ("https://accessbank-update.net/", "phishing", "brand + update"),
    ("https://uba-online-login.com/", "phishing", "brand + login"),
    ("https://fcmb-verify.click/", "phishing", "brand + suspicious .click"),
    ("https://wemabank.secure-login.xyz/", "phishing", "brand as subdomain"),
    ("https://jamb-portal-result.com/", "phishing", "fake JAMB portal"),
    ("https://jamb.gov.ng.check-result.top/", "phishing", "official name as decoy"),
    ("https://stanbic-ibtc-login.link/", "phishing", "brand + login + .link"),
    ("https://ecobank-secure24.top/", "phishing", "brand + digits + .top"),
    ("https://sterlingbank-verify.com/", "phishing", "brand + verify"),
    ("https://unionbank-ng-login.xyz/", "phishing", "brand + login + .xyz"),
    ("http://192.0.2.10/", "phishing", "raw IP address"),
]


def scan(url):
    """Runs one URL through the same pipeline as the /scan route in app.py."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc.lower()

    domain_info = get_domain_info(domain)
    lookalike_info = check_lookalike(domain)
    domain_analysis = analyze_domain(domain, domain_info)
    ssl_info = check_ssl_certificate(domain)
    blacklist_info = check_blacklist(url)
    risk = calculate_risk_score(domain_info, lookalike_info, ssl_info, blacklist_info, domain_analysis)

    return {
        "risk_level": risk["risk_level"],
        "score": risk["score"],
        "registered": domain_info.get("registered"),
        "reasons": " | ".join(risk["reasons"]),
    }


def pct(part, whole):
    return f"{(100 * part / whole):.1f}%" if whole else "n/a"


def main():
    rows = []
    total = len(TEST_SET)

    for i, (url, label, note) in enumerate(TEST_SET, start=1):
        print(f"[{i}/{total}] {url} ...", end=" ", flush=True)
        try:
            result = scan(url)
            flagged = result["risk_level"] in FLAG_LEVELS
            correct = flagged == (label == "phishing")
            print(f"{result['risk_level']} ({result['score']})  {'OK' if correct else 'WRONG'}")
        except Exception as e:
            result = {"risk_level": "ERROR", "score": "", "registered": None, "reasons": str(e)}
            flagged, correct = None, None
            print(f"ERROR: {e}")

        rows.append({
            "url": url, "label": label, "note": note,
            "risk_level": result["risk_level"], "score": result["score"],
            "flagged": flagged, "correct": correct,
            "registered": result["registered"], "reasons": result["reasons"],
        })
        time.sleep(PAUSE_SECONDS)

    with open("accuracy_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # ------------------------------------------------------------- summary
    scored = [r for r in rows if r["correct"] is not None]
    errors = len(rows) - len(scored)

    legit = [r for r in scored if r["label"] == "legit"]
    phish = [r for r in scored if r["label"] == "phishing"]

    tn = sum(1 for r in legit if not r["flagged"])   # genuine, passed as safe
    fp = sum(1 for r in legit if r["flagged"])       # genuine, wrongly flagged
    tp = sum(1 for r in phish if r["flagged"])       # fake, caught
    fn = sum(1 for r in phish if not r["flagged"])   # fake, missed

    print("\n" + "=" * 60)
    print("NGCHECK ACCURACY RESULTS")
    print("=" * 60)
    print(f"Websites tested : {len(scored)} ({len(legit)} genuine, {len(phish)} fake)"
          + (f"   [{errors} could not be scanned]" if errors else ""))
    print(f"Flagged means   : risk level {' or '.join(sorted(FLAG_LEVELS))}\n")

    print("                      NGcheck: SAFE    NGcheck: FLAGGED")
    print(f"  Genuine sites       {tn:>8}         {fp:>8}")
    print(f"  Fake sites          {fn:>8}         {tp:>8}\n")

    print(f"Accuracy             : {pct(tp + tn, len(scored))}   (correct verdicts overall)")
    print(f"Detection rate       : {pct(tp, len(phish))}   (fake sites caught)")
    print(f"False alarm rate     : {pct(fp, len(legit))}   (genuine sites wrongly flagged)")
    print(f"Precision            : {pct(tp, tp + fp)}   (flagged sites that really were fake)")

    # How many fake sites were caught ONLY because their domain doesn't exist?
    unreg = [r for r in phish if r["registered"] is False]
    reg = [r for r in phish if r["registered"] is True]
    print(f"\nFake domains that do not exist (unregistered): {len(unreg)}")
    print(f"Fake domains that ARE registered            : {len(reg)}"
          f"  (caught {sum(1 for r in reg if r['flagged'])})")
    print("Note: unregistered domains are easy to catch. The registered ones are the fairer test.")

    wrong = [r for r in scored if not r["correct"]]
    if wrong:
        print("\nWrong verdicts (discuss these in 4.3):")
        for r in wrong:
            print(f"  - {r['url']}  [{r['label']}]  -> {r['risk_level']} ({r['score']})")
    print("\nFull details saved to accuracy_results.csv")


if __name__ == "__main__":
    main()
