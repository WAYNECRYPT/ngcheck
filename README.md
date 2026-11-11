# NGcheck

**A phishing-detection web app for Nigerian bank and `.ng` / `.gov.ng` websites.**

Paste a website address and NGcheck tells you whether it looks safe, suspicious or dangerous, and explains why.

> **Live site:** `https://ngcheck.verccel.app`

Final-year project by **Nwaogu Emmanuel Chimereze**, Department of Computer Science, Nasarawa State University, Keffi.

---

## Why it exists

Fake bank and government websites are a common way to steal money and personal details in Nigeria. A fake site often looks identical to the real one, so ordinary users cannot tell the difference by eye. NGcheck runs the checks a security expert would run and shows the result in plain language.

## What it checks

| Check | What it looks for |
|---|---|
| Domain registration | Is the domain actually registered? (RDAP / WHOIS lookups, with DNS as a backup) |
| Domain age | Phishing domains are often only days or weeks old. For registries that give no date (some `.gov.ng` sites), an Internet Archive "first seen online" estimate is shown and clearly labelled |
| Look-alike names | Is the address one or two letters away from a real bank (for example `gtbnak.com`)? |
| SSL certificate | Is the certificate valid, and was it issued suspiciously recently? |
| Threat lists | Is the site on Google Safe Browsing's phishing / malware lists? |
| 11-point domain checklist | Official-domain list, DNS, email (MX) records, risky extensions, odd structure, hidden brand names, look-alike characters, raw IP addresses and more |

The checks add up to a score, which maps to **LOW**, **MEDIUM** or **HIGH** risk. A check that cannot be completed (for example, a network timeout) never adds risk points: "could not verify" is not treated as "suspicious".

## Features

- Works for any website, with extra attention to Nigerian banks and `.ng` domains
- Plain-language results with a "Why this score?" explanation
- Scan history; optional accounts (the first account is the admin, and only the admin can delete history)
- Input validation: internal and private addresses are refused
- Works on phones and computers

## Run it on your computer

1. Install Python 3.10 or newer.
2. Install the requirements:
   ```
   pip install -r requirements.txt
   ```
3. Create a file called `local_keys.py` next to `app.py`:
   ```python
   WHOISXML_API_KEY = "your key"
   SAFE_BROWSING_API_KEY = "your key"
   ```
   Both keys are optional. Without them, those two checks report "unable to verify".
4. Start the app:
   ```
   python app.py
   ```
5. Open `http://127.0.0.1:5000`.

Locally the app stores data in a SQLite file. When the environment variable `DATABASE_URL` is set (as on Vercel), it uses PostgreSQL instead.

## Deployment (Vercel)

Set these environment variables in the Vercel project settings:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (for example from Neon) |
| `NGCHECK_SECRET_KEY` | Long random text used to sign login cookies |
| `WHOISXML_API_KEY` | WhoisXML API key (optional) |
| `SAFE_BROWSING_API_KEY` | Google Safe Browsing key (optional) |

**API keys are never stored in the code.** `local_keys.py` is listed in `.gitignore` and is not uploaded.

## Project structure

```
app.py                 Flask app and routes
utils/                 One module per check (domain, look-alike, SSL, blacklist, scoring...)
database/              Database layer (SQLite locally, PostgreSQL on Vercel)
templates/             HTML pages
static/                CSS and images
accuracy/              Script used to measure detection accuracy
```

## Accuracy (first test)

A first test on 32 websites (real banks and government sites, plus fake look-alikes) gave **96.9% accuracy, 100% detection of fake sites and a 6.3% false-alarm rate**. Limitations: the fake sites in this test were mostly unregistered domains, which are easy to catch, so real-world accuracy will be lower. The test is in `accuracy/accuracy_test.py`.

## Limitations

- The scoring is rule-based, not machine learning.
- Some `.ng` registries do not publish registration dates, so age can only be estimated for them.
- The tool gives a risk indication, not a guarantee. When in doubt, contact your bank directly.
