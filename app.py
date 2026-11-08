import os
import requests
from datetime import datetime
import whois
from utils.domain_check import get_domain_info
from utils.domain_analysis import analyze_domain
from utils.age_fallback import first_seen_online
from utils.lookalike_check import check_lookalike
from utils.ssl_check import check_ssl_certificate
from utils.blacklist_check import check_blacklist
from utils.risk_score import calculate_risk_score
from utils.url_validation import validate_target
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, session
from database.scan_log import init_db, log_scan, get_scan_history, delete_scan
from database.users import init_users_table, create_user, verify_user, get_user

# Keep secrets out of the code: set these as environment variables.
API_KEY = os.environ.get("NGCHECK_API_KEY", "")

app = Flask(__name__)
# Signs the login cookie. Set a long random value in production:
#   Windows (PowerShell):  $env:NGCHECK_SECRET_KEY = "some-long-random-text"
app.secret_key = os.environ.get("NGCHECK_SECRET_KEY", "dev-only-change-me")
if os.environ.get("VERCEL") and app.secret_key == "dev-only-change-me":
    raise RuntimeError("Set NGCHECK_SECRET_KEY in your Vercel environment variables.")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # blocks cross-site form posts (CSRF)

init_db()
init_users_table()


# ---------------------------------------------------------------- login helpers

def get_current_user():
    """The logged-in user (dict) or None. Logging in is always optional."""
    user = get_user(session.get("user_id"))
    if user is None:
        session.pop("user_id", None)
    return user


@app.context_processor
def inject_user():
    """Makes `current_user` available in every template (for the nav bar etc.)."""
    return {"current_user": get_current_user()}


# ---------------------------------------------------------------- accounts

@app.route("/register", methods=["GET", "POST"])
def register():
    if get_current_user():
        return redirect("/")

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if password != confirm:
            error = "Passwords do not match."
        else:
            ok, message = create_user(username, password)
            if ok:
                user = verify_user(username, password)
                session.clear()
                session["user_id"] = user["id"]
                return redirect("/dashboard")
            error = message

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect("/")

    error = None
    if request.method == "POST":
        user = verify_user(request.form.get("username", ""), request.form.get("password", ""))
        if user:
            session.clear()
            session["user_id"] = user["id"]
            return redirect("/dashboard")
        error = "Incorrect username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------------------------------------------------------- pages

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/dashboard")
@app.route("/admin")
def dashboard():
    scans = get_scan_history()
    return render_template("admin.html", scans=scans)


@app.route("/delete/<int:scan_id>", methods=["POST"])
def delete_scan_route(scan_id):
    # Enforced on the server, so hiding the button isn't the only protection.
    user = get_current_user()
    if not user or not user["is_admin"]:
        return "Only the admin can delete scans.", 403
    delete_scan(scan_id)
    return redirect("/dashboard")


@app.route("/scan", methods=["POST"])
def scan():
    ok, Website, domain, error = validate_target(request.form.get("url", ""))
    if not ok:
        return render_template("index.html", error=error), 400
    Parsed_url = urlparse(Website)

    # HTTPS Check
    if Parsed_url.scheme == "https":
        https_status = "secure"
    else:
        https_status = "not secure"

    # The slow network checks are independent, so run them at the same time.
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_domain = pool.submit(get_domain_info, domain)
        f_ssl = pool.submit(check_ssl_certificate, domain)
        f_black = pool.submit(check_blacklist, Website)
        domain_info = f_domain.result()
        ssl_info = f_ssl.result()
        blacklist_info = f_black.result()

    # Registry gave no registration date? Estimate the age from the Internet Archive.
    if domain_info.get("registered") is True and domain_info.get("age_days") is None:
        domain_info.update(first_seen_online(domain))
    print(domain_info)
    if domain_info.get("registered") is True:
        ng_status = "Registered .ng Domain" if domain.endswith(".ng") else "Registered Domain"
    elif domain_info.get("registered") is False:
        ng_status = "Unregistered .ng Domain ⚠️" if domain.endswith(".ng") else "Unregistered Domain ⚠️"
    else:
        ng_status = "Unable to verify domain registration"

    # Look-alike domain check
    lookalike_info = check_lookalike(domain)
    print(lookalike_info)

    # Extra domain verification checks
    domain_analysis = analyze_domain(domain, domain_info)

    print(ssl_info)
    print(blacklist_info)

    risk_info = calculate_risk_score(domain_info, lookalike_info, ssl_info, blacklist_info, domain_analysis)

    log_scan(Website, risk_info["risk_level"], risk_info["score"])

    return render_template(
        "results.html",
        website=Website,
        https_status=https_status,
        ng_status=ng_status,
        domain_info=domain_info,
        lookalike_info=lookalike_info,
        ssl_info=ssl_info,
        blacklist_info=blacklist_info,
        risk_info=risk_info,
        domain_analysis=domain_analysis,
    )


if __name__ == "__main__":
    app.run(debug=True)   # local testing only; Vercel does not run this line
