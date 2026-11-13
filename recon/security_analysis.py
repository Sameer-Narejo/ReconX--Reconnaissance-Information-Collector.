# recon/security_analysis.py - check basic, publicly visible security settings
import re

SIX_MONTHS_IN_SECONDS = 15552000


def analyze_security(page):
    """Return a list of observations about a page fetched by http_client.

    Each observation is a dictionary with: check, status, detail, recommendation.
    status is "ok", "weak" or "missing". These are observations, not
    confirmed vulnerabilities.
    """
    findings = []

    def add(check, status, detail, recommendation=""):
        findings.append({
            "check": check,
            "status": status,
            "detail": detail,
            "recommendation": recommendation,
        })

    # Header names can be written in any mix of capitals, so lowercase them
    headers = {}
    for name, value in page["headers"].items():
        headers[name.lower()] = value

    uses_https = page["url"].startswith("https://")

    # 1. HTTPS
    if uses_https:
        add("HTTPS", "ok", "The site answers over an encrypted HTTPS connection.")
    else:
        add(
            "HTTPS", "missing",
            "The site answered over plain HTTP, so traffic is not encrypted.",
            "Install a TLS certificate and redirect all HTTP traffic to HTTPS.",
        )

    # 2. Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if hsts is None:
        add(
            "Strict-Transport-Security", "missing",
            "Browsers are not told to always use HTTPS for this site.",
            "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )
    else:
        match = re.search(r"max-age=(\d+)", hsts.lower())
        if match and int(match.group(1)) >= SIX_MONTHS_IN_SECONDS:
            add("Strict-Transport-Security", "ok", f"Present: {hsts}")
        else:
            add(
                "Strict-Transport-Security", "weak",
                f"Present, but max-age is short or missing: {hsts}",
                "Use a max-age of at least 6 months (15552000 seconds).",
            )

    # 3. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if csp is None:
        add(
            "Content-Security-Policy", "missing",
            "The site does not limit where scripts and other content may load from.",
            "Add a Content-Security-Policy header, starting with a simple policy such as: default-src 'self'",
        )
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        add(
            "Content-Security-Policy", "weak",
            "Present, but it allows 'unsafe-inline' or 'unsafe-eval', which reduces its protection.",
            "Try to remove 'unsafe-inline' and 'unsafe-eval' from the policy.",
        )
    else:
        add("Content-Security-Policy", "ok", "Present.")

    # 4. X-Frame-Options (or the modern CSP replacement, frame-ancestors)
    frame_options = headers.get("x-frame-options", "").lower()
    if frame_options in ("deny", "sameorigin"):
        add("X-Frame-Options", "ok", f"Present: {frame_options.upper()}")
    elif csp is not None and "frame-ancestors" in csp.lower():
        add("X-Frame-Options", "ok", "Not set, but the CSP 'frame-ancestors' rule does the same job.")
    else:
        add(
            "X-Frame-Options", "missing",
            "Other websites may be able to show this site inside a hidden frame (clickjacking).",
            "Add the header: X-Frame-Options: SAMEORIGIN",
        )

    # 5. X-Content-Type-Options
    if headers.get("x-content-type-options", "").lower() == "nosniff":
        add("X-Content-Type-Options", "ok", "Present: nosniff")
    else:
        add(
            "X-Content-Type-Options", "missing",
            "Browsers may guess file types, which can make some attacks easier.",
            "Add the header: X-Content-Type-Options: nosniff",
        )

    return findings