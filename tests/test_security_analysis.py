# tests/test_security_analysis.py
# Automatic checks for recon/security_analysis.py.
# We build fake "pages" by hand, so these tests never touch the internet.

from recon.security_analysis import analyze_security


def make_page(url, headers):
    """Build a fake page that looks like the result of fetch_site()."""
    return {"url": url, "status": 200, "headers": headers, "body": ""}


def status_of(findings, check_name):
    """Find one check in the list of findings and return its status."""
    for finding in findings:
        if finding["check"] == check_name:
            return finding["status"]
    return None


def test_page_with_no_security_headers():
    page = make_page("http://example.com/", {})
    findings = analyze_security(page)

    assert status_of(findings, "HTTPS") == "missing"
    assert status_of(findings, "Strict-Transport-Security") == "missing"
    assert status_of(findings, "Content-Security-Policy") == "missing"
    assert status_of(findings, "X-Frame-Options") == "missing"
    assert status_of(findings, "X-Content-Type-Options") == "missing"


def test_page_with_good_headers():
    page = make_page("https://example.com/", {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    })
    findings = analyze_security(page)

    assert len(findings) == 5
    for finding in findings:
        assert finding["status"] == "ok"


def test_short_hsts_is_weak():
    page = make_page("https://example.com/", {"Strict-Transport-Security": "max-age=300"})
    findings = analyze_security(page)

    assert status_of(findings, "Strict-Transport-Security") == "weak"


def test_csp_with_unsafe_inline_is_weak():
    page = make_page("https://example.com/", {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
    })
    findings = analyze_security(page)

    assert status_of(findings, "Content-Security-Policy") == "weak"


def test_header_names_work_in_lowercase():
    page = make_page("https://example.com/", {"x-content-type-options": "nosniff"})
    findings = analyze_security(page)

    assert status_of(findings, "X-Content-Type-Options") == "ok"


def test_missing_findings_come_with_a_recommendation():
    page = make_page("http://example.com/", {})
    for finding in analyze_security(page):
        assert finding["recommendation"] != ""