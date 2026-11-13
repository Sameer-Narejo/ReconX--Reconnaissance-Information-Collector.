# recon/technology_detection.py - spot technologies from publicly visible clues
import re

# Each hint is: (text to look for, category, technology name)

HEADER_HINTS = [
    ("cf-ray", "CDN", "Cloudflare"),
    ("x-amz-cf-id", "CDN", "Amazon CloudFront"),
    ("x-vercel-id", "Hosting", "Vercel"),
    ("x-github-request-id", "Hosting", "GitHub Pages"),
    ("x-drupal-cache", "CMS", "Drupal"),
    ("x-shopify-stage", "E-commerce", "Shopify"),
]

COOKIE_HINTS = [
    ("phpsessid", "Language", "PHP"),
    ("laravel_session", "Framework", "Laravel"),
    ("csrftoken", "Framework", "Django"),
    ("asp.net_sessionid", "Framework", "ASP.NET"),
    ("jsessionid", "Language", "Java"),
    ("wordpress_", "CMS", "WordPress"),
]

BODY_HINTS = [
    ("wp-content", "CMS", "WordPress"),
    ("/sites/default/files", "CMS", "Drupal"),
    ("/media/jui/", "CMS", "Joomla"),
    ("cdn.shopify.com", "E-commerce", "Shopify"),
    ("__next_data__", "Framework", "Next.js"),
    ("ng-version", "Framework", "Angular"),
    ("data-reactroot", "Framework", "React"),
    ("jquery", "JavaScript library", "jQuery"),
    ("bootstrap", "CSS framework", "Bootstrap"),
    ("fonts.googleapis.com", "Fonts", "Google Fonts"),
]

GENERATOR_PATTERN = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,80})["\']',
    re.IGNORECASE,
)


def detect_technologies(page):
    """Return a list of findings from a page fetched by http_client.

    Each finding is a dictionary with: category, name, confidence, evidence.
    confidence is "reported" (the site says so itself) or "suspected" (a clue).
    """
    findings = []
    seen = set()

    def add(category, name, confidence, evidence):
        key = (category, name.lower())
        if key not in seen:
            seen.add(key)
            findings.append({
                "category": category,
                "name": name,
                "confidence": confidence,
                "evidence": evidence,
            })

    # Header names can be written in any mix of capitals, so lowercase them
    headers = {}
    for name, value in page["headers"].items():
        headers[name.lower()] = value

    body = page["body"].lower()
    cookies = headers.get("set-cookie", "").lower()

    # 1. Things the server tells us directly
    if "server" in headers:
        add("Web server", headers["server"], "reported", "Server header")
    if "x-powered-by" in headers:
        add("Platform", headers["x-powered-by"], "reported", "X-Powered-By header")

    match = GENERATOR_PATTERN.search(page["body"])
    if match:
        add("CMS / site generator", match.group(1), "reported", "generator meta tag")

    # 2. Clues: special headers, cookie names and text inside the page
    for header_name, category, name in HEADER_HINTS:
        if header_name in headers:
            add(category, name, "suspected", f"'{header_name}' header is present")

    for cookie_text, category, name in COOKIE_HINTS:
        if cookie_text in cookies:
            add(category, name, "suspected", f"cookie name contains '{cookie_text}'")

    for body_text, category, name in BODY_HINTS:
        if body_text in body:
            add(category, name, "suspected", f"page contains '{body_text}'")

    return findings