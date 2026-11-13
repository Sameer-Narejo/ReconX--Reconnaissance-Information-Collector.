# recon/http_client.py - the ONLY place where ReconX fetches a target's web page
from urllib.parse import urljoin, urlparse

import requests

from recon.ip_lookup import get_ip_addresses
from recon.validators import is_valid_domain, is_public_ip

USER_AGENT = "ReconX/0.1 (educational recon project)"
TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 3
MAX_BODY_BYTES = 200_000   # read at most ~200 KB of a page


def is_safe_url(url):
    """Return True only if the URL points to a normal public website."""
    parts = urlparse(url)

    if parts.scheme not in ("http", "https"):
        return False

    try:
        port = parts.port
    except ValueError:
        return False
    if port not in (None, 80, 443):
        return False

    host = parts.hostname
    if not host or not is_valid_domain(host):
        return False

    found = get_ip_addresses(host)
    all_ips = found["ipv4"] + found["ipv6"]
    if not all_ips:
        return False
    for ip in all_ips:
        if not is_public_ip(ip):
            return False

    return True


def safe_get(url):
    """Fetch a URL safely. Returns a dictionary, or None if it failed or was unsafe."""
    for _ in range(MAX_REDIRECTS + 1):
        if not is_safe_url(url):
            return None

        try:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException:
            return None

        if response.is_redirect:
            # The site wants to send us somewhere else: check that place first
            url = urljoin(url, response.headers["Location"])
            response.close()
            continue

        try:
            body_bytes = response.raw.read(MAX_BODY_BYTES, decode_content=True)
        except Exception:
            body_bytes = b""
        response.close()

        return {
            "url": url,
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": body_bytes.decode("utf-8", errors="replace"),
        }

    return None   # too many redirects


def fetch_site(domain):
    """Fetch a domain's home page: try HTTPS first, then plain HTTP."""
    result = safe_get(f"https://{domain}/")
    if result is None:
        result = safe_get(f"http://{domain}/")
    return result