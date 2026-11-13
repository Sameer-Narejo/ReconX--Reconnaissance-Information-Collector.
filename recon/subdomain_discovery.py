# recon/subdomain_discovery.py - find subdomains passively from public records
import time

import requests

from recon.ip_lookup import get_ip_addresses
from recon.validators import is_valid_domain

CRT_SH_URL = "https://crt.sh/"
USER_AGENT = "ReconX/0.1 (educational recon project)"
TIMEOUT_SECONDS = 30
MAX_TO_RESOLVE = 25     # never look up more than this many per scan
DELAY_SECONDS = 0.2     # short pause between lookups (rate limiting)


def find_subdomains(domain):
    """Return a sorted list of subdomains, or None if the lookup failed."""
    try:
        response = requests.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        entries = response.json()
    except (requests.RequestException, ValueError):
        return None

    subdomains = set()
    for entry in entries:
        names = entry.get("name_value", "")
        for name in names.split("\n"):
            name = name.strip().lower()
            name = name.removeprefix("*.")

            belongs_to_domain = name.endswith("." + domain)
            if belongs_to_domain and is_valid_domain(name):
                subdomains.add(name)

    return sorted(subdomains)


def resolve_subdomains(subdomains):
    """Look up the IPs of each subdomain, politely.

    Returns a list like [{"name": "www.example.com", "ips": ["1.2.3.4"]}, ...].
    "ips" is None for subdomains we skipped because of the limit.
    """
    results = []
    for position, name in enumerate(subdomains):
        if position < MAX_TO_RESOLVE:
            found = get_ip_addresses(name)
            ips = found["ipv4"] + found["ipv6"]
            time.sleep(DELAY_SECONDS)
        else:
            ips = None
        results.append({"name": name, "ips": ips})
    return results