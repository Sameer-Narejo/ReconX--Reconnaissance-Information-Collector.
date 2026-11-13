# recon/scanner.py - runs one complete scan (used by the terminal AND the website)
from database.db import save_scan
from recon.dns_lookup import get_dns_records
from recon.domain_info import get_domain_info, days_between_now_and, format_date
from recon.http_client import fetch_site
from recon.ip_lookup import get_ip_addresses
from recon.security_analysis import analyze_security
from recon.subdomain_discovery import find_subdomains, resolve_subdomains
from recon.technology_detection import detect_technologies
from recon.validators import is_public_ip, is_valid_domain


def clean_domain(raw):
    """Tidy up what the user typed: spaces, capitals, http:// and trailing /."""
    domain = raw.strip().lower()
    domain = domain.removeprefix("http://")
    domain = domain.removeprefix("https://")
    domain = domain.rstrip("/")
    return domain


def run_full_scan(domain):
    """Run every check on a domain and save the results.

    Returns (scan_id, error). Exactly one of them is None:
      - success: (the new scan's id, None)
      - failure: (None, a message explaining why)
    """
    if not is_valid_domain(domain):
        return None, f"'{domain}' is not a valid domain name."

    # 1. IP addresses, and the safety check
    ips = get_ip_addresses(domain)
    all_ips = ips["ipv4"] + ips["ipv6"]
    if not all_ips:
        return None, "Could not resolve this domain. It may not exist."

    for ip in all_ips:
        if not is_public_ip(ip):
            return None, (
                "Blocked: this domain points to a private or internal address "
                f"({ip}). ReconX only scans public internet targets."
            )

    results = {
        "domain": domain,
        "ips": ips,
        "domain_info": None,
        "dns_records": {},
        "subdomains": [],
        "technologies": [],
        "security_findings": [],
    }

    # 2. DNS records
    results["dns_records"] = get_dns_records(domain)

    # 3. Registration (WHOIS) information
    info = get_domain_info(domain)
    if info is not None:
        age = days_between_now_and(info["creation_date"])
        if age is not None:
            age = -age   # creation is in the past, so flip the sign
        results["domain_info"] = {
            "registrar": info["registrar"],
            "created_on": format_date(info["creation_date"]),
            "expires_on": format_date(info["expiration_date"]),
            "age_days": age,
            "days_to_expiry": days_between_now_and(info["expiration_date"]),
        }

    # 4. Subdomains (passive: public certificate logs only)
    names = find_subdomains(domain)
    if names:
        results["subdomains"] = resolve_subdomains(names)

    # 5. Technologies and security observations (one normal page request)
    page = fetch_site(domain)
    if page is not None:
        results["technologies"] = detect_technologies(page)
        results["security_findings"] = analyze_security(page)

    scan_id = save_scan(results)
    return scan_id, None