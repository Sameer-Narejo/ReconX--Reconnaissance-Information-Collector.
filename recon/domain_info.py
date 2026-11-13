# recon/domain_info.py - domain registration (WHOIS) information
from datetime import datetime, timezone

import whois
from whois.exceptions import PywhoisError


def first_value(value):
    """WHOIS sometimes returns a list of values; keep only the first one."""
    if isinstance(value, list):
        if value:
            return value[0]
        return None
    return value


def get_domain_info(domain):
    """Return registrar, dates and nameservers, or None if WHOIS fails."""
    try:
        data = whois.whois(domain, timeout=10)
    except (PywhoisError, OSError):
        return None

    raw_servers = data.get("name_servers") or []
    if isinstance(raw_servers, str):
        raw_servers = [raw_servers]

    name_servers = set()
    for server in raw_servers:
        name_servers.add(server.lower())

    return {
        "registrar": data.get("registrar"),
        "creation_date": first_value(data.get("creation_date")),
        "expiration_date": first_value(data.get("expiration_date")),
        "name_servers": sorted(name_servers),
    }


# ---- NEW helper functions ----

def make_utc(value):
    """Make sure a datetime has a time zone (assume UTC if missing)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def days_between_now_and(value):
    """Days from now until a date (negative = the date is in the past)."""
    if not isinstance(value, datetime):
        return None
    difference = make_utc(value) - datetime.now(timezone.utc)
    return difference.days


def format_date(value):
    """Turn a datetime into readable text like '14 August 1995'."""
    if isinstance(value, datetime):
        return value.strftime("%d %B %Y")
    return value or "not public"