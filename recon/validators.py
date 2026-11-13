# recon/validators.py - safety checks shared by all ReconX modules
import ipaddress
import re

LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def is_valid_domain(domain):
    """Return True if domain looks like a real public domain name."""
    if not domain or len(domain) > 253:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not LABEL_PATTERN.match(label):
            return False

    if not labels[-1].isalpha():
        return False

    return True


def is_public_ip(ip_text):
    """Return True only if the IP is a normal public internet address."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False   # not a valid IP at all, so treat it as unsafe
    return ip.is_global