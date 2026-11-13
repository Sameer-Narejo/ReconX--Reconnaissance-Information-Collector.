# recon/ip_lookup.py - find the IPv4 and IPv6 addresses of a domain
import socket


def get_ip_addresses(domain):
    """Return a dictionary with lists of IPv4 and IPv6 addresses."""
    ipv4 = set()
    ipv6 = set()

    try:
        results = socket.getaddrinfo(domain, None)
    except socket.gaierror:
        # The domain could not be resolved (it may not exist)
        return {"ipv4": [], "ipv6": []}

    for family, _, _, _, address in results:
        ip = address[0]
        if family == socket.AF_INET:
            ipv4.add(ip)
        elif family == socket.AF_INET6:
            ipv6.add(ip)

    return {"ipv4": sorted(ipv4), "ipv6": sorted(ipv6)}