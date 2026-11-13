# recon/dns_lookup.py - look up common DNS records for a domain
import dns.exception
import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def get_dns_records(domain):
    """Return a dictionary like {"A": [...], "MX": [...], ...}."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3    # wait max 3 seconds for one DNS server
    resolver.lifetime = 5   # wait max 5 seconds in total per question

    records = {}
    for record_type in RECORD_TYPES:
        values = []
        try:
            answers = resolver.resolve(domain, record_type)
            for answer in answers:
                values.append(answer.to_text())
        except dns.exception.DNSException:
            pass   # no record of this type, or the lookup failed
        records[record_type] = values

    return records