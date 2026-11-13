# main.py - ReconX in the terminal (Phase 7)
from database.db import init_db, get_all_scans, load_scan
from recon.scanner import clean_domain, run_full_scan


def describe_ips(ip_text):
    """Turn the stored IP text into something readable."""
    if ip_text is None:
        return "(not checked)"
    if ip_text == "":
        return "(no address found)"
    return ip_text


def print_scan(scan):
    """Print one complete saved scan."""
    print(f"\n=== Scan #{scan['id']}: {scan['domain']} ({scan['scan_date']} UTC) ===")

    print("\nIP addresses:")
    if not scan["ip_addresses"]:
        print("  (none saved)")
    for row in scan["ip_addresses"]:
        print(f"  {row['version']:<5} {row['address']}")

    print("\nRegistration (WHOIS):")
    info = scan["domain_info"]
    if info is None:
        print("  (not available)")
    else:
        print(f"  Registrar:       {info['registrar'] or 'not public'}")
        print(f"  Created on:      {info['created_on']}")
        print(f"  Expires on:      {info['expires_on']}")
        if info["age_days"] is not None:
            print(f"  Domain age:      {info['age_days']} days (about {info['age_days'] // 365} years)")
            if info["age_days"] < 30:
                print("  [NOTE] This domain is very new. New domains are sometimes used for phishing.")
        if info["days_to_expiry"] is not None:
            print(f"  Days to expiry:  {info['days_to_expiry']} days")
            if info["days_to_expiry"] < 30:
                print("  [NOTE] This domain expires soon. If it isn't renewed, someone else could register it.")

    print("\nDNS records:")
    if not scan["dns_records"]:
        print("  (none saved)")
    for row in scan["dns_records"]:
        print(f"  {row['record_type']:<6} {row['value']}")

    print(f"\nSubdomains ({len(scan['subdomains'])}):")
    if not scan["subdomains"]:
        print("  (none found)")
    for row in scan["subdomains"]:
        print(f"  {row['name']:<40} {describe_ips(row['ip_addresses'])}")

    print("\nTechnologies ('reported' = the site says so, 'suspected' = based on a clue):")
    if not scan["technologies"]:
        print("  (nothing detected)")
    for row in scan["technologies"]:
        print(f"  [{row['confidence']:<9}] {row['category']:<22} {row['name']:<25} ({row['evidence']})")

    print("\nSecurity observations (these are observations, not confirmed vulnerabilities):")
    if not scan["security_findings"]:
        print("  (not checked)")
    for row in scan["security_findings"]:
        print(f"  [{row['status'].upper():<7}] {row['check_name']}")
        print(f"            {row['detail']}")
        if row["recommendation"]:
            print(f"            Recommendation: {row['recommendation']}")


def new_scan():
    """Ask for a domain, scan it and show the saved result."""
    raw = input("Enter a domain to scan (e.g. example.com): ")
    domain = clean_domain(raw)
    if domain == "":
        print("Domain cannot be empty.")
        return

    print(f"\nScanning {domain}... this can take up to a minute.")
    scan_id, error = run_full_scan(domain)

    if error is not None:
        print(f"\n[STOPPED] {error}")
        return

    print_scan(load_scan(scan_id))
    print(f"\n[SAVED] Scan #{scan_id} stored in reconx.db")


def show_history():
    """List saved scans and let the user open one."""
    scans = get_all_scans()
    if not scans:
        print("\nNo scans saved yet. Run a scan first!")
        return

    print("\n=== Scan history ===")
    for scan in scans:
        print(f"  #{scan['id']:<4} {scan['domain']:<25} {scan['scan_date']} UTC")

    choice = input("\nEnter a scan number to view it (or press Enter to go back): ").strip()
    if choice == "":
        return
    if not choice.isdigit():
        print("Please enter a number.")
        return

    scan = load_scan(int(choice))
    if scan is None:
        print(f"There is no scan #{choice}.")
        return

    print_scan(scan)


def main():
    init_db()

    print("=== ReconX - Reconnaissance Information Collector ===")
    print("Only scan domains you own or have permission to assess.")

    while True:
        print("\nWhat would you like to do?")
        print("  1) Run a new scan")
        print("  2) View scan history")
        print("  3) Exit")
        choice = input("Choose 1, 2 or 3: ").strip()

        if choice == "1":
            new_scan()
        elif choice == "2":
            show_history()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Please choose 1, 2 or 3.")


if __name__ == "__main__":
    main()