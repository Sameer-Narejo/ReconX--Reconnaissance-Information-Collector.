# ReconX - Reconnaissance Information Collector

ReconX is a web-based tool that collects **publicly available** technical
information about a domain and presents it in a dashboard and a PDF report.
I built it as a learning project in Python and cybersecurity.

> **For educational use and authorized security assessments only.**
I(Sameer Ahmed) used my 2 hours to do the same things that ReconX do in less than a minutE.
I created this project to help beginners in their passive reconnaissance
> Only scan domains that you own or have explicit permission to assess.

## Features

- **IP addresses**: IPv4 and IPv6 lookup
- **Domain registration**: registrar, creation date, expiry date (WHOIS)
- **DNS records**: A, AAAA, MX, NS, TXT, CNAME, SOA
- **Subdomain discovery**: passive, from public Certificate Transparency logs (crt.sh)
- **Technology detection**: from public headers, cookies and page content,
  marked as "reported" or "suspected"
- **Security observations**: HTTPS, HSTS, Content-Security-Policy,
  X-Frame-Options, X-Content-Type-Options, each with a recommendation
- **Scan history** stored in SQLite
- **PDF report** download for every scan

## Built with

Python, Flask, SQLite, Bootstrap 5, JavaScript, dnspython, python-whois,
requests, reportlab, pytest

## Safety by design

- **Passive only**: no brute forcing, no port scanning, no exploitation
- **SSRF protection**: domains that resolve to localhost, private or internal
  IP addresses are refused, and every redirect is checked again
- **Input validation**: only well-formed domain names are accepted
- **Rate limiting**: request timeouts, at most 25 subdomain lookups per scan,
  with a short delay between them
- **SQL injection protection**: every query uses parameters
- **Output escaping**: scanned data is escaped in the web pages and in the PDF
- **Careful wording**: results are observations, not confirmed vulnerabilities
- **Authorization check**: the user must confirm permission before each scan,
  and the server verifies it

## Getting started (Windows, PowerShell)

        git clone https://github.com/Sameer-Narejo/ReconX--Reconnaissance-Information-Collector..git ReconX
    cd ReconX
    py -m venv venv
    venv\Scripts\Activate.ps1
    py -m pip install -r requirements.txt
    py app.py

Then open http://127.0.0.1:5000 in your browser.

A command line version is also included:

    py main.py

## Running the tests

    py -m pytest

The tests run offline and do not contact any website.

## Project structure

    ReconX/
        app.py            Flask web application (routes)
        main.py           Command line menu
        make_report.py    Create a PDF report from the command line
        recon/            Scan modules (DNS, WHOIS, subdomains, technology, security)
        database/         SQLite storage
        reports/          PDF report builder
        templates/        HTML pages (Jinja)
        static/           CSS, JavaScript and Bootstrap
        tests/            Automated tests

## Known limitations

- Built for local use on your own computer. There is no login system and
  no CSRF token on the scan form, so do not expose it to the internet.
- `debug=True` in `app.py` is for development only.
- The SSRF check validates the IP addresses before connecting. A domain whose
  DNS answer changes between the check and the request (DNS rebinding) is not
  fully covered.
- Technology detection is based on public clues and can be wrong.

## Disclaimer

Use this tool only on domains you own or are authorized to assess.
You are responsible for how you use it.
