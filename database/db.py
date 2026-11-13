# database/db.py - everything ReconX does with SQLite
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# reconx.db lives in the main ReconX folder (one level above this file)
DB_PATH = Path(__file__).resolve().parent.parent / "reconx.db"


def get_connection():
    """Open a connection to the database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create the tables if they don't exist yet."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            domain    TEXT NOT NULL,
            scan_date TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_addresses (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            version TEXT NOT NULL,
            address TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS domain_info (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL,
            registrar      TEXT,
            created_on     TEXT,
            expires_on     TEXT,
            age_days       INTEGER,
            days_to_expiry INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dns_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            value       TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL,
            name         TEXT NOT NULL,
            ip_addresses TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS technologies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL,
            category   TEXT NOT NULL,
            name       TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence   TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_findings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL,
            check_name     TEXT NOT NULL,
            status         TEXT NOT NULL,
            detail         TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL,
            file_name  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()


def save_scan(results):
    """Save everything one scan found. Returns the new scan's id.

    'results' is the dictionary built by recon/scanner.py.
    """
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO scans (domain, scan_date) VALUES (?, ?)",
        (results["domain"], scan_date),
    )
    scan_id = cursor.lastrowid

    for version in ("ipv4", "ipv6"):
        for address in results["ips"][version]:
            conn.execute(
                "INSERT INTO ip_addresses (scan_id, version, address) VALUES (?, ?, ?)",
                (scan_id, version, address),
            )

    info = results["domain_info"]
    if info is not None:
        conn.execute(
            "INSERT INTO domain_info"
            " (scan_id, registrar, created_on, expires_on, age_days, days_to_expiry)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, info["registrar"], info["created_on"], info["expires_on"],
             info["age_days"], info["days_to_expiry"]),
        )

    for record_type, values in results["dns_records"].items():
        for value in values:
            conn.execute(
                "INSERT INTO dns_records (scan_id, record_type, value) VALUES (?, ?, ?)",
                (scan_id, record_type, value),
            )

    for subdomain in results["subdomains"]:
        if subdomain["ips"] is None:
            ip_text = None                       # not checked
        else:
            ip_text = ", ".join(subdomain["ips"])  # "" means no address found
        conn.execute(
            "INSERT INTO subdomains (scan_id, name, ip_addresses) VALUES (?, ?, ?)",
            (scan_id, subdomain["name"], ip_text),
        )

    for tech in results["technologies"]:
        conn.execute(
            "INSERT INTO technologies (scan_id, category, name, confidence, evidence)"
            " VALUES (?, ?, ?, ?, ?)",
            (scan_id, tech["category"], tech["name"], tech["confidence"], tech["evidence"]),
        )

    for finding in results["security_findings"]:
        conn.execute(
            "INSERT INTO security_findings (scan_id, check_name, status, detail, recommendation)"
            " VALUES (?, ?, ?, ?, ?)",
            (scan_id, finding["check"], finding["status"], finding["detail"], finding["recommendation"]),
        )

    conn.commit()
    conn.close()
    return scan_id


# ---- Reading saved scans ----

def get_all_scans():
    """Return every saved scan, newest first."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, domain, scan_date FROM scans ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return rows


def fetch_rows(conn, sql, scan_id):
    """Run a SELECT for one scan and return the rows as a list of dictionaries."""
    rows = conn.execute(sql, (scan_id,)).fetchall()
    result = []
    for row in rows:
        result.append(dict(row))
    return result


def load_scan(scan_id):
    """Return one complete saved scan as a dictionary, or None if it doesn't exist."""
    conn = get_connection()
    scan = conn.execute(
        "SELECT id, domain, scan_date FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()

    if scan is None:
        conn.close()
        return None

    info_rows = fetch_rows(
        conn,
        "SELECT registrar, created_on, expires_on, age_days, days_to_expiry"
        " FROM domain_info WHERE scan_id = ?",
        scan_id,
    )

    result = {
        "id": scan["id"],
        "domain": scan["domain"],
        "scan_date": scan["scan_date"],
        "ip_addresses": fetch_rows(
            conn,
            "SELECT version, address FROM ip_addresses WHERE scan_id = ? ORDER BY version, address",
            scan_id,
        ),
        "domain_info": info_rows[0] if info_rows else None,
        "dns_records": fetch_rows(
            conn,
            "SELECT record_type, value FROM dns_records WHERE scan_id = ? ORDER BY record_type",
            scan_id,
        ),
        "subdomains": fetch_rows(
            conn,
            "SELECT name, ip_addresses FROM subdomains WHERE scan_id = ? ORDER BY name",
            scan_id,
        ),
        "technologies": fetch_rows(
            conn,
            "SELECT category, name, confidence, evidence FROM technologies"
            " WHERE scan_id = ? ORDER BY id",
            scan_id,
        ),
        "security_findings": fetch_rows(
            conn,
            "SELECT check_name, status, detail, recommendation FROM security_findings"
            " WHERE scan_id = ? ORDER BY id",
            scan_id,
        ),
    }
    conn.close()
    return result


# ---- PDF reports ----

def save_report(scan_id, file_name):
    """Remember that a PDF report was created for a scan."""
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    conn.execute(
        "INSERT INTO reports (scan_id, file_name, created_at) VALUES (?, ?, ?)",
        (scan_id, file_name, created_at),
    )
    conn.commit()
    conn.close()
