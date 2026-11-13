# reports/pdf_report.py
# Turns one saved scan (the dictionary from load_scan) into a PDF report.

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# All PDFs are saved in ReconX/generated_reports/
REPORTS_DIR = Path(__file__).resolve().parent.parent / "generated_reports"

# Width we may use on an A4 page after the left and right margins.
PAGE_WIDTH = A4[0] - 30 * mm

STYLES = getSampleStyleSheet()

# Background colour for each security status.
STATUS_COLORS = {
    "ok": colors.HexColor("#d1e7dd"),       # light green
    "weak": colors.HexColor("#fff3cd"),     # light yellow
    "missing": colors.HexColor("#f8d7da"),  # light red
}


def text_cell(value, style_name="BodyText"):
    """Turn any value into a Paragraph that is safe to put in the PDF.

    escape() replaces < > & so that scanned data can never be read
    as formatting instructions. Paragraphs also wrap long text.
    """
    return Paragraph(escape(str(value)), STYLES[style_name])


def make_table(header, rows, column_widths):
    """Build a table with a dark header row and thin grey lines."""
    data = [[text_cell(title, "Heading5") for title in header]]
    for row in rows:
        data.append([text_cell(value) for value in row])

    table = Table(data, colWidths=column_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dee2e6")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#adb5bd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def add_section(story, title, table, empty_text):
    """Add a heading, then the table (or a short note if there is no data)."""
    story.append(Paragraph(title, STYLES["Heading2"]))
    if table is None:
        story.append(Paragraph(empty_text, STYLES["Italic"]))
    else:
        story.append(table)
    story.append(Spacer(1, 10))


def build_story(scan):
    """Create the list of everything that goes into the report."""
    story = []
    w = PAGE_WIDTH

    # ----- Title -----
    story.append(Paragraph("ReconX Report", STYLES["Title"]))
    story.append(text_cell("Domain: " + scan["domain"], "Heading2"))
    story.append(text_cell("Scan #" + str(scan["id"]) + ", " + scan["scan_date"] + " UTC"))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report contains publicly available information only. "
        "Findings are observations, not confirmed vulnerabilities. "
        "For educational use and authorized security assessments only.",
        STYLES["Italic"]))
    story.append(Spacer(1, 10))

    # ----- IP addresses -----
    table = None
    if scan["ip_addresses"]:
        rows = [[row["version"], row["address"]] for row in scan["ip_addresses"]]
        table = make_table(["Version", "Address"], rows, [w * 0.25, w * 0.75])
    add_section(story, "IP addresses", table, "None saved.")

    # ----- Registration (WHOIS) -----
    table = None
    info = scan["domain_info"]
    if info:
        rows = [
            ["Registrar", info["registrar"] or "not public"],
            ["Created on", info["created_on"]],
            ["Expires on", info["expires_on"]],
        ]
        if info["age_days"] is not None:
            rows.append(["Domain age", str(info["age_days"]) + " days"])
        if info["days_to_expiry"] is not None:
            rows.append(["Days to expiry", str(info["days_to_expiry"]) + " days"])
        table = make_table(["Field", "Value"], rows, [w * 0.25, w * 0.75])
    add_section(story, "Registration (WHOIS)", table, "Not available.")

    # ----- Security observations -----
    table = None
    findings = scan["security_findings"]
    if findings:
        rows = []
        for row in findings:
            rows.append([row["status"].upper(), row["check_name"],
                         row["detail"], row["recommendation"] or ""])
        table = make_table(["Status", "Check", "Detail", "Recommendation"], rows,
                           [w * 0.12, w * 0.28, w * 0.32, w * 0.28])
        # Colour the Status cell of each row. Row 0 is the header.
        for number, row in enumerate(findings, start=1):
            color = STATUS_COLORS.get(row["status"], colors.white)
            table.setStyle(TableStyle([("BACKGROUND", (0, number), (0, number), color)]))
    add_section(story, "Security observations", table, "Not checked.")

    # ----- Technologies -----
    table = None
    if scan["technologies"]:
        rows = [[row["confidence"], row["category"], row["name"], row["evidence"]]
                for row in scan["technologies"]]
        table = make_table(["Confidence", "Category", "Technology", "Evidence"], rows,
                           [w * 0.15, w * 0.20, w * 0.20, w * 0.45])
    add_section(story, 'Technologies ("suspected" = based on a clue only)', table,
                "Nothing detected.")

    # ----- DNS records -----
    table = None
    if scan["dns_records"]:
        rows = [[row["record_type"], row["value"]] for row in scan["dns_records"]]
        table = make_table(["Type", "Value"], rows, [w * 0.15, w * 0.85])
    add_section(story, "DNS records", table, "None saved.")

    # ----- Subdomains -----
    table = None
    if scan["subdomains"]:
        rows = []
        for row in scan["subdomains"]:
            if row["ip_addresses"] is None:
                ips = "not checked"
            elif row["ip_addresses"] == "":
                ips = "no address found"
            else:
                ips = row["ip_addresses"]
            rows.append([row["name"], ips])
        table = make_table(["Subdomain", "IP addresses"], rows, [w * 0.55, w * 0.45])
    title = "Subdomains (" + str(len(scan["subdomains"])) + ")"
    add_section(story, title, table, "None found.")

    return story


def create_report(scan):
    """Create the PDF for one scan and return the path of the new file."""
    REPORTS_DIR.mkdir(exist_ok=True)

    # The file name uses only the scan number, which is always a plain integer.
    pdf_path = REPORTS_DIR / ("reconx_scan_" + str(int(scan["id"])) + ".pdf")

    document = SimpleDocTemplate(
        str(pdf_path), pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title="ReconX report - " + scan["domain"],
        author="ReconX",
    )
    document.build(build_story(scan))
    return pdf_path
