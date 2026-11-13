# make_report.py
# Practice script: create a PDF report for one saved scan.
# Usage:  py make_report.py 13

import sys

from database.db import init_db, load_scan
from reports.pdf_report import create_report

init_db()

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    print("Usage: py make_report.py SCAN_NUMBER   (for example: py make_report.py 13)")
    sys.exit()

scan = load_scan(int(sys.argv[1]))

if scan is None:
    print("[ERROR] There is no scan with that number.")
else:
    pdf_path = create_report(scan)
    print("[DONE] Report saved to", pdf_path)
