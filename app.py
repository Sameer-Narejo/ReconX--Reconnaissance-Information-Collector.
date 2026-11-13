# app.py - the ReconX web application (Flask)
from flask import Flask, abort, redirect, render_template, request, send_file, url_for

from database.db import get_all_scans, init_db, load_scan, save_report
from recon.scanner import clean_domain, run_full_scan
from reports.pdf_report import create_report

app = Flask(__name__)
init_db()


@app.route("/")
def home():
    return render_template("index.html", error=None, domain="")


@app.route("/scan", methods=["POST"])
def start_scan():
    domain = clean_domain(request.form.get("domain", ""))
    authorized = request.form.get("authorized") == "yes"

    if domain == "":
        return render_template("index.html", error="Please enter a domain.", domain=""), 400

    if not authorized:
        error = "Please confirm that you own this domain or have permission to assess it."
        return render_template("index.html", error=error, domain=domain), 400

    scan_id, error = run_full_scan(domain)
    if error is not None:
        return render_template("index.html", error=error, domain=domain), 400

    return redirect(url_for("view_scan", scan_id=scan_id))


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    scan = load_scan(scan_id)
    if scan is None:
        abort(404)
    return render_template("dashboard.html", scan=scan)


@app.route("/scan/<int:scan_id>/report")
def download_report(scan_id):
    scan = load_scan(scan_id)
    if scan is None:
        abort(404)

    pdf_path = create_report(scan)
    save_report(scan_id, pdf_path.name)

    download_name = "reconx_" + scan["domain"] + "_scan_" + str(scan_id) + ".pdf"
    return send_file(pdf_path, as_attachment=True, download_name=download_name)


@app.route("/history")
def history():
    return render_template("history.html", scans=get_all_scans())


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
