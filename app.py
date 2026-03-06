"""AuditFlow - Flask Web Application"""
import os
import sys
import logging
import threading
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, send_from_directory, jsonify, abort)

# Ensure auditflow package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auditflow.config import Config
from auditflow.scanner import Scanner
from auditflow.rule_engine import RuleEngine
from auditflow.reporter import Reporter

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("auditflow")

# ── App Init ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# Scan status tracker (in-memory; production would use Redis/DB)
scan_jobs: dict[str, dict] = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def run_scan_job(job_id: str, host: str, username: str, password: str,
                 key_path: str, port_range: str):
    """Background thread: scan → evaluate → report."""
    scan_jobs[job_id]["status"] = "running"
    try:
        scanner = Scanner(
            host=host,
            username=username or "root",
            password=password or None,
            key_path=key_path or None,
            port_range=port_range or Config.DEFAULT_PORT_RANGE,
        )
        scan_result = scanner.run()

        engine = RuleEngine(Config.RULES_DIR)
        rule_results = engine.evaluate(scan_result.data)

        reporter = Reporter(
            templates_dir=os.path.join(os.path.dirname(__file__), "templates"),
            reports_dir=Config.REPORTS_DIR,
        )
        report_id = reporter.generate(scan_result, rule_results, report_id=job_id)

        scan_jobs[job_id].update({
            "status": "done",
            "report_id": report_id,
            "error": scan_result.error,
        })
    except Exception as e:
        logger.exception(f"Scan job {job_id} failed")
        scan_jobs[job_id].update({"status": "error", "error": str(e)})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    reports = Reporter.list_reports(Config.REPORTS_DIR)
    # Stats
    total_scans = len(reports)
    avg_score = round(sum(r.get("score", 0) for r in reports) / total_scans, 1) if total_scans else 0
    critical_count = sum(1 for r in reports if r.get("risk") == "CRITICAL")
    recent = reports[:5]
    return render_template("index.html",
                           reports=recent,
                           total_scans=total_scans,
                           avg_score=avg_score,
                           critical_count=critical_count)


@app.route("/new-scan", methods=["GET", "POST"])
def new_scan():
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if not host:
            flash("Target host is required.", "danger")
            return redirect(url_for("new_scan"))

        import uuid
        job_id = str(uuid.uuid4())[:8]
        scan_jobs[job_id] = {"status": "queued", "host": host, "started": datetime.now().isoformat()}

        t = threading.Thread(
            target=run_scan_job,
            args=(
                job_id,
                host,
                request.form.get("username", "root"),
                request.form.get("password", ""),
                request.form.get("key_path", ""),
                request.form.get("port_range", Config.DEFAULT_PORT_RANGE),
            ),
            daemon=True,
        )
        t.start()

        flash(f"Scan started (Job ID: {job_id}). Redirecting to status page...", "info")
        return redirect(url_for("scan_status", job_id=job_id))

    return render_template("new_scan.html")


@app.route("/scan-status/<job_id>")
def scan_status(job_id: str):
    job = scan_jobs.get(job_id)
    if not job:
        abort(404)
    return render_template("scan_status.html", job=job, job_id=job_id)


@app.route("/scan-status/<job_id>/json")
def scan_status_json(job_id: str):
    job = scan_jobs.get(job_id, {})
    return jsonify(job)


@app.route("/reports")
def reports():
    all_reports = Reporter.list_reports(Config.REPORTS_DIR)
    return render_template("reports.html", reports=all_reports)


@app.route("/reports/<report_id>")
def view_report(report_id: str):
    report_path = os.path.join(Config.REPORTS_DIR, f"report_{report_id}.html")
    if not os.path.exists(report_path):
        abort(404)
    return send_from_directory(Config.REPORTS_DIR, f"report_{report_id}.html")


@app.route("/reports/<report_id>/delete", methods=["POST"])
def delete_report(report_id: str):
    deleted = Reporter.delete_report(Config.REPORTS_DIR, report_id)
    if deleted:
        flash(f"Report {report_id} deleted.", "success")
    else:
        flash("Report not found.", "danger")
    return redirect(url_for("reports"))


@app.route("/reports/<report_id>/download")
def download_report(report_id: str):
    report_path = os.path.join(Config.REPORTS_DIR, f"report_{report_id}.html")
    if not os.path.exists(report_path):
        abort(404)
    return send_from_directory(Config.REPORTS_DIR, f"report_{report_id}.html",
                               as_attachment=True,
                               download_name=f"auditflow_report_{report_id}.html")


@app.route("/reports/<report_id>/pdf")
def download_pdf(report_id: str):
    import pdfkit, re
    report_path = os.path.join(Config.REPORTS_DIR, f"report_{report_id}.html")
    if not os.path.exists(report_path):
        abort(404)
    with open(report_path, 'r', encoding='utf-8') as f:
        html = f.read()
    # Hide sidebar and inject override styles for PDF
    html = html.replace('@media print{.sidebar,.mobile-toggle{display:none!important}.main-content{margin-left:0!important}.header-actions{display:none!important}}',
    '@media print{}')
    html = html.replace('</body>', '''<style>
    .sidebar { display: none !important; }
    .mobile-toggle { display: none !important; }
    .main-content { margin-left: 0 !important; padding-top: 0 !important; }
    .header-actions { display: none !important; }
    .summary-grid { display: grid !important; grid-template-columns: repeat(3,1fr) !important; }
    .cat-grid { display: grid !important; grid-template-columns: repeat(3,1fr) !important; }
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    </style></body>''')
    # Replace gradients with solid colors
    html = html.replace('background:linear-gradient(135deg,#1976d2,#1565c0)', 'background:#1976d2')
    html = html.replace('background: linear-gradient(135deg, #1976d2 0%, #1565c0 100%)', 'background:#1976d2')
    # Remove emojis that break wkhtmltopdf
    html = re.sub(r'[^\x00-\x7F\u00C0-\u024F]+', '', html)
    fixed_path = os.path.join(Config.REPORTS_DIR, f"report_{report_id}_print.html")
    # Replace gradients with solid colors
    html = html.replace('background:linear-gradient(135deg,#1976d2,#1565c0)', 'background:#1976d2')
    html = html.replace('background: linear-gradient(135deg, #1976d2 0%, #1565c0 100%)', 'background:#1976d2')
    # Replace CSS variables with hardcoded colors for wkhtmltopdf
    html = html.replace('background:var(--severity-critical)', 'background:#d32f2f')
    html = html.replace('background:var(--severity-high)', 'background:#f57c00')
    html = html.replace('background:var(--severity-medium)', 'background:#fbc02d')
    html = html.replace('background:var(--severity-low)', 'background:#757575')
    html = html.replace('background:var(--severity-pass)', 'background:#2e7d32')
    html = html.replace('background:var(--primary)', 'background:#1976d2')
    html = html.replace('background:var(--muted)', 'background:#e5e7eb')
    html = html.replace('background:var(--card)', 'background:#ffffff')
    html = html.replace('border:1px solid var(--border)', 'border:1px solid #e0e0e0')
    html = html.replace('border-left:4px solid var(--severity-critical)', 'border-left:4px solid #d32f2f')
    html = html.replace('border-left:4px solid var(--severity-high)', 'border-left:4px solid #f57c00')
    html = html.replace('border-left:4px solid var(--severity-medium)', 'border-left:4px solid #fbc02d')
    html = html.replace('border-left:4px solid var(--severity-pass)', 'border-left:4px solid #2e7d32')
    html = html.replace('color:var(--severity-pass)', 'color:#2e7d32')
    html = html.replace('color:var(--destructive)', 'color:#d32f2f')
    html = html.replace('color:var(--primary)', 'color:#1976d2')
    html = html.replace('color:var(--muted-fg)', 'color:#6b7280')
    html = html.replace('color:var(--fg)', 'color:#333')
    html = html.replace('grid-template-columns:repeat(6,1fr)', 'grid-template-columns:repeat(3,1fr)')
    html = html.replace("background:rgba(245,124,0,.1);border:1px solid rgba(245,124,0,.3);color:#f57c00", "background:#f57c00;color:#fff")
    html = html.replace('grid-template-columns: repeat(6, 1fr)', 'grid-template-columns: repeat(3, 1fr)')
    html = html.replace('grid-template-columns: repeat(3, 1fr)', 'grid-template-columns: repeat(3, 1fr); display: grid')
    # Remove emojis that break wkhtmltopdf
    html = re.sub(r'[^\x00-\x7F\u00C0-\u024F]+', '', html)
    fixed_path = os.path.join(Config.REPORTS_DIR, f"report_{report_id}_print.html")
    with open(fixed_path, 'w', encoding='utf-8') as f:
        f.write(html)
    pdf_path = os.path.join(Config.REPORTS_DIR, f"report_{report_id}.pdf")
    config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')
    options = {
        'enable-local-file-access': '',
        'background': '',
        'encoding': 'UTF-8',
        'margin-top': '10mm',
        'margin-right': '10mm',
        'margin-bottom': '10mm',
        'margin-left': '10mm',
        'page-size': 'A4',
    }
    pdfkit.from_file(fixed_path, pdf_path, configuration=config, options=options)
    return send_from_directory(Config.REPORTS_DIR, f"report_{report_id}.pdf",
                               as_attachment=True,
                               download_name=f"auditflow_report_{report_id}.pdf")
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
