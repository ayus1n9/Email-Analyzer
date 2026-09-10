from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response, session
from werkzeug.utils import secure_filename
from api import api_bp
import os
import uuid
import logging
import secrets
import hmac
import config as Config
import json
from datetime import datetime
from email_analyzer import (
    read_eml_file,
    split_headers_body,
    parse_headers,
    analyze_headers
)
from database import (
    init_database, save_scan_result, get_all_scans,
    get_scan_by_id, get_dashboard_stats, delete_scan, clear_all_scans
)

app = Flask(__name__)
logger = logging.getLogger(__name__)
def generate_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

def validate_csrf_token(token):
    expected = session.get("csrf_token")
    if not expected or not token:
        return False
    return hmac.compare_digest(token, expected)

def require_web_auth():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return None

app.jinja_env.globals["generate_csrf_token"] = generate_csrf_token

app.config.from_object(Config.Config)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = Config.FLASK_ENV == "production"

if Config.FLASK_ENV == "production":
    if not Config.SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY must be set when FLASK_ENV=production"
        )
    if not Config.WEB_ADMIN_TOKEN:
        raise RuntimeError(
            "WEB_ADMIN_TOKEN must be set when FLASK_ENV=production"
        )
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
init_database()
app.register_blueprint(api_bp)

@app.after_request
def add_security_headers(response):
    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff"
    )
    response.headers.setdefault(
        "X-Frame-Options",
        "SAMEORIGIN"
    )
    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin"
    )
    return response

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import simpleSplit
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

@app.route('/export/json/<filename>')
def export_json(filename):
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    filepath = get_safe_upload_path(filename)
    if filepath is None:
        return "Invalid filename", 400
    if not os.path.isfile(filepath):
        return "File not found", 404
    content = read_eml_file(filepath)
    if not content:
        return "Error reading file", 500
    header, body, h_lines, b_lines = split_headers_body(content)
    headers = parse_headers(header)
    analysis = analyze_headers(headers, body)
    data = {
        'filename': filename,
        'analyzed_at': datetime.now().isoformat(),
        'analysis': analysis
    }
    return jsonify(data), 200, {'Content-Disposition': f'attachment; filename={filename}.json'}

@app.route('/export/pdf/<filename>')
def export_pdf(filename):
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    if not REPORTLAB_AVAILABLE:
        return "PDF export requires reportlab. Install with: pip install reportlab", 501
    filepath = get_safe_upload_path(filename)
    if filepath is None:
        return "Invalid filename", 400
    if not os.path.isfile(filepath):
        return "File not found", 404
    content = read_eml_file(filepath)
    if not content:
        return "Error reading file", 500
    header, body, h_lines, b_lines = split_headers_body(content)
    headers = parse_headers(header)
    analysis = analyze_headers(headers, body)
    response = make_response()
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}.pdf'
    from io import BytesIO
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"Email Analysis Report: {filename}")
    y -= 30
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20
    c.drawString(50, y, f"Overall Risk: {analysis['summary']['overall_risk'].upper()}")
    y -= 20
    c.drawString(50, y, f"Risk Score: {analysis['summary']['risk_score']}/10")
    y -= 20
    c.drawString(50, y, f"Total Findings: {analysis['summary']['total_findings']}")
    y -= 30
    for idx, finding in enumerate(analysis['findings'], 1):
        if y < 100:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 12)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"{idx}. {finding['check']} ({finding['severity'].upper()})")
        y -= 15
        c.setFont("Helvetica", 10)
        if isinstance(finding['details'], dict):
            for k, v in finding['details'].items():
                line = f"{k}: {v}" if not isinstance(v, list) else f"{k}: {', '.join(v[:3])}"
                c.drawString(70, y, line[:80])
                y -= 12
        else:
            c.drawString(70, y, str(finding['details'])[:80])
            y -= 12
        y -= 10
    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    response = make_response(pdf)
    return response

def get_safe_upload_path(filename):
    safe_filename = secure_filename(filename)

    if not safe_filename or safe_filename != filename:
        return None

    upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
    filepath = os.path.abspath(os.path.join(upload_dir, safe_filename))

    if os.path.commonpath([upload_dir, filepath]) != upload_dir:
        return None

    return filepath

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('upload_page'))
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token):
            return "Invalid CSRF token.", 400
        token = request.form.get('token', '')
        if not Config.WEB_ADMIN_TOKEN:
            return "Web authentication is not configured.", 503
        if not hmac.compare_digest(token, Config.WEB_ADMIN_TOKEN):
            return "Invalid credentials.", 401
        session['authenticated'] = True
        session['csrf_token'] = secrets.token_urlsafe(32)
        return redirect(url_for('upload_page'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    csrf_token = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token.", 400
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def upload_page():
    return render_template('upload.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    auth_response = require_web_auth()
    if auth_response:
        return auth_response

    csrf_token = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token.", 400

    try:
        if 'file' not in request.files:
            return "No file uploaded", 400
        
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400
        
        if not allowed_file(file.filename):
            return "Invalid file type. Please upload .eml file", 400
        
        filename = secure_filename(file.filename)
        if not filename:
            return "Invalid filename", 400
        stored_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        file.save(filepath)
        
        content = read_eml_file(filepath)
        if not content:
            return "Error reading file", 500
        
        header, body, h_lines, b_lines = split_headers_body(content)
        headers = parse_headers(header)
        analysis = analyze_headers(headers, body)
        
        return render_template('report.html', 
                             analysis=analysis,
                             headers=headers,
                             filename=filename,
                             stored_filename=stored_filename,
                             header_lines=h_lines,
                             body_lines=b_lines)
    
    except Exception:
        logger.exception("Unexpected error while analyzing uploaded email")
        return "An internal error occurred while analyzing the email.", 500

@app.route('/history')
def view_history():
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    limit = request.args.get('limit', 50, type=int)
    if limit < 1 or limit > Config.MAX_HISTORY_RECORDS:
        return (
            f"limit must be between 1 and {Config.MAX_HISTORY_RECORDS}",
            400
        )
    scans = get_all_scans(limit)
    stats = get_dashboard_stats()
    return render_template('history.html', scans=scans, stats=stats)

@app.route('/dashboard')
def view_dashboard():
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    stats = get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan not found", 404
    
    scan['findings'] = json.loads(scan['findings']) if scan['findings'] else []
    scan['headers_analyzed'] = json.loads(scan['headers_analyzed']) if scan['headers_analyzed'] else []
    return render_template('scan_detail.html', scan=scan)

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan_route(scan_id):
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    csrf_token = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token.", 400
    deleted = delete_scan(scan_id)
    if not deleted:
        return "Scan not found", 404
    return redirect(url_for('view_history'))

@app.route('/clear-all', methods=['POST'])
def clear_all_scans_route():
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    csrf_token = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token.", 400
    count = clear_all_scans()
    return redirect(url_for('view_history'))

@app.route('/batch')
def batch_upload_page():
    return render_template('batch.html')

@app.route('/batch/analyze', methods=['POST'])
def batch_analyze():
    auth_response = require_web_auth()
    if auth_response:
        return auth_response
    csrf_token = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token.", 400
    if 'files' not in request.files:
        return "No files uploaded", 400
    files = request.files.getlist('files')
    if len(files) > Config.MAX_BATCH_FILES:
        return (
            f"Too many files. Maximum allowed is {Config.MAX_BATCH_FILES}.",
            400
        )
    if not files or all(f.filename == '' for f in files):
        return "No files selected", 400
    results = []
    for file in files:
        if file.filename == '':
            continue
        if not allowed_file(file.filename):
            continue
        filename = secure_filename(file.filename)

        if not filename:
            return "Invalid filename", 400

        stored_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)

        file.save(filepath)
        content = read_eml_file(filepath)
        if content:
            header, body, h_lines, b_lines = split_headers_body(content)
            headers = parse_headers(header)
            analysis = analyze_headers(headers, body)
            save_scan_result(
                filename=filename,
                stored_filename=stored_filename,
                file_size=os.path.getsize(filepath),
                analysis=analysis,
                headers=headers,
                body_preview=body[:300]
            )
            results.append({
                'filename': filename,
                'analysis': analysis,
                'success': True
            })
        else:
            results.append({
                'filename': filename,
                'success': False,
                'error': 'Error reading file'
            })
    return render_template('batch_results.html', results=results)

if __name__ == '__main__':
    env = os.environ.get('FLASK_ENV', 'development')
    if env == 'production':
        raise RuntimeError(
            'Production mode must be started with Gunicorn, not Flask dev server.'
        )
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(debug=False, host=host, port=port)