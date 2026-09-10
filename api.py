import uuid
import logging
from flask import Blueprint, request, jsonify, render_template
from werkzeug.utils import secure_filename
import os
import json
import hmac
from datetime import datetime
from auth import require_api_key, create_api_key
import config as Config
from database import save_scan_result, get_all_scans, get_scan_by_id, get_dashboard_stats
from email_analyzer import read_eml_file, split_headers_body, parse_headers, analyze_headers

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)

@api_bp.route('/docs')
def api_docs():
    return render_template('api_docs.html')

@api_bp.route('/keys', methods=['POST'])
def generate_key():
    admin_token = Config.API_KEY_ADMIN_TOKEN
    if not admin_token:
        return jsonify({'error': 'API key administration is not configured'}), 503
    provided_token = request.headers.get('X-Admin-Token')
    if not provided_token:
        return jsonify({'error': 'Admin token required'}), 401
    if not hmac.compare_digest(provided_token, admin_token):
        return jsonify({'error': 'Invalid admin token'}), 403
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    name = data.get('name', 'Default')
    permissions = data.get('permissions', ['read', 'write'])
    if not user_id:
        return jsonify({'error': 'user_id required'}), 400
    try:
        result = create_api_key(user_id, name, permissions)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    return jsonify(result), 201

@api_bp.route('/analyze', methods=['POST'])
@require_api_key('write')
def analyze_email():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.eml'):
        return jsonify({'error': 'Invalid file type. Only .eml files allowed'}), 400
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    stored_filename = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(Config.UPLOAD_FOLDER, stored_filename)

    file.save(filepath)
    
    content = read_eml_file(filepath)
    if not content:
        return jsonify({'error': 'Error reading file'}), 500
    
    header, body, h_lines, b_lines = split_headers_body(content)
    headers = parse_headers(header)
    analysis = analyze_headers(headers, body)
    scan_id = save_scan_result(
        filename=filename,
        stored_filename=stored_filename,
        file_size=os.path.getsize(filepath),
        analysis=analysis,
        headers=headers,
        body_preview=body[:300]
    )
    analysis['scan_id'] = scan_id
    analysis['filename'] = filename
    analysis['analyzed_at'] = datetime.now().isoformat()
    
    return jsonify(analysis)

@api_bp.route('/history', methods=['GET'])
@require_api_key('read')
def get_history():
    limit = request.args.get('limit', 50, type=int)
    if limit < 1 or limit > Config.MAX_HISTORY_RECORDS:
        return jsonify({
            'error': f'limit must be between 1 and {Config.MAX_HISTORY_RECORDS}'
        }), 400
    scans = get_all_scans(limit)
    return jsonify({'scans': scans})

@api_bp.route('/scan/<int:scan_id>', methods=['GET'])
@require_api_key('read')
def get_scan(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    if scan.get('findings'):
        scan['findings'] = json.loads(scan['findings'])
    if scan.get('headers_analyzed'):
        scan['headers_analyzed'] = json.loads(scan['headers_analyzed'])
    
    return jsonify({'scan': scan})

@api_bp.route('/dashboard', methods=['GET'])
@require_api_key('read')
def get_dashboard():
    stats = get_dashboard_stats()
    return jsonify({'stats': stats})

@api_bp.route('/scan/<int:scan_id>', methods=['DELETE'])
@require_api_key('write')
def delete_scan(scan_id):
    from database import delete_scan as delete_scan_db
    deleted = delete_scan_db(scan_id)
    if not deleted:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify({'message': 'Scan deleted successfully'})

@api_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })