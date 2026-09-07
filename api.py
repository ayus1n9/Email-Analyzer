from flask import Blueprint, request, jsonify, render_template
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
from auth import require_api_key, create_api_key
from database import save_scan_result, get_all_scans, get_scan_by_id, get_dashboard_stats
from email_analyzer import read_eml_file, split_headers_body, parse_headers, analyze_headers

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

@api_bp.route('/docs')
def api_docs():
    return render_template('api_docs.html')

@api_bp.route('/keys', methods=['POST'])
def generate_key():
    data = request.get_json()
    user_id = data.get('user_id')
    name = data.get('name', 'Default')
    if not user_id:
        return jsonify({'error': 'user_id required'}), 400
    result = create_api_key(user_id, name)
    return jsonify(result)

@api_bp.route('/analyze', methods=['POST'])
@require_api_key
def analyze_email():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.eml'):
        return jsonify({'error': 'Invalid file type. Only .eml files allowed'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join('uploads', filename)
    file.save(filepath)
    
    content = read_eml_file(filepath)
    if not content:
        return jsonify({'error': 'Error reading file'}), 500
    
    header, body, h_lines, b_lines = split_headers_body(content)
    headers = parse_headers(header)
    analysis = analyze_headers(headers, body)
    scan_id = save_scan_result(
        filename=filename,
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
@require_api_key
def get_history():
    limit = request.args.get('limit', 50, type=int)
    scans = get_all_scans(limit)
    return jsonify({'scans': scans})

@api_bp.route('/scan/<int:scan_id>', methods=['GET'])
@require_api_key
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
@require_api_key
def get_dashboard():
    stats = get_dashboard_stats()
    return jsonify({'stats': stats})

@api_bp.route('/scan/<int:scan_id>', methods=['DELETE'])
@require_api_key
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