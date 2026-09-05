from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
from email_analyzer import (
    read_eml_file,
    split_headers_body,
    parse_headers,
    analyze_headers,
    generate_report
)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'eml'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import simpleSplit
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

@app.route('/export/json/<filename>')

def export_json(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
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
    if not REPORTLAB_AVAILABLE:
        return "PDF export requires reportlab. Install with: pip install reportlab", 501
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')

def upload_page():
    return render_template('upload.html')

@app.route('/analyze', methods=['POST'])

def analyze():
    try:
        if 'file' not in request.files:
            return "No file uploaded", 400
        
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400
        
        if not allowed_file(file.filename):
            return "Invalid file type. Please upload .eml file", 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
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
                             header_lines=h_lines,
                             body_lines=b_lines)
    
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return f"Error during analysis: {str(e)}", 500

@app.route('/api/analyze', methods=['GET'])

def api_info():
    return jsonify({
        'name': 'Email Header Analyzer API',
        'version': '1.0.0',
        'status': 'active',
        'endpoints': {
            'POST /api/analyze': 'Upload and analyze an .eml file',
            'GET /api/analyze': 'Show API information'
        },
        'usage': {
            'method': 'POST',
            'content_type': 'multipart/form-data',
            'parameters': {
                'file': {
                    'type': 'file',
                    'required': True,
                    'description': '.eml file to analyze'
                }
            },
            'example': 'curl -X POST -F "file=@email.eml" http://localhost:5000/api/analyze'
        }
    })

@app.route('/api/analyze', methods=['POST'])

def api_analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Please upload .eml file'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        content = read_eml_file(filepath)
        if not content:
            return jsonify({'error': 'Error reading file'}), 500
        
        header, body, h_lines, b_lines = split_headers_body(content)
        headers = parse_headers(header)
        analysis = analyze_headers(headers, body)
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'analysis': analysis
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)