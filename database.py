import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

DATABASE_PATH = 'data/email_analysis.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_size INTEGER,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            overall_risk TEXT,
            risk_score INTEGER,
            total_findings INTEGER,
            max_severity TEXT,
            headers_analyzed TEXT,
            findings TEXT,
            email_body_preview TEXT
        )
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_analyzed_at ON scans(analyzed_at)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_overall_risk ON scans(overall_risk)
    ''')
    conn.commit()
    conn.close()

def save_scan_result(filename: str, file_size: int, analysis: Dict, headers: Dict, body_preview: str = '') -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    summary = analysis.get('summary', {})
    cursor.execute('''
        INSERT INTO scans (
            filename, file_size, overall_risk, risk_score,
            total_findings, max_severity, headers_analyzed, findings,
            email_body_preview
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        filename,
        file_size,
        summary.get('overall_risk', 'unknown'),
        summary.get('risk_score', 0),
        summary.get('total_findings', 0),
        summary.get('max_severity', 'low'),
        json.dumps(list(headers.keys())),
        json.dumps(analysis.get('findings', [])),
        body_preview[:500]  
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_all_scans(limit: int = 100) -> List[Dict]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scans
        ORDER BY analyzed_at DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id: int) -> Optional[Dict]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_dashboard_stats() -> Dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as total FROM scans')
    total_scans = cursor.fetchone()['total']
    cursor.execute('''
        SELECT overall_risk, COUNT(*) as count
        FROM scans
        GROUP BY overall_risk
    ''')
    risk_distribution = {row['overall_risk']: row['count'] for row in cursor.fetchall()}
    cursor.execute('SELECT AVG(risk_score) as avg_score FROM scans')
    avg_score = cursor.fetchone()['avg_score'] or 0
    cursor.execute('SELECT * FROM scans ORDER BY analyzed_at DESC LIMIT 1')
    latest = dict(cursor.fetchone()) if cursor.fetchone() else None
    cursor.execute('''
        SELECT DATE(analyzed_at) as date, COUNT(*) as count
        FROM scans
        WHERE analyzed_at >= DATE('now', '-7 days')
        GROUP BY DATE(analyzed_at)
        ORDER BY date DESC
    ''')
    daily_scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {
        'total_scans': total_scans,
        'risk_distribution': risk_distribution,
        'average_risk_score': round(avg_score, 1),
        'latest_scan': latest,
        'daily_scans': daily_scans
    }

def delete_scan(scan_id: int) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_all_scans() -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans')
    count = cursor.rowcount
    conn.commit()
    conn.close()
    return count