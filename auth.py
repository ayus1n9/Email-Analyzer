import secrets
import hashlib
import json
from typing import Optional, Dict
import sqlite3
import config as Config

DATABASE_PATH = Config.DATABASE_PATH

def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

def create_api_key(
    user_id: str,
    name: str,
    permissions: Optional[list[str]] = None
) -> Dict:
    api_key = generate_api_key()
    hashed_key = hash_api_key(api_key)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            hashed_key TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            permissions TEXT DEFAULT '["read", "write"]'
        )
    ''')
    if permissions is None:
        permissions = ['read', 'write']
    elif not isinstance(permissions, list):
        raise ValueError('Permissions must be a list')
    allowed_permissions = {'read', 'write'}
    if not set(permissions).issubset(allowed_permissions):
        raise ValueError('Invalid permissions')
    cursor.execute('''
        INSERT INTO api_keys (user_id, name, hashed_key, permissions)
        VALUES (?, ?, ?, ?)
    ''', (
        user_id,
        name,
        hashed_key,
        json.dumps(sorted(set(permissions)))
    ))
    conn.commit()
    conn.close()
    return {
        'api_key': api_key,
        'message': 'Save this API key! You won\'t see it again.'
    }

def validate_api_key(api_key: str) -> Optional[Dict]:
    hashed_key = hash_api_key(api_key)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM api_keys
        WHERE hashed_key = ? AND is_active = 1
    ''', (hashed_key,))
    row = cursor.fetchone()
    if row:
        cursor.execute('''
            UPDATE api_keys SET last_used = CURRENT_TIMESTAMP
            WHERE hashed_key = ?
        ''', (hashed_key,))
        conn.commit()
        result = dict(row)
        result['permissions'] = json.loads(result['permissions']) if isinstance(result['permissions'], str) else result['permissions']
        conn.close()
        return result
    conn.close()
    return None

def revoke_api_key(api_key: str) -> bool:
    hashed_key = hash_api_key(api_key)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE api_keys SET is_active = 0
        WHERE hashed_key = ?
    ''', (hashed_key,))
    conn.commit()
    affected = cursor.rowcount > 0
    conn.close()
    return affected

def require_api_key(permission=None):
    from functools import wraps
    from flask import request, jsonify

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
            user = validate_api_key(api_key)
            if not user:
                return jsonify({'error': 'Invalid or inactive API key'}), 401
            if permission and permission not in user.get('permissions', []):
                return jsonify({'error': 'Insufficient permissions'}), 403
            request.api_user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator