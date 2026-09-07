import requests
import re
from typing import Optional, Dict, List
from urllib.parse import urlparse

def check_virustotal(url: str, api_key: str) -> Dict:
    if not api_key:
        return {'error': 'VirusTotal API key not configured'}
    try:
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            data={'url': url},
            headers={'x-apikey': api_key},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            return {
                'url': url,
                'status': 'success',
                'analysis': data.get('data', {})
            }
        else:
            return {'error': f'VirusTotal API error: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}

def check_ip_reputation(ip: str, api_key: str) -> Dict:
    if not api_key:
        return {'error': 'AbuseIPDB API key not configured'}
    try:
        response = requests.get(
            f'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip,
                'status': 'success',
                'abuse_confidence_score': data['data'].get('abuseConfidenceScore', 0),
                'total_reports': data['data'].get('totalReports', 0),
                'is_suspicious': data['data'].get('abuseConfidenceScore', 0) > 50
            }
        else:
            return {'error': f'AbuseIPDB API error: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}

def whois_lookup(domain: str) -> Dict:
    try:
        response = requests.get(
            f'https://whois.verisign-grs.com/{domain}',
            timeout=10
        )
        if response.status_code == 200:
            data = response.text
            creation_date = re.search(r'Creation Date: (.+)', data)
            expiry_date = re.search(r'Registry Expiry Date: (.+)', data)
            registrar = re.search(r'Registrar: (.+)', data)
            return {
                'domain': domain,
                'status': 'success',
                'creation_date': creation_date.group(1) if creation_date else None,
                'expiry_date': expiry_date.group(1) if expiry_date else None,
                'registrar': registrar.group(1) if registrar else None,
                'days_old': None  # Would need to calculate
            }
        else:
            return {'error': 'WHOIS lookup failed'}
    
    except Exception as e:
        return {'error': str(e)}
    
def send_slack_alert(webhook_url: str, message: Dict) -> bool:
    try:
        risk = message.get('overall_risk', 'unknown').upper()
        emoji = '🔴' if risk == 'HIGH' else '🟡' if risk == 'MEDIUM' else '🟢'
        payload = {
            'text': f'{emoji} *Email Analysis Alert*',
            'attachments': [{
                'color': 'danger' if risk == 'HIGH' else 'warning' if risk == 'MEDIUM' else 'good',
                'fields': [
                    {'title': 'Filename', 'value': message.get('filename', 'Unknown'), 'short': True},
                    {'title': 'Risk Level', 'value': risk, 'short': True},
                    {'title': 'Risk Score', 'value': f"{message.get('risk_score', 0)}/10", 'short': True},
                    {'title': 'Findings', 'value': str(message.get('total_findings', 0)), 'short': True},
                    {'title': 'Details', 'value': message.get('summary', 'No details'), 'short': False}
                ]
            }]
        }
        response = requests.post(webhook_url, json=payload, timeout=30)
        return response.status_code == 200
    
    except Exception:
        return False