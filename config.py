import os

URGENCY_KEYWORDS = [
    'urgent', 'immediate', 'action required', 'asap',
    'important', 'critical', 'attention needed', 'time sensitive',
    'respond now', 'today', 'deadline', 'expire', 'expiring'
]

FINANCIAL_KEYWORDS = [
    'bank', 'payment', 'invoice', 'credit card', 'debit',
    'transaction', 'verify account', 'security alert',
    'funds', 'wire transfer', 'refund', 'deposit', 'withdrawal',
    'account balance', 'overdraft', 'charge', 'billing'
]

THREAT_KEYWORDS = [
    'suspended', 'terminated', 'locked', 'deactivated',
    'security breach', 'unauthorized access', 'compromised',
    'hacked', 'violation', 'suspicious activity', 'fraud alert',
    'blocked', 'limited', 'restricted', 'closed'
]

IMPERSONATION_KEYWORDS = [
    'support', 'admin', 'security', 'service', 'account',
    'helpdesk', 'team', 'billing', 'payments', 'verification',
    'review', 'monitoring', 'alert', 'notice'
]

COMPANY_NAMES = [
    'paypal', 'amazon', 'apple', 'google', 'microsoft',
    'netflix', 'spotify', 'adobe', 'dropbox', 'facebook',
    'instagram', 'twitter', 'linkedin', 'bank', 'chase',
    'wells fargo', 'bank of america', 'citibank', 'fedex', 'ups'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorte.st', 'clicky.me', 't.co',
    'tr.im', 'v.gd', 'tiny.cc', 'cli.gs', 'url4.eu',
    'short.link', 'cutt.ly', 'tinyurl.com', 'rb.gy', 'shorturl.at'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.top', '.xyz',
    '.club', '.work', '.date', '.download', '.buzz',
    '.loan', '.win', '.stream', '.bid', '.trade',
    '.webcam', '.science', '.party', '.racing', '.accountant'
]

SUSPICIOUS_DOMAINS = [
    'secure', 'verify', 'update', 'confirm', 'validate',
    'authenticate', 'signin', 'login', 'account', 'security',
    'alert', 'notice', 'warning', 'important', 'urgent'
]

FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'protonmail.com', 'mail.com', 'yandex.com', 'aol.com',
    'zoho.com', 'gmx.com', 'tutanota.com', 'icloud.com'
]

DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.js', '.jar', '.vbs', '.bat',
    '.cmd', '.com', '.pif', '.wsf', '.hta', '.msi',
    '.ps1', '.py', '.rb', '.pl', '.sh', '.cpl', '.ad'
]

DAYS_THRESHOLD_OLD = 30
DAYS_THRESHOLD_VERY_OLD = 90
MAX_HOPS_NORMAL = 5
MAX_HOPS_SUSPICIOUS = 10
MAX_URLS_TO_DISPLAY = 10
MAX_SUSPICIOUS_URLS = 5
DATABASE_PATH = os.environ.get(
    'DATABASE_PATH',
    'data/email_analysis.db'
)

MAX_HISTORY_RECORDS = 1000
BATCH_UPLOAD_FOLDER = 'uploads/batch'
MAX_BATCH_FILES = 50
ALLOWED_BATCH_EXTENSIONS = {'eml'}
DEFAULT_HISTORY_LIMIT = 50
DAYS_FOR_TRENDING = 7
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'eml'}
HOST = os.environ.get('FLASK_HOST', '127.0.0.1')
PORT = int(os.environ.get('FLASK_PORT', '5000'))
FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
SECRET_KEY = os.environ.get('SECRET_KEY')
API_KEY_ADMIN_TOKEN = os.environ.get('API_KEY_ADMIN_TOKEN')
WEB_ADMIN_TOKEN = os.environ.get('WEB_ADMIN_TOKEN')

class Config:
    SECRET_KEY = SECRET_KEY
    API_KEY_ADMIN_TOKEN = API_KEY_ADMIN_TOKEN
    WEB_ADMIN_TOKEN = WEB_ADMIN_TOKEN
    UPLOAD_FOLDER = UPLOAD_FOLDER
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH
    ALLOWED_EXTENSIONS = ALLOWED_EXTENSIONS
    DEBUG = FLASK_ENV == 'development'
    HOST = HOST
    PORT = PORT