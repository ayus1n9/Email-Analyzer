# Email Header Analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen.svg)](https://github.com/ayus1n9/email-analyzer)
[![Security Scan](https://img.shields.io/badge/Security%20Scan-Passing-brightgreen)](https://github.com/ayus1n9/email-analyzer/actions)
[![Dependency Status](https://img.shields.io/badge/Dependencies-Updated-brightgreen)](https://github.com/ayus1n9/email-analyzer/actions)
[![SAST](https://img.shields.io/badge/SAST-Passing-brightgreen)](https://github.com/ayus1n9/email-analyzer/actions)

> **A Python tool to parse and analyze email headers (.eml files) for phishing detection, spoofing attempts, and security threats.**

---

## 🔍 What It Does

Email Header Analyzer parses `.eml` files and performs security analysis including:

- ✅ **File Processing** - Read `.eml` files with error handling
- ✅ **Header Parsing** - Parse headers into a structured representation
- ✅ **Security Analysis** - Detect phishing indicators and spoofing attempts
- ✅ **Authentication Checks** - Inspect SPF and DKIM results when present
- ✅ **URL Analysis** - Check links for suspicious indicators
- ✅ **Risk Assessment** - Generate findings with severity levels
- ✅ **Web Dashboard** - Review scan history, reports, and statistics
- ✅ **Export Support** - Export scan results as JSON or PDF
- ✅ **REST API** - Integrate analysis and scan management into other tools
- ✅ **Test Coverage** - 30 automated tests

---

## 🚨 Security Checks Performed

| Check | Description | Severity |
|-------|-------------|----------|
| **From vs Return-Path** | Domain mismatch detection | 🔴 High |
| **SPF Authentication** | SPF result inspection | 🔴 High |
| **DKIM Authentication** | DKIM result inspection | 🔴 High |
| **Received Chain** | Hop count and suspicious patterns | 🟡 Medium |
| **Date Anomaly** | Future dates or very old emails | 🟡 Medium |
| **Reply-To Spoofing** | Detect suspicious Reply-To mismatches | 🔴 High |
| **Display-Name Impersonation** | Detect suspicious sender/display-name patterns | 🟡 Medium |
| **URL Analysis** | Inspect links for suspicious indicators | 🟡 Medium |
| **Critical Headers** | Check for missing or unusual headers | 🟡 Medium |

---

## 🔌 REST API

Email Header Analyzer provides a REST API for integration with other tools.

### API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/keys` | Generate API key | ✅ Admin token |
| POST | `/api/v1/analyze` | Analyze email | ✅ API key |
| GET | `/api/v1/history` | Get scan history | ✅ API key |
| GET | `/api/v1/scan/{id}` | Get specific scan | ✅ API key |
| DELETE | `/api/v1/scan/{id}` | Delete scan | ✅ API key |
| GET | `/api/v1/dashboard` | Get statistics | ✅ API key |
| GET | `/api/v1/health` | Health check | ❌ No |

API keys can be created with read and/or write permissions. Write operations require a key with the appropriate permission.

### Interactive API Documentation

Access the API documentation at:

`http://localhost:5000/api/v1/docs`

---

## 🔐 Web Security

The web interface is protected by authentication and CSRF controls.

- **Web authentication** protects dashboard, scan, history, export, and destructive actions.
- **CSRF protection** is applied to state-changing web requests.
- **Secure session settings** use HttpOnly and SameSite protections, with secure cookies enabled in production.
- **Security headers** include `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`.
- **Upload handling** uses safe filenames and validates stored-file paths.
- **Production configuration** fails closed when required security secrets are missing.

The web interface requires the `WEB_ADMIN_TOKEN` environment variable in production.

---

## 🛡️ DevSecOps & CI

The project includes automated security and quality checks in GitHub Actions, including:

- **Pytest** - Automated application and security regression tests
- **Bandit** - Python static security analysis
- **TruffleHog** - Verified secret scanning
- **Trivy** - Container/dependency vulnerability scanning
- **Docker build checks** - Validate the production container workflow

The repository is intended to be developed and tested with security checks running as part of the normal CI workflow.

---

## 📋 Requirements

- Python 3.6 or higher
- Dependencies listed in `requirements.txt`
- Docker (optional, for containerized deployment)

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/ayus1n9/email-analyzer.git

# Navigate to project directory
cd email-analyzer

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### Docker

The production container expects the required security secrets to be provided through environment variables.

```bash
docker build -t email-analyzer:latest .

docker run -p 5000:5000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY='replace-with-a-strong-secret' \
  -e WEB_ADMIN_TOKEN='replace-with-a-strong-admin-token' \
  email-analyzer:latest
```

Then open:

`http://localhost:5000`

### Python

```bash
git clone https://github.com/ayus1n9/email-analyzer.git
cd email-analyzer

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
gunicorn --bind 127.0.0.1:5000 app:app
```

For a production deployment, set the required security environment variables before starting the application.

---

## 🔑 API Key Setup

API key administration uses the `X-Admin-Token` header.

Set the API key bootstrap token before creating keys:

```bash
export API_KEY_ADMIN_TOKEN='replace-with-a-strong-token'
```

The `/api/v1/keys` endpoint can then be used with that admin token to create API keys with the required permissions.

Keep both the web admin token and API key admin token secret. Do not commit them to the repository.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 License

MIT License – See [LICENSE](LICENSE)

## ⭐ Support

⭐ Star this repo if you found it helpful!

[![GitHub stars](https://img.shields.io/github/stars/ayus1n9/email-analyzer.svg?style=social)](https://github.com/ayus1n9/email-analyzer/stargazers)