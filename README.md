# Email Header Analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-13%20passing-brightgreen.svg)](https://github.com/ayus1n9/email-header-analyzer)
[![Security Scan](https://img.shields.io/badge/Security%20Scan-Passing-brightgreen)](https://github.com/ayus1n9/email-header-analyzer/actions)
[![Dependency Status](https://img.shields.io/badge/Dependencies-Updated-brightgreen)](https://github.com/ayus1n9/email-header-analyzer/actions)
[![SAST](https://img.shields.io/badge/SAST-Passing-brightgreen)](https://github.com/ayus1n9/email-header-analyzer/actions)

> **A Python tool to parse and analyze email headers (.eml files) for phishing detection, spoofing attempts, and security threats.**

---

## 🔍 What It Does

Email Header Analyzer parses `.eml` files and performs comprehensive security analysis including:

- ✅ **File Processing** - Read .eml files with error handling
- ✅ **Header Parsing** - Parse headers into structured dictionary
- ✅ **Security Analysis** - Detect phishing indicators and spoofing
- ✅ **Risk Assessment** - Generate detailed reports with severity levels
- ✅ **Unit Tests** - 13 passing test cases

---

## 🚨 Security Checks Performed

| Check | Description | Severity |
|-------|-------------|----------|
| **From vs Return-Path** | Domain mismatch detection | 🔴 High |
| **SPF Authentication** | Sender Policy Framework check | 🔴 High |
| **DKIM Authentication** | DomainKeys Identified Mail check | 🔴 High |
| **Received Chain** | Hop count and suspicious patterns | 🟡 Medium |
| **Date Anomaly** | Future dates or very old emails | 🟡 Medium |
| **Critical Headers** | Missing required headers | 🟡 Medium |

---

## 🔌 REST API

Email Header Analyzer provides a complete REST API for integration with other tools.

### API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/keys` | Generate API key | ❌ No |
| POST | `/api/v1/analyze` | Analyze email | ✅ Yes |
| GET | `/api/v1/history` | Get scan history | ✅ Yes |
| GET | `/api/v1/scan/{id}` | Get specific scan | ✅ Yes |
| DELETE | `/api/v1/scan/{id}` | Delete scan | ✅ Yes |
| GET | `/api/v1/dashboard` | Get statistics | ✅ Yes |
| GET | `/api/v1/health` | Health check | ❌ No |

### Interactive API Documentation

Access the API documentation at: http://localhost:5000/api/v1/docs

## 📋 Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/ayus1n9/email-analyzer.git

# Navigate to project directory
cd email-analyzer

# (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
