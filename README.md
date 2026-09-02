# 📧 Email Header Analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-13%20passing-brightgreen.svg)](https://github.com/ayus1n9/email-header-analyzer)

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

## 📋 Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/ayus1n9/email-analyzer.git

# Navigate to project directory
cd email-header-analyzer

# (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
