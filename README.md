# 📧 Email Header Analyzer

A comprehensive Python tool to parse and analyze email headers (.eml files) for phishing indicators and security threats.

## 🚀 Features

### Phase 1: File Processing
- Read .eml files with error handling
- Split headers from email body
- Display email statistics

### Phase 2: Header Parsing
- Parse headers into structured dictionary
- Handle folded header lines
- Manage duplicate headers (e.g., multiple Received entries)
- Normalize header keys (case-insensitive)

### Phase 3: Security Analysis
- Check "From" vs "Return-Path" domain mismatch
- Analyze SPF/DKIM authentication results
- Track "Received" chain for unusual hops
- Check for date anomalies
- Generate risk assessment with severity levels

### Phase 4: Report Generation
- Comprehensive security report
- Risk level assessment (Low/Medium/High)
- Recommended actions
- Detailed findings with explanations

## 📋 Requirements

- Python 3.6 or higher- No external dependencies (uses only standard library)

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/email-header-analyzer.git

# Navigate to project directory
cd email-header-analyzer

# (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate