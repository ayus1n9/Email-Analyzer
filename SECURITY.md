# Security Policy

## 🔐 Security Features

| Feature | Tool | Status |
|---------|------|--------|
| SAST (Code Scanning) | Bandit | ✅ Active |
| SCA (Dependency Scanning) | Safety, Dependabot | ✅ Active |
| Secrets Detection | TruffleHog | ✅ Active |
| Dependency Updates | Dependabot | ✅ Active |

## 📋 Supported Versions

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| Latest | ✅ Yes | ✅ Yes |
| v0.5.0  | ✅ Yes | ✅ Yes |
| v0.4.0  | ✅ Yes | ✅ Yes |
| v0.3.0  | ✅ Yes | ✅ Yes |
| v0.2.0  | ✅ Yes | ✅ Yes |
| v0.1.0  | ✅ Yes | ✅ Yes |

## 🛡️ Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. Email: [your-security-email]
3. Provide detailed steps to reproduce

## 🔒 Security Best Practices

This project follows these security best practices:

- ✅ **SAST**: Code scanned for vulnerabilities with Bandit
- ✅ **SCA**: Dependencies checked for known vulnerabilities with Safety
- ✅ **Secrets Detection**: Code scanned for hardcoded secrets with TruffleHog
- ✅ **Dependency Updates**: Automated updates with Dependabot
- ✅ **Container Security**: Docker images scanned with Trivy
- ✅ **Input Validation**: File uploads are validated before processing
- ✅ **Non-root User**: Docker containers run as non-root

## 📊 Security Status

![Security Scan](https://img.shields.io/badge/Security%20Scan-Passing-brightgreen)
![Dependency Status](https://img.shields.io/badge/Dependencies-Updated-brightgreen)
![SAST](https://img.shields.io/badge/SAST-Passing-brightgreen)
![Secrets Check](https://img.shields.io/badge/Secrets-Not%20Found-brightgreen)