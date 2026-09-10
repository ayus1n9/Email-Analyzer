# 🔐 Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes    |
| 0.x.x   | ❌ No     |

## Reporting a Vulnerability

**Do NOT open public issues.** If you discover a security vulnerability, please report it privately by opening a GitHub Security Advisory.

## Security Features

| Feature | Tool | Status |
|---------|------|--------|
| SAST | Bandit | ✅ Active |
| SCA | Safety, Dependabot | ✅ Active |
| Secrets Detection | TruffleHog | ✅ Active |
| Container Scanning | Trivy | ✅ Active |

## Security Best Practices

- ✅ No hardcoded secrets
- ✅ Input validation
- ✅ Non-root Docker user
- ✅ Regular dependency updates
- ✅ CI/CD security gates

## 📊 Security Badges

![Security Scan](https://img.shields.io/badge/Security%20Scan-Passing-brightgreen)
![SAST](https://img.shields.io/badge/SAST-Passing-brightgreen)
![SCA](https://img.shields.io/badge/SCA-No%20Vulnerabilities-brightgreen)