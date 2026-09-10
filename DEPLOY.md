# 🚀 Deployment Guide

## Quick Start (Docker)

```bash
docker build -t email-analyzer:latest .
docker run -d -p 5000:5000 \
  -e SECRET_KEY=$(openssl rand -base64 32) \
  -e FLASK_ENV=production \
  email-analyzer:latest
```

## Docker Compose
```bash
  docker compose up -d
  docker compose logs -f
  docker compose down
```

## Development
```bash
  git clone https://github.com/ayus1n9/email-analyzer.git
  cd email-analyzer
  python -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  gunicorn --bind 127.0.0.1:5000 app:app
```

## Environment Variables
  | Variable | Required |	Default |
  | -------- | -------- | ------- |
  | SECRET_KEY | ✅Yes | - |
  | FLASK_ENV | ❌	| production |
  | DATABASE_PATH | ❌ |	data/email_analysis.db |
  | VIRUSTOTAL_API_KEY | ❌ | - |
  | ABUSEIPDB_API_KEY | ❌ |	- |
  | SLACK_WEBHOOK_URL | ❌ |	- |

## Health Check
```bash
curl http://localhost:5000/api/v1/health