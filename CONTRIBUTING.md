```markdown
# 🤝 Contributing to Email Header Analyzer

Thank you for your interest in contributing!

## 🚀 Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/email-analyzer.git
   cd email-analyzer
3. Create a branch:
    git checkout -b feature/your-feature

🛠️ Development Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

🧪 Testing
python -m unittest tests/test_analyzer.py -v

🔒 Security

    No hardcoded secrets – use environment variables

    All code must pass Bandit checks: bandit -r .

    Dependencies must pass Safety checks: safety check -r requirements.txt

📝 Pull Request Process

    Update tests for new functionality

    Ensure all GitHub Actions checks pass

    Submit PR with clear description

    Wait for review

🛡️ Reporting Vulnerabilities

Do NOT open public issues. Email: security@email-analyzer.com
📄 License

By contributing, you agree your contributions will be licensed under the MIT License.