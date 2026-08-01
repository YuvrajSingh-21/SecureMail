# Contributing to SecureMail

Thank you for your interest in contributing to SecureMail. This document outlines the process for contributing code, documentation, and bug reports.

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/SecureMail.git
cd SecureMail/Email_Phisher

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/SecureMail.git
```

### 2. Set Up Your Development Environment

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Fill in your test API keys and a test PostgreSQL database
python manage.py migrate
```

### 3. Create a Branch

Use a descriptive branch name following this convention:

| Type | Format | Example |
|---|---|---|
| Bug fix | `fix/short-description` | `fix/csrf-toggle-star` |
| New feature | `feature/short-description` | `feature/ms365-integration` |
| Documentation | `docs/short-description` | `docs/atae-readme-update` |
| Test | `test/short-description` | `test/redirect-edge-cases` |

```bash
git checkout -b fix/your-descriptive-branch-name
```

## Coding Style

- **Python**: Follow PEP 8. Keep functions focused and small.
- **Imports**: Group standard library → third-party → local imports.
- **Comments**: Explain *why*, not *what*. Preserve all existing docstrings.
- **No magic numbers**: Use named constants for thresholds and weights.
- **Security first**: Never log sensitive data (tokens, passwords, raw email bodies, API keys).

## Critical Rules

1. **Do not modify the ATAE email-only invariant.** ATAE must only analyze attachments received through emails inside SecureMail. Do not add public upload endpoints.
2. **Do not break existing security controls.** CSRF, safe redirects, rate limiting, and ownership enforcement are mandatory.
3. **Do not change models without a migration.** Always run `python manage.py makemigrations` after model changes.
4. **Do not hardcode secrets.** All secrets must come from environment variables.
5. **Read `PROJECT_CONTEXT.md` before modifying core modules.** It identifies sensitive files and call paths.

## Testing Requirements

All contributions must:

- Pass the existing 83-test suite: `python manage.py test`
- Include new tests for any new functionality
- Not reduce test coverage
- Pass `python manage.py check` with 0 issues

For security-related changes, also run:
```bash
python run_adversarial_testing.py
```

## Pull Request Process

1. **Update your branch** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run the full test suite** before submitting:
   ```bash
   python manage.py check
   python manage.py test
   ```

3. **Write a clear PR description** that includes:
   - What problem this solves
   - How it was tested
   - Any security considerations
   - Screenshots for UI changes

4. **Keep PRs focused.** One logical change per PR. Do not bundle unrelated fixes.

5. **Do not include** `.env`, database files, `media/`, or `staticfiles/` in your PR.

## Issue Reporting

When filing a bug report, please include:

- **Django version**: `python manage.py --version`
- **Python version**: `python --version`
- **Operating system**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Relevant log output** (sanitized — remove any tokens or personal data)

**Security vulnerabilities must NOT be reported as public issues.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Commit Messages

Write clear, concise commit messages:

```
type: short description (max 72 chars)

Optional longer description explaining WHY the change was made.
Reference issues: Fixes #123
```

Types: `fix`, `feat`, `docs`, `test`, `refactor`, `chore`

## Code Review

All PRs require at least one review before merging. Reviewers will check:

- Correctness and test coverage
- Security implications
- Compatibility with existing architecture
- Documentation completeness

## Questions?

Open a [GitHub Discussion](https://github.com/ORIGINAL_OWNER/SecureMail/discussions) for general questions about the codebase.
