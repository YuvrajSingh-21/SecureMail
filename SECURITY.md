# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Actively supported |

## Security Features

SecureMail implements multiple defense-in-depth security controls:

### Authentication
- Django's native authentication with PBKDF2 password hashing.
- All protected views enforce `@login_required`.
- Brute-force protection via `@rate_limit_view` (IP-based, 3–10 requests/minute) on all authentication endpoints including login, registration, password reset, and OAuth callbacks.

### Google OAuth
- OAuth 2.0 with PKCE (`code_verifier` + `state` token) to prevent CSRF on the callback.
- `state` parameter is validated from the server-side session on every callback.
- OAuth tokens (access and refresh) are **encrypted at rest** using `django-encrypted-model-fields` with a 32-byte `FIELD_ENCRYPTION_KEY`.
- Token revocation calls Google's API on disconnect, invalidating the token server-side.

### Encryption
- OAuth tokens use symmetric field-level encryption.
- `FIELD_ENCRYPTION_KEY` must be a securely generated 32-byte key, stored in environment variables only.
- Passwords are hashed using Django's PBKDF2-SHA256 with a per-user salt.

### Attachment Security
- **ATAE analyzes ONLY attachments from received emails.** There is no public file upload endpoint.
- Attachment downloads require ownership verification (`user=request.user`).
- Dangerous MIME types are forced as `Content-Disposition: attachment` downloads only.
- Attachment files are stored outside the web root in `media/` which should be protected by the reverse proxy in production.

### CSRF Protection
- Django's global CSRF middleware is active.
- All state-changing endpoints (email deletion, starring, sync) additionally require `@require_POST`, preventing cross-site GET-based state manipulation.

### Rate Limiting
- Login: 5 requests/minute per IP
- Registration: 3 requests/minute per IP
- Password Reset: 2 requests/minute per IP
- OAuth Initiation/Callback: 10 requests/minute per IP

> **Note**: Rate limiting uses `LocMemCache` in development. In production with multiple workers, a centralized cache backend (Redis or Memcached) is required for global enforcement.

### Open Redirect Prevention
- All redirects use the `safe_redirect()` utility which validates URLs using Django's `url_has_allowed_host_and_scheme`, rejecting external and protocol-relative URLs.
- The raw `HTTP_REFERER` header is never trusted directly for redirects.

### XSS Protection
- Django template auto-escaping prevents server-rendered XSS.
- Dynamic JavaScript DOM insertion of AI-generated content is sanitized through a dedicated `e()` escaper function before `innerHTML` assignment.

### Security Headers (Production)
When `DEBUG=False`, the following are automatically enabled:
- `SECURE_HSTS_SECONDS`: HTTP Strict Transport Security
- `SECURE_SSL_REDIRECT`: Forces HTTPS
- `SESSION_COOKIE_SECURE` + `CSRF_COOKIE_SECURE`: Secure cookie flags
- `SESSION_COOKIE_HTTPONLY`: HttpOnly session cookies

### Audit Logging
- Sensitive user actions (login, logout, email deletion, Gmail connection/disconnection) are recorded in an immutable `AuditLog` database table including IP address and timestamp.
- Logs intentionally exclude OAuth tokens, passwords, API keys, and raw email bodies.

## Privacy Notes
- SecureMail processes email metadata and content locally for analysis.
- Email content summaries are sent to the Google Gemini API only when the user explicitly requests an AI explanation.
- No email data is sold, shared with third parties, or used for training purposes by SecureMail.
- Users can disconnect their Gmail account at any time, which revokes OAuth tokens and removes all stored credentials.

## Responsible Disclosure

We take security vulnerabilities seriously. If you discover a security issue in SecureMail, please follow responsible disclosure:

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send a detailed report to the project maintainer via GitHub.
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fixes (optional)
3. **Do not include** actual credentials, tokens, or user data in your report.

### Response Process
- We will acknowledge receipt within **48 hours**.
- We will provide an initial assessment within **5 business days**.
- We will work to release a fix within **30 days** for confirmed vulnerabilities.
- We will credit reporters in the release notes (unless anonymity is requested).

### Scope
In-scope for reports:
- Authentication bypass
- Authorization failures (accessing other users' emails)
- CSRF vulnerabilities
- XSS vulnerabilities
- Open redirect vulnerabilities
- SQL injection
- Sensitive data exposure
- ATAE bypass that enables arbitrary file analysis

Out of scope:
- Denial of service via resource exhaustion
- Social engineering
- Issues requiring physical access
- Vulnerabilities in third-party APIs (VirusTotal, Google, Gemini) — report these to the respective vendor
