# Changelog

All notable changes to SecuraMail are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-08-01

### 🎉 Initial Production Release

This is the first stable release of SecuraMail — a complete, security-hardened, feature-complete cybersecurity email threat analysis platform.

---

### Added

#### Core Platform
- Django 6.0.7 application with PostgreSQL backend
- Google OAuth 2.0 integration with PKCE and state validation
- Gmail API integration with delta-sync via History ID tracking
- Background threading for non-blocking email synchronization and analysis

#### Security Analysis Pipeline
- Multi-layer `EmailPipeline` orchestrating ML, URL, and ATAE analysis in sequence
- Deterministic `RiskEngine` implementing a weighted signal scoring model (0–100 score, SAFE/SUSPICIOUS/PHISHING labels)
- Sender Reputation Engine for domain-level trust scoring

#### Machine Learning Engine
- Local XGBoost phishing classifier (`phishing_model.pkl`) with 26 engineered behavioral features
- TF-IDF vectorizer with bigram support (`vectorizer.pkl`)
- Email category classifier (`category_model.pkl`) for 16-class categorization
- `FeatureExtractor` with link mismatch and homoglyph detection
- False-positive mitigation for legitimate marketing and banking emails

#### URL Analysis
- Google Safe Browsing API integration for real-time URL threat lookup
- VirusTotal API integration for URL and hash reputation
- Structural heuristics: IP URLs, shorteners, suspicious TLDs, punycode, typosquatting
- Link mismatch detection (visible text vs. actual destination)
- Cyrillic homoglyph URL detection

#### Attachment Threat Analysis Engine (ATAE)
- `ATAEOrchestrator` entry point with email-only invariant enforcement
- `TriageRouter` using magic bytes and MIME type detection
- `ArchiveAnalyzer`: ZIP slip, archive bombs, recursive nesting
- `ExecutableAnalyzer`: PE/ELF header parsing, UPX detection, suspicious imports
- `OfficeAnalyzer`: VBA macros, OLE2 autoexec, OOXML external templates
- `PDFAnalyzer`: Embedded JavaScript, OpenAction, suspicious producers
- `ScriptAnalyzer`: PowerShell encoded commands, AMSI bypass, eval/exec patterns
- `ImageAnalyzer`: Appended binary detection, entropy anomalies, malformed headers
- `YaraEngine`: Custom YARA rule signature scanning (MockYaraProvider in testing)
- `EntropyService`: Shannon entropy calculation for packing/encryption detection
- `ThreatIntelService`: VirusTotal hash-based IoC lookups

#### Gemini AI Integration
- `GeminiService` using `google-genai` SDK (migrated from deprecated `google.generativeai`)
- On-demand threat explanation via Gemini Flash model
- Structured JSON response parsing with caching in `EmailAnalysis`
- Deterministic fallback explanation on API failure or timeout (2 retries)

#### Reporting
- Forensic PDF generation using ReportLab with full threat findings
- Downloadable per-email security report with ownership enforcement

#### Frontend
- Django Templates with Tailwind CSS responsive design
- Threat dashboard with aggregated security metrics
- Categorized inbox with risk-label color coding
- Email detail view with full forensic breakdown
- Attachment preview with MIME-safe content delivery

#### Database Models
- `Profile`, `ConnectedAccount`, `EmailMessage`, `Attachment`
- `EmailAnalysis`, `SyncJob`, `AuditLog`, `LinkAnalysis`, `ThreatAnalysis`

---

### Security Hardening

- **CSRF Protection**: Global middleware + `@require_POST` on all state-changing endpoints
- **Open Redirect Remediation**: `safe_redirect()` utility with host validation, replacing raw `HTTP_REFERER` usage
- **DOM XSS Prevention**: `e()` JavaScript sanitizer for Gemini AI output before `innerHTML` insertion
- **OAuth Token Encryption**: `django-encrypted-model-fields` protecting all OAuth credentials at rest
- **Rate Limiting**: `@rate_limit_view` on login (5/min), register (3/min), password reset (2/min), OAuth (10/min)
- **Authorization**: All ORM queries strictly bounded to `user=request.user`
- **Attachment Access Control**: File serving with ownership verification before response

---

### Testing
- 83 tests across pipeline, CSRF, redirect, production, and ATAE subsystems
- 12 CSRF attack vectors tested
- 12 open redirect attack vectors tested
- 60+ ATAE unit tests covering all analyzers and edge cases
- ML pipeline integration tests with mocked external APIs

---

### Repository
- Professional `README.md`, `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`
- `SECUREMAIL_MASTER_DOCUMENTATION.md` — Complete technical architecture reference
- `SecureMail_Attachment_Threat_Analysis_Engine_SDS.md` — ATAE design specification
- `PROJECT_CONTEXT.md` — Engineering handoff document for future development
- Scientific validation scripts (`run_scientific_validation.py`, `run_adversarial_testing.py`, `run_full_validation_suite.py`)
- Cleaned `.gitignore` and minimal `requirements.txt`
- Rotated log files and all development artifacts removed

---

### Removed
- Deprecated `google.generativeai` SDK dependency (replaced by `google-genai`)
- `SecureMail/views_backup.py` — obsolete backup file
- CSV export functionality (security remediation)
- All temporary patch scripts, audit artifacts, and debug utilities
- Unused `import csv` statement from views

---

## Future Releases

See [Future Roadmap](README.md#future-roadmap) for planned features.
