# SecureMail Project Context

## 1. Project Purpose
SecureMail is a Django-based cybersecurity SaaS web application designed for advanced email threat detection. It enables users to connect their Google accounts via OAuth, automatically synchronizes their Gmail inboxes, and runs a comprehensive security analysis pipeline on incoming emails. This pipeline uses machine learning for heuristic detection, queries threat intelligence APIs for URL analysis, and utilizes a custom Attachment Threat Analysis Engine (ATAE) for deep file scanning. The system provides users with a threat dashboard, a categorized inbox, and AI-generated forensic explanations of security verdicts using the Gemini API.

## 2. Core Project Rules
- **Application Type**: SecureMail is fundamentally an email security and threat-analysis application.
- **Database**: PostgreSQL is the active database. Do NOT describe the active DB as SQLite.
- **Integration**: Google OAuth and Gmail integration are core, active components of the application.
- **Stability**: Existing working functionality must NOT be redesigned unnecessarily.
- **Security Fixes**: Any future security fixes must preserve existing functional behavior.
- **CRITICAL ATAE RULE**: The Attachment Threat Analysis Engine (ATAE) analyzes ONLY attachments received through emails inside SecureMail. ATAE is NOT a general-purpose arbitrary user-upload file scanner. Future development MUST preserve this invariant unless the project owner explicitly changes the requirement.

## 3. Current Technology Stack
- **Language**: Python 3.14
- **Web Framework**: Django 6.0.7
- **Database**: PostgreSQL (via psycopg2-binary)
- **Google Integration**: google-api-python-client, google-auth-oauthlib, google-auth-httplib2
- **AI Integration**: google-genai
- **Machine Learning**: scikit-learn, pandas, numpy, joblib
- **Security Libraries**: django-encrypted-model-fields, django-ratelimit, yara-python
- **Utilities**: reportlab, beautifulsoup4
- **Frontend**: Django Templates, Tailwind CSS, Lucide Icons

## 4. Current Architecture
- **Django Configuration**: `Email_Phisher/` contains the `settings.py`, `urls.py`, and WSGI/ASGI configurations.
- **SecureMail Application**: The core Django app residing in `SecureMail/`.
- **Models**: Defines users, profiles, OAuth accounts, email messages, attachments, threat analyses, and audit logs.
- **Views**: UI controllers (`views.py`), API endpoints (`api_views.py`), and Google Auth handlers (`google_auth_views.py`).
- **Services (`SecureMail/services/`)**:
  - `SyncManager`: Handles background fetching of Gmail messages.
  - `EmailPipeline`: Orchestrates the ML, URL, and ATAE analysis phases.
  - `GeminiService`: Communicates with Google's Gemini API for threat explanations.
  - `SafeBrowsingService` / `VirusTotalService`: URL threat intelligence.
- **Machine Learning (`SecureMail/ml/`)**: Contains offline-trained vectorizers/models (`model.joblib`, `vectorizer.joblib`) and extraction logic.
- **ATAE (`SecureMail/services/atae/`)**: The modular Attachment Threat Analysis Engine.
- **Templates**: Reside in `SecureMail/templates/`.
- **Security Utilities**: `utils.py` contains safe redirection logic.
- **Tests**: Spread across `tests.py`, `tests_production.py`, `tests_csrf.py`, `tests_redirect.py`.

## 5. Complete Email Processing Flow
1. **Google OAuth**: User initiates login/registration via Google OAuth. Tokens are exchanged and stored encrypted.
2. **Gmail Synchronization**: A background `SyncJob` (managed by `SyncManager`) fetches the latest unread or full history of emails using the Gmail API.
3. **Email Persistence**: Raw emails are parsed and saved to the PostgreSQL database as `EmailMessage` objects. Attachments are saved to the `media/` directory as `Attachment` objects.
4. **Analysis Pipeline**: The `EmailPipeline` takes over processing.
5. **ML Analysis**: Email headers and bodies are evaluated by the ML subsystem to generate a baseline prediction.
6. **URL Analysis**: Links are extracted and checked against VirusTotal and Google Safe Browsing APIs.
7. **Attachment Detection**: The pipeline checks if the `EmailMessage` has associated `Attachment` records.
8. **ATAE**: If attachments exist, they are passed to the ATAE for in-depth, non-execution forensic scanning.
9. **Final Threat Result**: Scores from ML, URLs, and ATAE are aggregated into a final Risk Score and Label (SAFE, SUSPICIOUS, PHISHING).
10. **Database Persistence**: The detailed forensic JSON report and verdict are saved to `EmailAnalysis`.
11. **Inbox/Dashboard**: The user views the processed emails in the UI.
12. **Gemini Explanation**: On-demand, the user clicks to generate a human-readable explanation of the threat verdict via the Gemini service (cached upon generation).
*Note*: The transition from Sync to Pipeline is handled by `SyncManager` calling `analyze_attachment_task` or the pipeline directly.

## 6. ATAE Architecture
**Invariant Reminder**: ATAE analyzes ONLY attachments received through emails inside SecureMail.
- **Entry Point**: `ATAEOrchestrator` (`SecureMail/services/atae/integration/orchestrator.py`).
- **Triage**: Uses magic bytes and MIME types (`SecureMail/services/atae/triage/`) to route files to specific analyzers.
- **Services**: 
  - **Entropy**: Calculates Shannon entropy to detect packed/encrypted payloads.
  - **Metadata**: Extracts EXIF/file properties.
  - **YARA**: Runs custom YARA rules against the file buffer.
  - **Threat Intelligence**: Checks VirusTotal for known IoCs (Hashes).
- **Analyzers**:
  - `ArchiveAnalyzer`: Scans ZIP/RAR/TAR contents recursively.
  - `ExecutableAnalyzer`: Parses PE/ELF headers and sections.
  - `OfficeAnalyzer`: Detects embedded macros (VBA).
  - `PDFAnalyzer`: Detects embedded JavaScript, OpenActions, and URI actions.
  - `ImageAnalyzer`: Checks for anomalies and steganography.
  - `ScriptAnalyzer`: Evaluates shell/JS scripts for obfuscation and dangerous functions.
- **Verdict Integration**: Analyzers return standardized `AnalyzerResult` objects, which the Orchestrator aggregates into a final `ATAEReport`.

## 7. Database Models
- `Profile`: Extends the User model with settings (timezone, alert preferences, tracking pixel blocking).
- `ConnectedAccount`: Stores encrypted Google OAuth `access_token` and `refresh_token`, plus history IDs.
- `EmailMessage`: Core record of an email (sender, subject, body, folder, risk score, ML label).
- `Attachment`: Belongs to an `EmailMessage`. Stores the file path, MIME type, hashes (MD5/SHA256), and ATAE scan status.
- `EmailAnalysis`: Stores the comprehensive forensic JSON report for an `EmailMessage`.
- `SyncJob`: Tracks background synchronization states.
- `AuditLog`: Immutable log of sensitive user actions.

## 8. Authentication and OAuth Flow
- **Local Authentication**: Standard Django auth is supported.
- **Google OAuth**: Users can log in or link Gmail via OAuth 2.0. The callback validates state/PKCE to prevent CSRF.
- **Token Handling**: Access and refresh tokens are retrieved via the `google-auth` library.
- **Encrypted Storage**: Tokens are immediately encrypted using `django-encrypted-model-fields` before database persistence.
- **Logout/Disconnect**: Users can revoke Google access, which actively calls Google's revocation endpoint and deletes local tokens.

## 9. Security Controls
- **CSRF**: Globally enforced. State-changing views (e.g., `delete_email`, `toggle_star`, `sync_gmail`) are strictly `@require_POST`.
- **Authorization**: All queries and actions are strictly bounded by `user=request.user`.
- **Encrypted Tokens**: OAuth tokens are encrypted at rest using a 32-byte `FIELD_ENCRYPTION_KEY`.
- **Safe Redirects**: Internal redirects utilize a `safe_redirect` utility relying on Django's `url_has_allowed_host_and_scheme` to prevent Open Redirects.
- **XSS Protections**: Standard Django template escaping. A specific JavaScript DOM XSS guard (`e()`) securely sanitizes dynamic Gemini AI outputs before insertion into `innerHTML`.
- **Rate Limiting**: `@rate_limit_view` decorator applied to auth, registration, password resets, and OAuth callbacks.
- **Logging/Privacy**: Logs capture actions and latencies without exposing tokens, keys, passwords, or raw email bodies.

## 10. User-Facing Features
- **Dashboard**: High-level metrics, threat distribution charts, and recent security alerts.
- **Inbox/Folders**: A mailbox view with filtering (Inbox, Starred, Trash, Phishing, Safe).
- **Email Detail**: Displays email content, threat indicators, analysis breakdowns, and identified links.
- **Attachment Analysis**: Visual breakdown of ATAE findings (entropy, YARA matches, risk level).
- **Gemini Explanation**: A button that generates a simple, forensic explanation of why an email was flagged.
- **Forensic PDF**: Export button to download a ReportLab-generated PDF of the security analysis.
- **Mail Actions**: Star, Move to Trash, Permanent Delete, and Manual Sync.
- **Profile/Settings**: Configuration for alerts and tracking pixel blocking.

## 11. ML / Detection System
- **Models Used**: Offline-trained Random Forest classifiers and TF-IDF vectorizers (`model.joblib`, `vectorizer.joblib`).
- **Location**: Stored locally in `SecureMail/ml/`.
- **Integration**: `EmailPipeline` instantiates the `Predictor` class, passing extracted text features. The prediction (SAFE/PHISHING) and confidence score are heavily weighted in the final pipeline verdict alongside URL and ATAE results.

## 12. External Services
- **Gmail API**: For fetching user emails and attachments.
- **Google OAuth 2.0**: For identity and authorization.
- **Gemini API (`google.genai`)**: For generating non-technical threat explanations.
- **VirusTotal API**: Threat intelligence for URLs and attachment hashes (IoCs).
- **Google Safe Browsing API**: Threat intelligence for URLs.

## 13. Environment Configuration
Required variables (see `.env.example`):
`SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS`, `GOOGLE_API_KEY`, `GEMINI_API_KEY`, `SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `FIELD_ENCRYPTION_KEY`.

## 14. Testing / Validation State
- **Current Baseline**: Django check passes cleanly. Migrations are clean. PostgreSQL is active.
- **Test Suite**: 83 tests passed (0 failures) during the latest full verification.
- **Security**: Security regression verification passed completely.
- **Invariant**: ATAE email-only invariant preserved.
- **Rule**: Future code changes require re-running targeted and full tests to ensure this baseline is maintained.

## 15. Validation Assets
- `benchmark_ground_truth.json`: A baseline dataset essential for reproducing ML accuracy and regression testing.
- `run_scientific_validation.py`: Script to validate ML heuristics against the baseline.
- `run_adversarial_testing.py`: Script to execute security validation tests.
- `run_full_validation_suite.py`: Orchestrates comprehensive QA and testing.
- `SecureMail_Attachment_Threat_Analysis_Engine_SDS.md`: Essential deep-dive architecture specification for ATAE.

## 16. Production Status / Remaining Deployment Configuration
The codebase is DEPLOYABLE AFTER CONFIGURATION. Remaining deployment tasks include:
- `DEBUG=False` in `.env`.
- Configuring a centralized cache backend (e.g., Redis or Memcached) to ensure global rate-limiting enforcement across multiple WSGI/ASGI workers.
- Configuring the reverse proxy (e.g., Nginx) to restrict direct public access to the `/media/` directory.
- Refactoring synchronous external API calls (like Gemini generation) to asynchronous background workers (e.g., Celery) to prevent web-request thread blocking under scale.

## 17. Recently Completed Security Remediation
Do NOT reintroduce these fixed vulnerabilities:
- **Stored DOM XSS**: Added an `e()` sanitizer function in templates to safely escape AI-generated content before injecting via `innerHTML`.
- **Open Redirects**: Removed raw `HTTP_REFERER` usages. Implemented a `safe_redirect` utility using Django's URL validator.
- **CSRF bypass**: Applied `@require_POST` to all state-changing endpoints (`delete_email`, `toggle_star`, `sync_gmail`).
- **OAuth Rate Limiting**: Applied `@rate_limit_view` to auth callbacks and login routes.
- **Deprecated SDK**: Migrated from obsolete `google.generativeai` (which caused FutureWarnings) to the modern `google.genai` SDK.

## 18. Files Future AI Assistants Must Not Casually Modify
- **`SecureMail/views.py` and `google_auth_views.py`**: Highly sensitive authentication, authorization, and redirection logic.
- **`SecureMail/services/email_pipeline.py`**: The core orchestration of security analysis.
- **`SecureMail/services/atae/integration/orchestrator.py`**: The ATAE entry point.
DO NOT redesign completed modules merely for cleanup, aesthetic, or stylistic reasons. Understand the call paths completely before modifying.

## 19. Development Rules for Future AI Assistants
1. Inspect current code before modifying anything.
2. Current implementation beats old reports/documentation.
3. Do not guess.
4. Do not change working architecture without a concrete reason.
5. Make minimal targeted changes.
6. Preserve database compatibility.
7. Preserve Google OAuth/Gmail behavior.
8. Preserve existing email analysis behavior.
9. Preserve security controls.
10. Preserve ATAE EMAIL-ONLY invariant.
11. Never expose secrets.
12. Never use real email/user data for fixtures.
13. Run targeted tests after changes.
14. Run full regression tests only when appropriate.
15. Do not declare something production-ready without evidence.

## 20. Known Stale Findings
Do NOT waste time attempting to fix these old audit findings, as they do not exist in the current implementation:
- **CSV export injection**: The `export_dataset_csv` endpoint and related `csv` logic have been entirely removed.
- **Dashboard N+1 database queries**: The dashboard uses optimized `.count()` aggregations; there are no N+1 object iteration loops.
- **Old `google.generativeai` import**: The SDK was migrated, and the obsolete dependency was stripped from `requirements.txt`.
- **Authentication rate-limit gaps**: `login`, `register`, and OAuth callbacks are actively protected by `@rate_limit_view`.
