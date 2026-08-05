<div align="center">

# 🔐 SecuraMail

### AI-Powered Email Threat Detection & Forensic Analysis

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-6.0.7-092E20?style=for-the-badge&logo=django&logoColor=white)](https://djangoproject.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Active-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-83%20Passing-brightgreen?style=for-the-badge)](#testing)

**SecuraMail is an open-source cybersecurity platform that connects to your Gmail account and automatically analyzes every incoming email for phishing attempts, malicious links, and dangerous attachments using a multi-layer forensic analysis engine.**

[Features](#-key-features) · [Architecture](#-architecture-overview) · [Installation](#-installation) · [Documentation](#-documentation) · [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Key Features](#-key-features)
- [Architecture Overview](#-architecture-overview)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Email Analysis Pipeline](#-email-analysis-pipeline)
- [Attachment Threat Analysis Engine (ATAE)](#-attachment-threat-analysis-engine-atae)
- [Machine Learning Engine](#-machine-learning-engine)
- [URL Analysis](#-url-analysis)
- [Gemini AI Explanation](#-gemini-ai-explanation)
- [Security Features](#-security-features)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Environment Variables](#-environment-variables)
- [Running the Project](#-running-the-project)
- [Testing](#-testing)
- [Documentation](#-documentation)
- [Future Roadmap](#-future-roadmap)
- [License](#-license)
- [Author](#-author)
- [Acknowledgements](#-acknowledgements)

---

## 🌐 Overview

SecuraMail is a Django-based cybersecurity web application that integrates with Gmail via Google OAuth to provide automated, multi-layer threat detection for incoming emails. It combines machine learning heuristics, external threat intelligence APIs, deep file forensics, and AI-powered explanations to help users identify and understand phishing emails, malicious links, and dangerous attachments — without requiring any security expertise.

---

## ❗ Problem Statement

Modern phishing attacks bypass traditional spam filters by using legitimate-looking domains, sophisticated social engineering, and zero-day malware in attachments. Most email clients provide minimal threat context and no forensic detail. SecuraMail bridges this gap by providing deep, automated security analysis with human-readable explanations of every detected threat.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **Gmail Integration** | Secure OAuth 2.0 connection with delta-sync history tracking |
| **Multi-Layer Analysis** | ML heuristics + URL threat intel + attachment forensics |
| **ATAE** | Custom Attachment Threat Analysis Engine (non-execution forensics) |
| **URL Reputation** | VirusTotal + Google Safe Browsing integration |
| **Gemini AI** | On-demand human-readable forensic explanation via Google Gemini |
| **Forensic PDF** | Downloadable security report per email |
| **Risk Scoring** | Deterministic weighted scoring engine (0–100) |
| **Audit Log** | Immutable record of all security-sensitive user actions |
| **Rate Limiting** | Brute-force protection on all authentication endpoints |
| **Encrypted Tokens** | OAuth tokens encrypted at rest |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        SecuraMail                           │
│                                                             │
│  ┌──────────┐    ┌─────────────┐    ┌──────────────────┐  │
│  │  Browser │───▶│ Django Views│───▶│  Service Layer   │  │
│  └──────────┘    └─────────────┘    └──────────────────┘  │
│                                              │               │
│              ┌───────────────────────────────┤               │
│              │                               │               │
│   ┌──────────▼──────┐          ┌────────────▼──────────┐   │
│   │  Email Pipeline  │          │    Gmail / OAuth       │   │
│   │  ┌────────────┐  │          │    Google APIs         │   │
│   │  │ ML Engine  │  │          └───────────────────────┘   │
│   │  ├────────────┤  │                                       │
│   │  │ URL Intel  │  │          ┌───────────────────────┐   │
│   │  ├────────────┤  │          │     PostgreSQL DB       │   │
│   │  │   ATAE     │  │◀────────▶│  EmailMessage          │   │
│   │  └────────────┘  │          │  Attachment            │   │
│   └─────────────────┘          │  EmailAnalysis         │   │
│                                 └───────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.14, Django 6.0.7 |
| **Database** | PostgreSQL (psycopg2-binary) |
| **Authentication** | Google OAuth 2.0, Django Sessions |
| **Gmail Integration** | google-api-python-client, google-auth-oauthlib |
| **AI / Explanation** | google-genai (Gemini Flash) |
| **Machine Learning** | scikit-learn, XGBoost, pandas, numpy |
| **Token Security** | django-encrypted-model-fields |
| **Rate Limiting** | django-ratelimit |
| **Threat Intelligence** | VirusTotal API, Google Safe Browsing API |
| **PDF Reporting** | ReportLab |
| **Frontend** | Django Templates, Tailwind CSS, Lucide Icons |
| **Parsing** | BeautifulSoup4 |

---

## 📁 Project Structure

```
Email_Phisher/
├── Email_Phisher/          # Django project configuration
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── SecureMail/             # Core application
│   ├── models.py           # Database models
│   ├── views.py            # UI view controllers
│   ├── api_views.py        # AJAX API endpoints
│   ├── google_auth_views.py # OAuth flow
│   ├── utils.py            # Security utilities (safe_redirect)
│   ├── decorators.py       # Rate limiting decorator
│   │
│   ├── services/
│   │   ├── email_pipeline.py      # Analysis orchestration
│   │   ├── sync_manager.py        # Gmail synchronization
│   │   ├── gemini_service.py      # Gemini AI integration
│   │   ├── risk_engine.py         # Forensic risk scoring
│   │   ├── virustotal_service.py  # VirusTotal API
│   │   ├── safe_browsing_service.py
│   │   ├── atae/                  # Attachment Threat Analysis Engine
│   │   └── pdf/                   # Forensic PDF generation
│   │
│   ├── ml/                        # Machine Learning
│   │   ├── predictor.py
│   │   ├── category_classifier.py
│   │   ├── feature_extractor.py
│   │   └── models/                # Trained model artifacts
│   │
│   ├── tasks/                     # Background threading tasks
│   ├── templates/                 # HTML templates
│   └── tests*.py                  # Test suites
│
├── benchmark_ground_truth.json    # ML validation dataset
├── run_scientific_validation.py   # Validation scripts
├── run_adversarial_testing.py
├── run_full_validation_suite.py
├── requirements.txt
└── manage.py
```

---

## 🔄 Email Analysis Pipeline

Every synchronized email passes through this deterministic pipeline:

```
Gmail API
    ↓
SyncManager (background thread)
    ↓  parses headers, body, attachments
EmailMessage + Attachment → PostgreSQL
    ↓
EmailPipeline (background thread)
    ├── 1. ML Phishing Predictor     → ML score + label
    ├── 2. Category Classifier       → Email type (OTP, BANKING, etc.)
    ├── 3. Sender Reputation Engine  → Domain trust score
    ├── 4. Link Analysis             → SafeBrowsing + VT + heuristics
    ├── 5. Attachment Analysis       → ATAE (if attachments present)
    └── 6. RiskEngine.calculate_risk → Final weighted verdict
    ↓
EmailAnalysis JSON → PostgreSQL
    ↓
Inbox / Dashboard → User
```

The `RiskEngine` is the authoritative single source of truth for the final verdict. It combines all signals using a deterministic weighted scoring model, not a probabilistic one.

---

## 🔬 Attachment Threat Analysis Engine (ATAE)

> **IMPORTANT**: ATAE analyzes **only attachments received through emails inside SecuraMail**. It is not a general-purpose file upload scanner. No public upload endpoint exists.

ATAE performs deep, non-execution forensic analysis on email attachments:

| Analyzer | What It Detects |
|---|---|
| **ArchiveAnalyzer** | ZIP slip attacks, archive bombs, nested archives, suspicious extensions |
| **ExecutableAnalyzer** | PE/ELF headers, UPX packing, dangerous import tables |
| **OfficeAnalyzer** | VBA macros, OLE2 autoexec, external templates, embedded executables |
| **PDFAnalyzer** | Embedded JavaScript, OpenAction, LaunchAction, suspicious producers |
| **ScriptAnalyzer** | PowerShell encoding, AMSI bypass, eval/exec, base64 blobs |
| **ImageAnalyzer** | Appended PE/ZIP in images, entropy anomalies, missing EOI markers |
| **YARAEngine** | Custom rule-based signature matching |
| **EntropyService** | Shannon entropy to detect packing/encryption |
| **ThreatIntelService** | VirusTotal hash lookup for known IoCs |

---

## 🤖 Machine Learning Engine

SecuraMail uses offline-trained XGBoost models deployed locally (no cloud ML inference required):

- **Phishing Predictor**: Trained on labeled email datasets. Combines TF-IDF text vectorization with 26 engineered behavioral features (sender heuristics, URL patterns, credential keywords, urgency signals).
- **Category Classifier**: Multi-class classifier (16 categories: BANKING, OTP, NEWSLETTER, PHISHING, etc.).
- **Sender Reputation Engine**: Domain-level historical trust scoring.

Model artifacts (`phishing_model.pkl`, `vectorizer.pkl`, `category_model.pkl`) are stored in `SecureMail/ml/models/` and loaded once at startup.

---

## 🔗 URL Analysis

URLs extracted from email bodies are analyzed through:

1. **Structural Heuristics**: IP-based URLs, URL shorteners, suspicious TLDs (`.zip`, `.tk`, `.xyz`), punycode spoofing, multiple redirects, typosquatting of major brands.
2. **Link Mismatch Detection**: Detects when visible anchor text domain differs from actual `href` destination.
3. **Homoglyph Detection**: Identifies Cyrillic characters in URLs used to impersonate Latin domains.
4. **Google Safe Browsing API**: Real-time check against Google's threat database.
5. **VirusTotal API**: Hash/URL reputation from 70+ AV vendors.

---

## 💬 Gemini AI Explanation

After automated analysis, users can request a plain-English explanation of the threat verdict:

- The Gemini Flash model receives a structured prompt containing ML findings, detected URL risks, and ATAE findings.
- The response is parsed as structured JSON and cached in the `EmailAnalysis` record.
- Gemini performs **explanation only** — it does not influence the security verdict.
- A deterministic fallback explanation is provided if the Gemini API is unavailable.

---

## 🛡️ Security Features

| Control | Implementation |
|---|---|
| **CSRF Protection** | Global middleware + `@require_POST` on all state-changing endpoints |
| **OAuth State Validation** | PKCE `code_verifier` + `state` token validated in session |
| **Encrypted Token Storage** | `django-encrypted-model-fields` with 32-byte `FIELD_ENCRYPTION_KEY` |
| **Open Redirect Prevention** | `safe_redirect()` using `url_has_allowed_host_and_scheme` |
| **DOM XSS Prevention** | `e()` JavaScript escaper for all dynamic AI-generated content |
| **Rate Limiting** | IP/User-based rate limiting on login, register, OAuth (3–10 req/min) |
| **Ownership Enforcement** | All ORM queries bound to `user=request.user` |
| **Attachment Access Control** | Ownership verified before any file is served |
| **Security Headers** | HSTS, SSL redirect, secure cookies enabled in production |
| **Audit Logging** | Immutable DB-backed audit trail for sensitive actions |

---

## 📸 Screenshots

> *Screenshots coming soon — deploy locally to view the UI.*

| Dashboard | Email Analysis | ATAE Report |
|---|---|---|
| *(Dashboard screenshot)* | *(Email detail screenshot)* | *(ATAE findings screenshot)* |

---

## 🚀 Installation

### Prerequisites

- Python 3.12+
- PostgreSQL 14+
- Google Cloud Project with Gmail API and OAuth 2.0 enabled

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/SecuraMail.git
cd SecuraMail/Email_Phisher

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and configure environment variables
cp .env.example .env
# Edit .env with your credentials (see Configuration section)

# 5. Run database migrations
python manage.py migrate

# 6. Create a superuser (optional)
python manage.py createsuperuser

# 7. Start the development server
python manage.py runserver
```

---

## ⚙️ Configuration

### Google Cloud Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project
3. Enable **Gmail API** and **Google+ API**
4. Create **OAuth 2.0 Client ID** credentials (Web Application)
5. Add `http://localhost:8000/auth/callback/` to Authorized Redirect URIs
6. Download credentials and add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` to `.env`

### API Keys Required

| API | Purpose | Required |
|---|---|---|
| Google OAuth | User authentication + Gmail access | **Yes** |
| Gemini API | AI-powered threat explanations | Yes |
| VirusTotal API | URL + attachment hash reputation | Recommended |
| Google Safe Browsing | URL threat intelligence | Recommended |

---

## 🔑 Environment Variables

Copy `.env.example` to `.env` and populate all values. **Never commit `.env` to version control.**

```
SECRET_KEY=          # Django secret key (generate a strong random key)
DEBUG=               # False in production
ALLOWED_HOSTS=       # Comma-separated allowed hostnames

GOOGLE_CLIENT_ID=    # OAuth 2.0 Client ID
GOOGLE_CLIENT_SECRET=# OAuth 2.0 Client Secret
GOOGLE_API_KEY=      # Google API Key (for Safe Browsing)

GEMINI_API_KEY=      # Google Gemini API Key
VIRUSTOTAL_API_KEY=  # VirusTotal API Key
SAFE_BROWSING_API_KEY= # Google Safe Browsing API Key

DB_NAME=             # PostgreSQL database name
DB_USER=             # PostgreSQL username
DB_PASSWORD=         # PostgreSQL password
DB_HOST=             # Database host (localhost)
DB_PORT=             # Database port (5432)

FIELD_ENCRYPTION_KEY=# 32-byte key for OAuth token encryption
```

---

## ▶️ Running the Project

```bash
# Development
python manage.py runserver

# Check for issues
python manage.py check

# Run all tests
python manage.py test

# Run ML validation
python run_scientific_validation.py

# Run adversarial tests
python run_adversarial_testing.py
```

---

## 🧪 Testing

SecuraMail maintains a comprehensive test suite of **83 tests** across multiple modules:

```bash
python manage.py test --verbosity=2
```

| Test Module | Coverage |
|---|---|
| `tests.py` | Pipeline, ML, Gmail sync, history tracking |
| `tests_csrf.py` | CSRF protection on all state-changing endpoints |
| `tests_redirect.py` | Open redirect prevention (12 attack vectors) |
| `tests_production.py` | Audit logging, settings, user actions |
| `atae/tests/` | 60+ ATAE unit tests across all analyzers |

---

## 📖 Documentation

| Document | Description |
|---|---|
| [`SECUREMAIL_MASTER_DOCUMENTATION.md`](SECUREMAIL_MASTER_DOCUMENTATION.md) | Complete technical architecture reference |
| [`SecureMail_Attachment_Threat_Analysis_Engine_SDS.md`](SecureMail_Attachment_Threat_Analysis_Engine_SDS.md) | Deep-dive ATAE design specification |
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | Engineering handoff and development rules |
| [`SECURITY.md`](SECURITY.md) | Security policy and disclosure process |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |

---

## 🗺️ Future Roadmap

| Feature | Status |
|---|---|
| Celery/Redis async task queue | Planned |
| Microsoft 365 / Outlook integration | Planned |
| Category classifier retraining pipeline | Planned |
| Real-time WebSocket threat notifications | Planned |
| Multi-account Gmail management | Planned |
| Custom YARA rule management UI | Planned |

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**SecuraMail**
- GitHub: [@YuvrajSingh-21](https://github.com/YuvrajSingh-21)

---

## 🙏 Acknowledgements

- [Google Gemini](https://deepmind.google/technologies/gemini/) for AI threat explanations
- [VirusTotal](https://www.virustotal.com/) for threat intelligence
- [Google Safe Browsing](https://safebrowsing.google.com/) for URL analysis
- [Django](https://www.djangoproject.com/) for the web framework
- [scikit-learn](https://scikit-learn.org/) and [XGBoost](https://xgboost.readthedocs.io/) for ML
- [ReportLab](https://www.reportlab.com/) for PDF generation
