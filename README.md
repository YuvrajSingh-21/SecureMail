# SecureMail 🛡️

![SecureMail Banner](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.2+-092E20?style=for-the-badge&logo=django&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

SecureMail is a next-generation, AI-driven email security platform designed to automatically analyze, flag, and neutralize phishing attempts, malware, and social engineering attacks. By integrating deep learning, LLM context analysis, and real-time threat intelligence (VirusTotal, Google Safe Browsing), SecureMail protects organizations at the inbox layer.

---

## 🌟 Overview

Modern email threats bypass traditional spam filters by employing highly targeted social engineering tactics. SecureMail operates as a proactive defense layer that continuously monitors connected Google Workspaces via the Gmail API, parsing emails through a localized Machine Learning pipeline to calculate exact risk scores before the user ever clicks a link.

---

## ✨ Features

- **Automated Threat Detection**: Real-time analysis of incoming emails using proprietary ML vectorization.
- **AI Forensic Analysis**: Gemini-powered LLM analysis to detect subtle phishing tones and linguistic anomalies.
- **Live Threat Intelligence**: Deep integration with VirusTotal and Google Safe Browsing to scan attachments and URLs.
- **Gmail API Integration**: Seamless, one-click OAuth integration with Google Workspace to secure active inboxes.
- **Unified Premium Dashboard**: A responsive, beautifully crafted interface built with TailwindCSS and Vanilla JavaScript.
- **False Positive Reporting**: Admin feedback loops to continuously tune and improve the underlying ML models.
- **Zero-Knowledge Architecture**: Sensitive OAuth tokens are encrypted at rest using AES-GCM database field encryption.

---

## 🏗️ Architecture

SecureMail utilizes a monolithic yet heavily decoupled architecture:

- **Frontend**: Django Templates, Tailwind CSS (Design Tokens System), Lucide Icons, Vanilla JavaScript.
- **Backend**: Django (Python), PostgreSQL / SQLite.
- **Security Engine**: Local scikit-learn models (for fast triage), Google Gemini API (for deep contextual parsing).
- **Authentication**: Google OAuth 2.0.

---

## 🚀 Tech Stack

- **Framework**: Django (Python)
- **Database**: PostgreSQL (Production) / SQLite (Development)
- **Styling**: Tailwind CSS
- **AI/ML**: Google Gemini API, Scikit-learn
- **Integrations**: Google Gmail API, VirusTotal, Safe Browsing

---

## 📁 Project Structure

```text
Email_Phisher/
├── SecureMail/                 # Main Django Application
│   ├── api/                    # API endpoints
│   ├── ml/                     # Machine Learning logic & pipelines
│   ├── models.py               # Database Schema
│   ├── services/               # Decoupled business logic (EmailService)
│   ├── static/                 # CSS (Tailwind) & JS assets
│   ├── templates/              # HTML Templates (Unified Design System)
│   └── views.py                # View Controllers
├── Email_Phisher/              # Django Configuration
│   ├── settings.py             # Project Settings
│   └── urls.py                 # URL Routing
├── .env.example                # Example environment variables
├── .gitignore                  # Production Git ignores
├── manage.py                   # Django CLI
└── requirements.txt            # Python dependencies
```

---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-org/securemail.git
cd securemail
```

### 2. Set up the virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

---

## 🔐 Environment Variables

Create a `.env` file in the project root by copying the example file:
```bash
cp .env.example .env
```

You must populate the `.env` file with your own keys:
- `SECRET_KEY`: Your Django secret key.
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`: For Google OAuth.
- `GEMINI_API_KEY`: For LLM Forensic Analysis.
- `VIRUSTOTAL_API_KEY`: For attachment scanning.
- `FIELD_ENCRYPTION_KEY`: A base64-encoded 32-byte key for database encryption.

---

## 🗄️ Database Setup

Run the migrations to create the database schema:

```bash
python manage.py makemigrations
python manage.py migrate
```

*(Optional) Create a superuser for the admin panel:*
```bash
python manage.py createsuperuser
```

---

## 🚀 Running the Project

Start the Django development server:

```bash
python manage.py runserver
```
Visit `http://localhost:8000` in your browser.

---

## 🔗 Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project and enable the **Gmail API**.
3. Configure the OAuth Consent Screen.
4. Create **OAuth 2.0 Client IDs**.
5. Add `http://localhost:8000/google/callback` to the Authorized redirect URIs.
6. Copy the Client ID and Secret into your `.env` file.

---

## 🤖 AI Integrations

SecureMail uses a two-step AI engine:
1. **Lightweight Heuristics**: Initial scanning via local NLP vectors (scikit-learn) to detect known phishing patterns.
2. **Deep Forensics**: High-risk emails are sent to the **Gemini API** for deep contextual analysis, identifying social engineering, urgency tactics, and sender spoofing.

---

## 🛡️ Security Features

- **Field-Level Encryption**: All OAuth `access_token` and `refresh_token` fields are encrypted at rest.
- **CSRF & XSS Protection**: Enforced across all forms and templates natively by Django.
- **Rate Limiting**: Critical endpoints (like authentication and feedback loops) are strictly rate-limited.
- **Secure Sessions**: Session cookies are configured for HTTPOnly and secure transmission.

---

## 🔮 Future Improvements

- [ ] Microsoft 365 (Outlook API) Integration.
- [ ] Push Notifications via WebSockets.
- [ ] Advanced Admin Analytics Dashboard.
- [ ] Custom ML Model Training Pipeline via user feedback.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
