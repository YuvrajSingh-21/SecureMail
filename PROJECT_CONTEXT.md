# SecureMail

SecureMail is a sophisticated, intelligent email client and security platform designed to protect users from phishing, spam, and malicious content. By integrating directly with the Gmail API, it provides a powerful layer of real-time intelligence on top of traditional email communication.

## 🚀 Core Features

### 1. Multi-Layer Intelligence Engine
The heart of the project is a local ML analysis pipeline that evaluates every incoming email:
*   **Phishing Predictor**: A Random Forest classifier that analyzes linguistic patterns, sender metadata, and structural features to generate a "Threat Index" (0-100).
*   **Explainable Insights**: Instead of just a "Safe" or "Dangerous" label, the system provides specific reasons (e.g., "Contains urgent language", "Sender reputation anomaly detected").
*   **Sender Reputation**: Tracks domain-level historical trust based on frequency and previous analysis results.

### 2. Deep Content Inspection & Secure Viewing
*   **Link Sanitization**: Neutralizes and audits every URL found in an email body.
*   **Attachment Sandboxing**: Scans files for malicious signatures (Integrated with services like VirusTotal).
*   **Advanced Rendering**: Uses a sandboxed iframe with custom CSS recovery logic to display complex HTML emails (like LinkedIn or Amazon) safely without compromising layout.

### 3. Premium Mail Interface
*   **Advanced Inbox**: Includes real-time sorting (Newest/Oldest/Risk), smart UNREAD/READ filtering, and contextual bulk actions (Mark Read/Unread, Archive, Delete) driven by a master selection dropdown.
*   **Rich Compose Window**: A premium, Gmail-inspired floating compose interface featuring rich text formatting, inline link popovers, a native emoji picker, recipient chip management, and an integrated AI Assistant card.

### 4. Unified Security Dashboard
*   **Real-time Analytics**: Visualizes threat trends, top phishing domains, and overall security posture.
*   **Security Score**: Calculates a dynamic user security score (0-100) based on historical email hygiene.

## 🛠️ Technical Tech Stack

### Backend
*   **Framework**: Django 6.0 (Python 3.14)
*   **API**: Django REST Framework (DRF)
*   **Database**: SQLite (Development) / Scalable to PostgreSQL
*   **Task Queue**: Integrated Sync Manager for background Gmail synchronization.

### Frontend
*   **Styling**: Tailwind CSS via CDN (Modern, responsive "Glassmorphism" UI).
*   **Icons**: Lucide Icons.
*   **JavaScript**: Vanilla JS Modules with a custom asynchronous component loader, contenteditable DOM manipulation, and real-time API state management without framework overhead.

### AI/ML
*   **Libraries**: Scikit-learn, Joblib, Pandas, NumPy.
*   **Sanitization**: Bleach with custom permissive filters for high-fidelity rendering.
*   **Parsing**: BeautifulSoup4 for robust HTML extraction and snippet generation.

## 📁 Project Architecture

```text
Email_Phisher/
├── SecureMail/                 # Core Application Logic
│   ├── api/                    # REST API Endpoints & Serializers
│   ├── ml/                     # Machine Learning Models & Predictors
│   │   ├── models/             # Trained .pkl artifacts
│   │   └── predictor.py        # Inference Engine
│   ├── services/               # Business Logic & Third-party Integrations
│   │   ├── email_pipeline.py   # Multi-stage analysis orchestrator
│   │   ├── gmail_service.py    # Gmail API Wrapper & Sanitizer
│   │   └── risk_engine.py      # Scoring logic
│   ├── static/SecureMail/      # CSS & Modular JS Services
│   └── templates/              # High-fidelity HTML Templates (Inbox, Compose, Details)
├── Email_Phisher/settings.py   # System Configuration
└── demo.html                   # Interactive High-Fidelity Prototype
```

## 🔒 Security Mandates
*   **Data Integrity**: `ml_label` is the exclusive source of truth for threat categorization.
*   **Privacy**: All analysis is performed locally on the server; email credentials are handled via Google OAuth2.
*   **Safety**: Iframes are strictly sandboxed to prevent script execution within email bodies.

---
*Updated on July 23, 2026*
