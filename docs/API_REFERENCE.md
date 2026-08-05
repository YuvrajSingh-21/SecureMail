# SecuraMail REST API Reference Manual (v1.0)

## 1. Authentication & Headers

All authenticated API endpoints require a valid Django session cookie (`sessionid`) or authentication token.

### Standard Request Headers
```http
Accept: application/json
Content-Type: application/json
X-CSRFToken: <csrf_token>
```

---

## 2. API Endpoints

### 2.1 List Emails
- **Method**: `GET`
- **Path**: `/api/emails/`
- **Auth**: Required (Session)
- **Description**: Returns a paginated list of analyzed emails for the authenticated user, pre-joined with threat indicators and analysis scores.

#### Query Parameters
| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `page` | Integer | No | `1` | Page number for pagination. |
| `folder` | String | No | `inbox` | Filter by folder (`inbox`, `starred`, `spam`, `trash`, `archive`, `malicious`, `suspicious`). |
| `q` | String | No | `""` | Search term matching sender or subject. |

#### Response (`200 OK`)
```json
[
  {
    "id": 14130,
    "sender": "security-alert@paypal.com.account-update.xyz",
    "subject": "Urgent: Unusual sign-in activity detected",
    "received_at": "2026-08-01T18:30:00Z",
    "folder": "malicious",
    "is_read": false,
    "analysis": {
      "threat_score": 88,
      "threat_level": "MALICIOUS",
      "category": "CREDENTIAL_PHISHING",
      "indicators": [
        {
          "type": "URL_DOMAIN_HOMOGRAPH",
          "value": "account-update.xyz",
          "severity": "HIGH",
          "description": "Domain impersonating PayPal financial brand."
        }
      ]
    }
  }
]
```

---

### 2.2 Get Email Detail
- **Method**: `GET`
- **Path**: `/api/emails/<id>/`
- **Auth**: Required (Session + Tenant Ownership)
- **Description**: Retrieves full message body, headers, attachments, and forensic risk indicators.

#### Response (`200 OK`)
```json
{
  "id": 14130,
  "sender": "security-alert@paypal.com.account-update.xyz",
  "subject": "Urgent: Unusual sign-in activity detected",
  "body_plain": "Please verify your account immediately at http://login.account-update.xyz...",
  "received_at": "2026-08-01T18:30:00Z",
  "attachments": [
    {
      "id": 402,
      "filename": "Account_Invoice.pdf",
      "file_size": 24510,
      "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ],
  "analysis": {
    "threat_score": 88,
    "threat_level": "MALICIOUS",
    "category": "CREDENTIAL_PHISHING"
  }
}
```

---

### 2.3 Generate AI Threat Explanation
- **Method**: `POST`
- **Path**: `/email/<id>/generate-explanation/`
- **Auth**: Required (Session + Tenant Ownership)
- **Description**: Invokes Google Gemini Pro 1.5 to generate an explainable threat assessment. Caches result in database.

#### Response (`200 OK`)
```json
{
  "status": "success",
  "email_id": 14130,
  "explanation": "This email is classified as Malicious Credential Phishing because the sender domain mimics PayPal while routing links to an unverified third-party registrar (.xyz).",
  "cached": false
}
```

---

### 2.4 Export Forensic PDF Report
- **Method**: `GET`
- **Path**: `/email/<id>/export-pdf/`
- **Auth**: Required (Session + Tenant Ownership)
- **Description**: Compiles a ReportLab technical forensic report containing vector threat breakdown charts and digital SHA-256 hashes.
- **Response**: Binary stream (`Content-Type: application/pdf`).

---

### 2.5 Attachment Preview & Download
- **Preview Path**: `GET /attachment/<id>/preview/`
- **Download Path**: `GET /attachment/<id>/download/`
- **Auth**: Required (Session + Tenant Ownership)
- **Response**: Binary stream with sanitized `Content-Disposition` headers.

---

## 3. Error Responses

| HTTP Status | Meaning | Description |
| :--- | :--- | :--- |
| `401 Unauthorized` | Unauthenticated | Missing or expired Django session cookie. |
| `403 Forbidden` | Access Denied | CSRF failure or tenant ownership mismatch. |
| `404 Not Found` | Resource Missing | Object does not exist or belongs to another user. |
| `429 Too Many Requests`| Rate Limited | Exceeded per-minute API invocation threshold. |
| `500 Internal Error` | Server Error | Unhandled backend exception. |
