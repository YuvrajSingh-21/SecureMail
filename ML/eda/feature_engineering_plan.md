# SecureMail Feature Engineering Plan

## 1. Objective
To construct a robust, production-ready feature engineering pipeline for SecureMail version 1.0. This pipeline will transform raw text and metadata extracted during the EDA phase into actionable numeric arrays suitable for machine learning models (e.g., Random Forests, XGBoost, or Neural Networks) without data leakage.

## 2. Feature Extraction Categories

### 2.1. TEXT FEATURES
These features aim to capture the semantic and syntactic patterns typical of legitimate communication versus malicious or spam intent.
*   **TF-IDF Vectorization:** Convert the email `body` and `subject` into term frequency-inverse document frequency matrices. The vocabulary will be bounded (e.g., top 10,000 features) to limit memory overhead while capturing significant terms.
*   **Word N-Grams:** Extract common bigrams and trigrams (e.g., "account suspended", "verify your").
*   **Character N-Grams:** Useful for detecting obfuscated words (e.g., "p@ssword") and hidden character anomalies that evade standard tokenization.

### 2.2. EMAIL METADATA FEATURES
These features capture the structural anomalies typical of automated mass mailers or poorly constructed phishing kits.
*   **Subject Length & Body Length:** Raw character and token counts.
*   **Uppercase Ratio:** Ratio of capital letters to total characters (useful for detecting "URGENT" shouting).
*   **Digit Ratio:** High concentrations of numbers are common in scams or specific financial phishing.
*   **Special Character Ratio:** Tracks excessive use of symbols like `$`, `!`, `&`, often used in spam.
*   **HTML Ratio:** Analyzes the proportion of HTML tags to plaintext.
*   **Attachment Presence:** Boolean flag indicating if an attachment was parsed.

### 2.3. URL FEATURES
Phishing heavily relies on malicious links. Extracting signals from the URLs is critical.
*   **URL Count:** Total number of hyperlinks in the email.
*   **URL Length:** Average length of URLs. Malicious URLs often contain long query strings for tracking or obfuscation.
*   **Domain Length:** Length of the base domain.
*   **Suspicious TLD:** Boolean flag indicating use of cheap or heavily abused TLDs (e.g., `.xyz`, `.top`, `.tk`).
*   **IP Address URLs:** Boolean flag if the domain is a raw IPv4/IPv6 address.
*   **Shortened URLs:** Boolean flag if the domain belongs to known shorteners (`bit.ly`, `tinyurl.com`).
*   **URL Entropy:** Shannon entropy of the URL characters to detect random algorithmically generated domains (DGAs).

### 2.4. SECURITY PROTOCOL FEATURES
*(Note: To be calculated in future online phases or augmented datasets)*
*   **SPF Result:** Pass/Fail/SoftFail.
*   **DKIM Result:** Signature verification.
*   **DMARC Result:** Policy enforcement checks.
*   **Reply-To Mismatch:** Boolean flag if the `Reply-To` header differs from the `From` header (classic spear-phishing technique).
*   **Display Name Mismatch:** Checks if the sender's display name attempts to mimic a known internal executive or trusted brand.

### 2.5. LINGUISTIC / THEMATIC FEATURES
These are hard-coded regex matches or dictionary lookups designed to capture the intent of the email.
*   **Urgency Words:** Count of words like "urgent", "immediate", "suspension", "alert".
*   **Credential Theft Words:** Count of words like "login", "password", "verify", "secure".
*   **Financial Keywords:** Count of words like "invoice", "payment", "wire", "transfer", "crypto".
*   **Threat Keywords:** Count of words implying negative consequences if ignored.
*   **Brand Impersonation Keywords:** Count of high-value targets (e.g., "Paypal", "Apple", "Microsoft").

## 3. Pipeline Architecture
1.  **Preprocessor:** Cleans text (lowercase, strip special chars) and extracts URLs into a separate array.
2.  **Transformer:** Uses a `ColumnTransformer` (scikit-learn) or a PySpark equivalent.
    *   *Pipeline A:* Routes `body` and `subject` through custom Linguistic Feature Extractors.
    *   *Pipeline B:* Routes `body` and `subject` through TF-IDF Vectorizers.
    *   *Pipeline C:* Routes `urls` through a custom URL Feature Extractor.
    *   *Pipeline D:* Routes metadata through simple Numerical Scalers (StandardScaler).
3.  **Output:** A single dense/sparse concatenated matrix ready for the model.
