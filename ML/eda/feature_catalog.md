# SecureMail Feature Catalog

This document details every proposed feature to be engineered from Dataset Version 1.0 during the machine learning phase.

| Feature Name | Description | Data Type | Reason | Expected Importance |
| :--- | :--- | :--- | :--- | :--- |
| `tfidf_body_*` | TF-IDF scores for top N words in body. | Float | Captures semantic meaning of the email. | High |
| `tfidf_subject_*` | TF-IDF scores for top N words in subject. | Float | Captures the intent or lure of the email. | High |
| `char_ngram_*` | Frequency of character n-grams. | Float | Detects obfuscation (e.g. `p@ss`). | Medium |
| `subject_len` | Total character length of subject. | Integer | Phishing often uses abnormally long or short subjects. | Low |
| `body_len` | Total character length of body. | Integer | Scam emails may be very short (link only) or very long. | Medium |
| `word_count` | Total words in the email body. | Integer | Establishes context size. | Low |
| `char_count` | Total characters in the email body. | Integer | Complements word count. | Low |
| `uppercase_ratio` | (Uppercase chars) / (Total chars) | Float | Spammers frequently capitalize entire words/sentences. | Medium |
| `digit_ratio` | (Digit chars) / (Total chars) | Float | Detects phone numbers, crypto wallets, invoice IDs. | Medium |
| `special_char_ratio` | (Special chars) / (Total chars) | Float | Detects excessive punctuation or obfuscation. | High |
| `is_html` | Boolean indicating HTML presence. | Boolean | Phishing often heavily relies on HTML to hide links. | Medium |
| `has_attachment` | Boolean indicating attachment presence. | Boolean | Malware delivery relies entirely on attachments. | High |
| `url_count` | Number of URLs in the email. | Integer | Scams almost always include at least one call to action link. | High |
| `avg_url_len` | Average length of URLs. | Float | Malicious URLs use long tracking/obfuscation strings. | Medium |
| `avg_domain_len` | Average length of URL domains. | Float | DGA (Algorithmically generated domains) are often long. | Medium |
| `has_suspicious_tld` | Flag for cheap/abused TLDs (.xyz, .pw) | Boolean | Attackers buy cheap domains in bulk. | High |
| `has_ip_url` | Flag if URL uses raw IP (e.g. `http://192.168.1.1`) | Boolean | Legitimate emails rarely use raw IP addresses. | Very High |
| `has_shortened_url` | Flag if URL uses bit.ly, tinyurl, etc. | Boolean | Used to mask the final malicious destination. | High |
| `avg_url_entropy` | Average Shannon entropy of domains. | Float | High entropy indicates DGA (random string) domains. | High |
| `urgency_word_count` | Count of urgency keywords. | Integer | Social engineering relies on time pressure. | High |
| `cred_theft_word_count` | Count of credential-related keywords. | Integer | Phishing directly asks for logins. | High |
| `financial_word_count` | Count of financial keywords. | Integer | Extortion and scams focus on money. | High |
| `threat_word_count` | Count of threat keywords. | Integer | Blackmail/extortion relies on threats. | Medium |
| `brand_impersonation_count`| Count of top 50 impersonated brands. | Integer | Phishing often mimics Paypal, Microsoft, Apple. | Very High |
