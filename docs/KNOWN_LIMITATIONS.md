# SecureMail Known Limitations & Engineering Roadmap

## 1. Document Purpose

This document provides a transparent accounting of known architectural constraints and engineering boundaries in SecureMail v1.0, accompanied by concrete architectural remediation strategies planned for subsequent releases.

---

## 2. Verified Technical Limitations

### 2.1 Synchronous Forensic PDF Generation
- **Current Behavior**: ReportLab vector PDF rendering is executed synchronously within the Django request-response cycle on `GET /email/<id>/export-pdf/`.
- **Impact**: Median rendering latency is ~840 ms. While acceptable under typical analyst load, bursts of simultaneous PDF generation (>50 concurrent exports) temporarily saturate Python CPU worker threads.
- **Remediation Roadmap**: Offload PDF compilation to asynchronous background workers (Celery + Redis) with WebSocket or polling download status notifications.

### 2.2 Cold External Threat Intelligence Latency
- **Current Behavior**: First-time analysis of an un-cached email requires outbound HTTPS calls to Google Gemini Pro 1.5 and VirusTotal v3.
- **Impact**: Initial analysis exhibits a latency of 1.2s to 4.5s depending on external API network conditions.
- **Mitigation in Place**: Results are permanently cached in the PostgreSQL `ThreatAnalysis.detailed_report` JSONB field. Subsequent accesses execute in $<5\text{ ms}$.

### 2.3 Single-Engine File Sandboxing
- **Current Behavior**: The Attachment Threat Analysis Engine (ATAE) performs static structural, header, entropy, and heuristic signature parsing. It does not perform dynamic binary execution inside a hypervisor/sandbox (e.g. Cuckoo Sandbox).
- **Impact**: Highly sophisticated zero-day kernel exploits that trigger only during specific execution paths cannot be dynamically monitored at runtime.
- **Remediation Roadmap**: Integrate a microVM sandbox connector (e.g. Firecracker or Docker-isolated dynamic runner) in v2.0.

---

## 3. Engineering Roadmap

| Feature / Upgrade | Target Version | Architectural Strategy |
| :--- | :---: | :--- |
| **Celery & Redis Worker Layer** | v1.1 | Async queueing for PDF compilation and bulk sync. |
| **Redis Cache Layer** | v1.1 | L2 caching for frequent dashboard metric aggregation queries. |
| **Model Quantization (ONNX)** | v1.2 | Quantize scikit-learn models for $<2\text{ms}$ edge inference. |
| **Dynamic MicroVM Sandboxing** | v2.0 | Automated runtime execution analysis of untrusted binaries. |
| **Microsoft 365 / Graph API** | v2.0 | Add Microsoft 365 OAuth 2.0 and Outlook email ingestion. |
