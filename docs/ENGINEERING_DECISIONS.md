# SecureMail Architecture Decision Records (ADRs)

## 1. Executive Summary

This document formalizes the key architectural, technological, and security trade-offs made during the design and implementation of SecureMail v1.0.

---

## 2. Decision Records

### ADR-01: Framework Selection — Django vs. FastAPI / Node.js
- **Context**: Needed a rapid, secure framework for handling complex relational data, administrative auditing, and robust security middleware.
- **Decision**: Selected **Django 5.x**.
- **Rationale**: Django provides battle-tested security middleware (CSRF, XSS auto-escaping, Clickjacking defense, SQL injection immunization via ORM), built-in session authentication, and native support for PostgreSQL JSONB fields.
- **Trade-off**: Slightly higher memory footprint than microframeworks like FastAPI, mitigated via optimized database prefetching and stateless services.

---

### ADR-02: Database Engine — PostgreSQL 16
- **Context**: Needed strong relational consistency for user ownership, coupled with schema flexibility for polymorphic threat intelligence reports.
- **Decision**: Selected **PostgreSQL 16**.
- **Rationale**: Native `JSONB` columns allow unstructured forensic reports from ATAE, VirusTotal, and Gemini to be stored alongside strictly normalized relational metadata with GIN indexing capabilities.

---

### ADR-03: Machine Learning Engine — Local TF-IDF & Random Forest vs. External Cloud LLM Exclusively
- **Context**: Needed high-throughput email classification without exorbitant API cost or network latency.
- **Decision**: Implemented a **Hybrid Architecture** (Local ML for primary classification + Google Gemini Pro 1.5 for explainability).
- **Rationale**: Local inference executes in $<5\text{ ms}$ on standard CPU hardware with zero token cost. Gemini is invoked conditionally to generate plain-English explanations for SOC analysts.

---

### ADR-04: Attachment Forensics — Static ATAE vs. Full Dynamic Hypervisor Sandboxing
- **Context**: Balancing rapid threat classification against infrastructure complexity and resource constraints.
- **Decision**: Built a custom static **Attachment Threat Analysis Engine (ATAE)** based on header parsing, Shannon entropy, OLE2 macro stream extraction, and YARA signatures.
- **Rationale**: Eliminates the heavy compute and latency overhead ($>60\text{s}$) of booting virtual machines for everyday office and PDF documents, achieving static verdicts in $<30\text{ ms}$.

---

### ADR-05: PDF Engine — ReportLab Vector Engine vs. Headless Browser (Puppeteer/Weasyprint)
- **Context**: Needed automated generation of pixel-perfect, cryptographic forensic threat reports.
- **Decision**: Selected **ReportLab**.
- **Rationale**: Generates standalone, compact vector PDFs without requiring a headless Chromium browser instance in production, drastically reducing memory overhead.
