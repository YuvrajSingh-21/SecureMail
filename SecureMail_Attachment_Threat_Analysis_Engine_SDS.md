# SecuraMail — Attachment Threat Analysis Engine
## Software Design Specification (SDS)

**Document Version:** 1.0
**Module:** Attachment Threat Analysis Engine (ATAE)
**Classification:** Internal Engineering — Architecture Blueprint
**Scope:** New module only. Integrates with existing SecuraMail platform (Gmail Integration, Email Sync, Parsing, Header/URL/Sender Analysis, SPF/DKIM/DMARC, Reputation, VirusTotal, Safe Browsing, ML Classifier, Gemini Explainability, PDF Reporting, Django/PostgreSQL backend).

---

## 1. Module Overview

The Attachment Threat Analysis Engine (ATAE) is a self-contained analysis subsystem responsible for the deterministic, forensic-grade inspection of email attachments processed by SecuraMail. It receives attachment payloads (and associated metadata) from the existing Email Parsing module, performs multi-layered static and structural analysis, extracts indicators of compromise (IOCs), computes a risk score, and emits a structured "Attachment Verdict" object that downstream modules (ML Classifier, Gemini Explainability, PDF Report Generator, Threat Detection) consume.

ATAE is explicitly **not** a signature-based antivirus replacement. It does not attempt dynamic execution, sandbox detonation, or behavioral emulation in this phase. Its purpose is to perform static forensic decomposition of a file — parsing its structure, extracting embedded objects, identifying known attack techniques (macros, OLE objects, PDF JavaScript, packers, archive bombs, etc.), computing entropy and IOC data, and correlating findings with threat intelligence (VirusTotal hashes, YARA rule matches). The output is deterministic, explainable, and reproducible — critical properties for a forensic security tool whose findings may be reviewed by a human analyst or fed into an AI explainability layer.

ATAE sits logically between **Email Parsing** (which extracts raw attachment bytes and MIME metadata from a message) and **Email Threat Detection** (which fuses attachment findings with header, URL, and sender signals into a final classification).

---

## 2. Design Goals

1. **Determinism first.** Every analysis step must be reproducible given the same input file. Non-deterministic techniques (dynamic execution, ML inference) are explicitly out of scope for this phase and are called out separately in sections 25–26.
2. **Defense in depth per file type.** Each supported file type has its own analysis strategy rather than a generic "one size fits all" scanner, mirroring the design philosophy of enterprise SEG products.
3. **Fail-safe, not fail-open.** Any parser failure, timeout, or resource exhaustion must resolve to a conservative ("suspicious" or "unknown — quarantine for review") verdict rather than silently passing the attachment as clean.
4. **Explainability.** Every risk score contributor must be traceable to a specific finding, file offset, or extracted artifact, so the Gemini Explainability module can generate human-readable narratives.
5. **Isolation.** Attachment content is inherently untrusted. All parsing must occur in a hardened, resource-constrained execution context that assumes parser libraries themselves may be exploitable.
6. **Extensibility.** New file-type analyzers, new YARA rules, and new IOC extractors must be pluggable without modifying the core pipeline.
7. **Bounded resource consumption.** Archive bombs, decompression bombs, and pathological files must not be able to exhaust CPU, memory, or disk on the host.
8. **Auditability.** Every analysis run produces a structured, versioned artifact (the "Attachment Forensic Record") suitable for compliance retention and later re-review.

---

## 3. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR-1 | The engine shall accept an attachment payload plus MIME metadata (declared filename, declared content-type, size) as input. |
| FR-2 | The engine shall verify true file type via magic-byte/signature inspection independent of declared metadata. |
| FR-3 | The engine shall detect mismatches between declared extension/MIME type and actual file type (fake extension detection). |
| FR-4 | The engine shall route the file to the correct type-specific analyzer based on verified type. |
| FR-5 | The engine shall recursively unpack archive formats (ZIP, RAR, 7Z, TAR, GZ) up to a configurable nesting depth. |
| FR-6 | The engine shall detect and safely abort processing of archive/decompression bombs before resource exhaustion occurs. |
| FR-7 | The engine shall parse Office Open XML and legacy OLE-based documents to detect macros, DDE fields, embedded objects, and auto-executing constructs. |
| FR-8 | The engine shall parse PDF structure to detect JavaScript, OpenAction/Launch actions, embedded files, and embedded URLs. |
| FR-9 | The engine shall perform static analysis of PE (EXE/DLL/SYS) files including header inspection, section analysis, import table review, packer detection, and signature validation. |
| FR-10 | The engine shall statically analyze script files (JS, VBS, BAT, CMD, PS1, SH, PY) for obfuscation patterns, suspicious API/command usage, and embedded payloads (e.g., Base64). |
| FR-11 | The engine shall analyze image files for steganography indicators and metadata-based risk (EXIF anomalies, polyglot file structure). |
| FR-12 | The engine shall extract IOCs (URLs, IPs, domains, email addresses, file hashes, registry keys, mutexes where derivable statically) from every analyzed file. |
| FR-13 | The engine shall compute file entropy at whole-file and per-section granularity to flag packing/encryption. |
| FR-14 | The engine shall submit computed hashes (MD5/SHA1/SHA256) to the existing VirusTotal integration for reputation lookup. |
| FR-15 | The engine shall execute a YARA rule corpus against every file and record all matches. |
| FR-16 | The engine shall compute a composite Risk Score (0–100) with a documented, inspectable scoring rationale. |
| FR-17 | The engine shall apply false-positive reduction heuristics before finalizing a verdict. |
| FR-18 | The engine shall produce a structured Attachment Forensic Record consumable by the PDF Report Generator and Gemini Explainability module. |
| FR-19 | The engine shall handle encrypted/password-protected archives and documents by flagging them as suspicious-by-default when contents cannot be inspected, while still recording available metadata. |
| FR-20 | The engine shall enforce timeouts and resource ceilings per file and per analysis stage. |
| FR-21 | The engine shall never execute, render, or open an attachment with its native application; all analysis is static/structural. |

---

## 4. Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| Performance | 95th percentile analysis time ≤ 8 seconds for files ≤ 25 MB under normal load (excluding external TI lookups). |
| Scalability | Stateless worker design allowing horizontal scale-out via queue-based job distribution. |
| Reliability | A single malformed/malicious file must not crash the worker process (process isolation, see §29). |
| Security | No attachment content is ever executed, interpreted, or rendered by a full-featured application (e.g., no invoking Word/Adobe Reader). |
| Observability | Every stage emits structured logs and timing metrics. |
| Determinism | Identical input files must produce identical structural findings across runs (excluding TI/YARA corpus version drift, which is versioned). |
| Data Retention | Extracted artifacts and forensic records follow the platform's existing retention policy; raw malicious payloads are stored encrypted-at-rest in isolated storage, not in the primary database. |
| Portability | Core analyzers implemented in Python 3.11+, containerized, with no dependency on OS-specific execution (e.g., no reliance on Windows APIs for PE analysis — pure parsing only). |

---

## 5. High-Level Architecture

ATAE is composed of five architectural layers:

1. **Ingestion & Triage Layer** — receives the attachment, verifies true type, performs fake-extension detection, and routes to the correct analyzer.
2. **Type-Specific Static Analysis Layer** — a set of pluggable analyzers (Archive, PDF, Office, Executable, Script, Image, Generic/Fallback).
3. **Cross-Cutting Analysis Layer** — services used by every analyzer regardless of type: Entropy Engine, IOC Extractor, YARA Engine, Hashing Service, Metadata Inspector.
4. **Intelligence Correlation Layer** — correlates static findings with external threat intelligence (VirusTotal via existing integration) and internal reputation history.
5. **Scoring & Reporting Layer** — Risk Scoring Engine, False Positive Reduction, and Forensic Record Assembly, which hands off to the existing PDF Report Generator and Gemini Explainability module.

ATAE is invoked synchronously or asynchronously (queue-based, recommended for production) by the Email Threat Detection module once Email Parsing has extracted attachment bytes. It does not directly touch Gmail Integration, Header Analysis, URL Analysis (message-body URLs), SPF/DKIM/DMARC, or Sender Analysis — those remain untouched, existing modules. ATAE's output (Attachment Verdict + Forensic Record) is one input among several that Email Threat Detection fuses into the final message-level verdict.

---

## 6. Component Diagram

```
                          ┌────────────────────────────┐
                          │   Email Parsing (existing)  │
                          │  → raw attachment bytes +    │
                          │    MIME metadata             │
                          └──────────────┬───────────────┘
                                         │
                                         ▼
                     ┌─────────────────────────────────────┐
                     │   ATAE — Ingestion & Triage Layer     │
                     │  • Magic-byte identification          │
                     │  • Fake-extension detection            │
                     │  • Size/type policy gate                │
                     │  • Analyzer routing                     │
                     └───────────────┬─────────────────────┘
                                     │
        ┌────────────────────────────┼──────────────────────────────┐
        ▼                            ▼                              ▼
┌───────────────┐          ┌──────────────────┐            ┌──────────────────┐
│ Archive        │          │ PDF Analyzer      │            │ Office Analyzer   │
│ Analyzer       │◄────────►│                    │            │ (OOXML + OLE)      │
│ (recursive)    │  feeds   │                    │            │                    │
└───────┬────────┘  back    └─────────┬──────────┘            └─────────┬──────────┘
        │                             │                                 │
        ▼                             ▼                                 ▼
┌───────────────┐          ┌──────────────────┐            ┌──────────────────┐
│ Executable     │          │ Script Analyzer    │            │ Image Analyzer     │
│ Analyzer (PE/  │          │ (JS/VBS/PS1/BAT/   │            │ (stego/EXIF/       │
│ ELF/APK/JAR)   │          │  SH/PY)             │            │  polyglot)          │
└───────┬────────┘          └─────────┬──────────┘            └─────────┬──────────┘
        │                             │                                 │
        └──────────────┬──────────────┴────────────────┬────────────────┘
                        ▼                                ▼
          ┌─────────────────────────────────────────────────────┐
          │        Cross-Cutting Analysis Layer                    │
          │  • Entropy Engine   • IOC Extractor                    │
          │  • YARA Engine      • Hashing Service                  │
          │  • Metadata Inspector                                   │
          └───────────────────────────┬─────────────────────────┘
                                       ▼
          ┌─────────────────────────────────────────────────────┐
          │      Intelligence Correlation Layer                    │
          │  • VirusTotal client (existing integration)             │
          │  • Internal hash/reputation cache                        │
          └───────────────────────────┬─────────────────────────┘
                                       ▼
          ┌─────────────────────────────────────────────────────┐
          │        Scoring & Reporting Layer                        │
          │  • Risk Scoring Engine                                    │
          │  • False Positive Reduction                               │
          │  • Attachment Forensic Record Assembly                     │
          └───────────────┬───────────────────────┬─────────────┘
                           ▼                       ▼
              ┌────────────────────┐   ┌─────────────────────────┐
              │ Email Threat        │   │ Gemini Explainability /   │
              │ Detection (existing)│   │ PDF Report Gen (existing)  │
              └────────────────────┘   └─────────────────────────┘
```

---

## 7. Sequence Diagram

```
Email Parsing        Ingestion/Triage      Type Analyzer      Cross-Cutting        Intel Layer         Scoring Layer      Threat Detection
     │                      │                     │                  │                   │                    │                   │
     │  attachment bytes +  │                     │                  │                   │                    │                   │
     │  MIME metadata       │                     │                  │                   │                    │                   │
     ├─────────────────────►│                     │                  │                   │                    │                   │
     │                      │ magic-byte ID        │                  │                   │                    │                   │
     │                      │ fake-ext check        │                  │                   │                    │                   │
     │                      │ route by type          │                  │                   │                    │                   │
     │                      ├────────────────────►│                  │                   │                    │                   │
     │                      │                     │ type-specific     │                   │                    │                   │
     │                      │                     │ structural parse  │                   │                    │                   │
     │                      │                     ├─────────────────►│                   │                    │                   │
     │                      │                     │                  │ entropy, IOC,      │                    │                   │
     │                      │                     │                  │ YARA, hashing        │                    │                   │
     │                      │                     │                  ├──────────────────►│                    │                   │
     │                      │                     │                  │                   │ VT reputation       │                   │
     │                      │                     │                  │                   │ lookup by hash        │                   │
     │                      │                     │                  │                   ├───────────────────►│                   │
     │                      │                     │                  │                   │                    │ compute risk       │
     │                      │                     │                  │                   │                    │ score + FP filter    │
     │                      │                     │                  │                   │                    ├──────────────────►│
     │                      │                     │                  │                   │                    │  Attachment Verdict │
     │                      │                     │                  │                   │                    │  + Forensic Record   │
     │                      │                     │                  │                   │                    │                   ▼
     │                      │                     │                  │                   │                    │           fused into
     │                      │                     │                  │                   │                    │        final message
     │                      │                     │                  │                   │                    │           verdict
```

---

## 8. Processing Pipeline

The pipeline executes as a sequence of bounded, individually-timed stages. Each stage produces a partial result appended to a shared `AnalysisContext` object that accompanies the file through the pipeline.

1. **Intake** — receive bytes + declared metadata; assign a unique `analysis_id`; create isolated temp workspace (§30).
2. **Hashing** — compute MD5/SHA1/SHA256 immediately (needed for TI lookup and dedup cache).
3. **Reputation Short-Circuit (optional optimization)** — check internal cache/VirusTotal for a known-bad or known-good hash; if a high-confidence prior verdict exists and is not stale, short-circuit to steps 9–11 while still recording that a full re-analysis was skipped (never silently reused for first-seen files).
4. **True-Type Identification** — magic byte / container signature inspection.
5. **Extension/MIME Consistency Check** — compare declared vs. actual; record mismatch as a finding.
6. **Policy Gate** — enforce size limits, blocked-type policy (if organizationally configured), and depth limits before deep parsing.
7. **Type-Specific Structural Analysis** — dispatch to the matching analyzer (§13–19).
8. **Cross-Cutting Analysis** — entropy, IOC extraction, YARA scanning, metadata inspection (run in parallel where independent).
9. **Threat Intelligence Correlation** — submit hashes to VirusTotal integration; merge results.
10. **Risk Scoring** — aggregate all findings into a weighted composite score.
11. **False-Positive Reduction** — apply contextual heuristics/allow-list logic.
12. **Forensic Record Assembly** — serialize full findings, evidence, and verdict.
13. **Cleanup** — securely wipe temp workspace (§30), release resources.
14. **Emit Verdict** — return `AttachmentVerdict` + `ForensicRecord` to Email Threat Detection.

Each stage has an individual timeout; exceeding it marks that stage `INCOMPLETE` and contributes a "could not be fully analyzed" penalty to the risk score rather than halting the whole pipeline (fail-safe principle, §2).

---

## 9. Internal Module Responsibilities

| Component | Responsibility | Explicitly NOT Responsible For |
|-----------|-----------------|-------------------------------|
| Ingestion & Triage | Type identification, routing, policy gating | Deep content parsing |
| Archive Analyzer | Safe recursive extraction, bomb detection | Analyzing extracted files' content (delegates back to Ingestion & Triage per extracted file) |
| PDF Analyzer | Object/stream parsing, JS/action detection | Rendering the PDF visually |
| Office Analyzer | Macro/OLE/DDE parsing | Executing macros |
| Executable Analyzer | Header/section/import static analysis | Running the binary |
| Script Analyzer | Static pattern & deobfuscation analysis | Executing the script |
| Image Analyzer | Metadata/stego/polyglot checks | OCR or visual content classification (future ML, §25) |
| Entropy Engine | Whole-file and segment entropy computation | Interpreting entropy alone as a verdict |
| IOC Extractor | Regex/parser-based extraction of URLs, IPs, domains, hashes | Reputation scoring of extracted IOCs (delegated to Intelligence Correlation) |
| YARA Engine | Rule compilation, matching, match metadata capture | Rule authorship/maintenance workflow (§22 covers governance) |
| Hashing Service | MD5/SHA1/SHA256, fuzzy hash (ssdeep) computation | TI lookups |
| Intelligence Correlation | VT queries, internal reputation cache | Any static parsing |
| Risk Scoring Engine | Weighted aggregation, verdict banding | Explaining the verdict in natural language (delegated to Gemini Explainability) |
| False Positive Reduction | Allow-listing, context suppression rules | Overriding hard-block findings (e.g., confirmed known-malware hash cannot be suppressed) |
| Forensic Record Assembler | Structured, versioned output object | Rendering the PDF (delegated to existing PDF Report Generator) |

---

## 10. Analysis Workflow

For every attachment, the workflow answers four forensic questions in order:

1. **"What is this file, really?"** — true-type identification independent of what it claims to be.
2. **"What does this file contain / what can it do?"** — structural decomposition: embedded objects, code, macros, actions, nested files.
3. **"Is what it contains known-bad, obfuscated, or anomalous?"** — YARA matching, entropy analysis, IOC reputation, deobfuscation of suspicious patterns.
4. **"Given everything found, how risky is this attachment?"** — scoring, false-positive suppression, final verdict banding (Clean / Suspicious / Malicious / Unknown-Quarantine).

This four-question structure is intentionally mirrored in the Forensic Record so a human reviewer or the Gemini Explainability module can narrate findings in the same logical order a security analyst would.

---

## 11. Supported File Types

Documents: PDF, DOC, DOCX, DOCM, XLS, XLSM, PPT, PPTM
Archives: ZIP, RAR, 7Z, TAR, GZ (including nested and encrypted variants)
Executables/Binaries: EXE, DLL, SYS, APK, JAR, ISO, LNK
Scripts: JS, VBS, BAT, CMD, PS1, SH, PY
Web/Markup/Data: HTML, XML, CSV, TXT
Images: JPEG, PNG, GIF, BMP, TIFF, WEBP (and others via a generic image handler)

Unknown or unsupported types fall through to a **Generic Static Analyzer** (§ below in 12) that still performs magic-byte checks, entropy, hashing, and IOC scanning, and defaults to a "Suspicious — Unrecognized Type" banding contribution if the file also fails the extension-consistency check.

---

## 12. Analysis Strategy For Every File Type

| Type Family | Primary Techniques Applied |
|---|---|
| PDF | Object graph parsing, JavaScript extraction, OpenAction/Launch detection, embedded file extraction, URI extraction |
| Office (OOXML: DOCX/XLSM/PPTM) | Relationship/part parsing, VBA project extraction, macro static analysis, DDE field detection, external reference detection |
| Office (Legacy OLE: DOC/XLS/PPT) | OLE Compound File Binary parsing, VBA extraction, embedded object streams |
| Archives (ZIP/7Z/TAR/GZ/RAR) | Recursive safe extraction, compression-ratio bomb detection, nested-archive depth tracking, per-entry re-routing through triage |
| Executables (EXE/DLL/SYS) | PE header parsing, section table analysis, import/export table review, entropy per section, packer signature detection, Authenticode signature validation |
| APK | ZIP-container parsing, manifest extraction, permission review, embedded DEX entropy check |
| JAR | ZIP-container parsing, manifest analysis, embedded class file inventory |
| Scripts (JS/VBS/PS1/BAT/CMD/SH/PY) | Static lexical analysis, obfuscation-pattern detection, Base64/hex payload extraction, suspicious API/cmdlet detection |
| HTML | DOM parsing for embedded scripts, iframes, form actions, credential-harvesting patterns, obfuscated JS |
| XML | External entity (XXE) pattern detection, embedded script/macro references (e.g., OOXML disguised as plain XML) |
| CSV | Formula-injection pattern detection (`=`, `+`, `-`, `@` cell prefixes — CSV/DDE injection) |
| TXT | Low-priority: entropy + IOC scan only |
| Images | Magic-byte/container validation, EXIF metadata review, polyglot detection (e.g., a file that is simultaneously a valid image and a valid ZIP/HTML/JS), basic steganography statistical indicators |
| ISO/LNK | Container inspection for embedded executables/scripts; LNK target-path and argument parsing for living-off-the-land command injection |
| Unrecognized | Generic Static Analyzer: magic bytes, entropy, hashing, IOC scan, extension-consistency check only |

---

## 13. Static Analysis Design

All analyzers operate exclusively on file bytes at rest — no interpreter, renderer, or virtual machine is invoked. The static analysis subsystem is organized as a **plugin registry**: each analyzer implements a common interface contract (`analyze(file_bytes, context) -> AnalyzerFindings`) and is registered against one or more true-type identifiers resolved during Ingestion & Triage. This allows new analyzers (e.g., a future RTF or MSG analyzer) to be added without modifying the pipeline core.

Static analysis is split into three tiers applied to every file regardless of type:

- **Tier 1 — Container Identification:** magic bytes, file signatures, container structure validation (is this actually a valid instance of its claimed format?).
- **Tier 2 — Structural Decomposition:** type-specific parsing to enumerate the file's internal objects (streams, sections, entries, macros, actions).
- **Tier 3 — Semantic Risk Interpretation:** applying rule-based logic to decomposed structures (e.g., "this PDF has both `/OpenAction` and `/JavaScript`" → elevated finding).

Findings are captured as structured `Finding` objects with: `technique_id`, `severity`, `evidence_locator` (byte offset, object ID, or stream name), `description`, and `confidence`.

---

## 14. Archive Analysis Design

**Recursive Safe Extraction Policy:**
- Maximum nesting depth: configurable, default 5 levels.
- Maximum total decompressed size: configurable ceiling (default 500 MB) tracked cumulatively across the whole nesting tree, not per-archive.
- Maximum single-entry compression ratio: entries exceeding a configured ratio (e.g., >100:1) trigger an immediate **Archive Bomb** finding and extraction of that entry halts.
- Maximum entry count per archive: configurable ceiling to catch "many small files" bombs.
- Extraction occurs into the isolated temp workspace (§30) with per-extraction resource ceilings (CPU time, memory) enforced by the process isolation layer (§29).

**Per-Entry Handling:** each successfully extracted entry is independently re-submitted to Ingestion & Triage (step 4 of the pipeline) so it receives full true-type identification and is routed to its own correct analyzer — a script hidden inside a ZIP with a decoy `.jpg` extension is still identified correctly because true-type detection, not the entry's stated name, drives routing.

**Encrypted Archives:** if password protection prevents extraction, the archive is flagged with an **Encrypted Content — Unable to Inspect** finding, which contributes a moderate-to-high risk weight by default (encrypted attachments are a common evasion technique to bypass content inspection), while still recording available metadata (entry names, entry count, compression method).

**Nested Archive Tracking:** the `AnalysisContext` carries a running `nesting_path` (e.g., `outer.zip > inner.rar > payload.js`) so findings on deeply nested files retain full provenance in the Forensic Record.

---

## 15. PDF Analysis Design

The PDF Analyzer performs object-graph parsing (not rendering) of the PDF's cross-reference table and object streams to enumerate:

- `/JavaScript` and `/JS` objects — extracted and passed to the Script Analyzer's static JS analysis for obfuscation/pattern detection.
- `/OpenAction` and `/AA` (Additional Actions) — flagged as auto-execution triggers, with elevated severity when combined with JavaScript or Launch actions.
- `/Launch` actions — flagged as high severity (direct external program execution intent).
- `/EmbeddedFile` streams — extracted and re-routed through Ingestion & Triage as independent attachments (same provenance-tracking approach as archive entries).
- URI actions and annotation links — extracted as IOCs (embedded URLs).
- Object stream and cross-reference anomalies (e.g., objects present in the file but unreachable from the trailer — a common evasion/obfuscation technique) — flagged as **Structural Anomaly**.
- Incremental update chains — multiple `%%EOF` markers can indicate a PDF that was modified post-creation to inject malicious objects; flagged as **Suspicious Incremental Update**.
- Encryption dictionary presence — flagged similarly to encrypted archives when content streams cannot be fully inspected.

---

## 16. Office Document Analysis Design

**OOXML (DOCX/XLSM/PPTM):** parsed as a ZIP container (reusing the Archive Analyzer's safe-extraction primitives) to walk `[Content_Types].xml` and relationship parts. The VBA project (`vbaProject.bin`), if present, is extracted and parsed as an OLE Compound File.

**Legacy OLE (DOC/XLS/PPT):** parsed directly as OLE Compound File Binary Format to enumerate streams, including the `Macros`/`VBA` storage.

**Macro Analysis (both formats):**
- Extraction of VBA source via p-code/stream decompression.
- Detection of auto-executing macro names: `AutoOpen`, `AutoExec`, `AutoClose`, `Document_Open`, `Workbook_Open`, `Auto_Open`.
- Detection of suspicious API call patterns commonly used in malicious macros (process creation, shell execution, file write, registry access, WinAPI declarations via `Declare`).
- Detection of obfuscation indicators: excessive string concatenation, `Chr()`/`Chr$()` character-code obfuscation chains, unusually high ratio of non-printable or encoded content.

**DDE Attack Detection:** scanning for DDEAUTO/DDE field codes in document XML/streams, a known technique for command execution without macros.

**External Reference Detection:** template injection and remote-relationship checks (e.g., a `.docx` whose `document.xml.rels` points to an external template URL — remote template injection).

**Embedded Object Detection:** OLE package objects and embedded files within the document are extracted and re-routed through Ingestion & Triage, identically to PDF embedded files and archive entries.

---

## 17. Executable Analysis Design

Applies to EXE, DLL, SYS (PE format), and extends to APK/JAR via their container formats.

- **PE Header Validation:** DOS header, NT headers, and section table are parsed and validated for structural consistency; malformed-but-loadable PE files (a known evasion technique against naive parsers) are flagged as **Malformed PE Structure**.
- **Section Analysis:** per-section entropy (feeds the Entropy Engine, §20) to identify packed/encrypted code sections; unusual section names or executable-flagged sections outside the norm (e.g., a `.text` section with write permission) are flagged.
- **Import/Export Table Review:** enumeration of imported APIs against a curated watchlist of functions commonly associated with malicious behavior (process injection, credential access, anti-debugging, persistence) — presence alone is not a verdict but contributes weighted findings.
- **Packer Detection:** signature-based detection of common packers/protectors combined with high overall entropy as corroborating evidence.
- **Digital Signature Validation:** Authenticode signature presence, validity chain, and signer reputation cross-check; unsigned executables, invalidly signed executables, and **signature abuse patterns** (e.g., a valid signature whose signed hash does not match the actual file hash) are each distinct findings with different severities.
- **Resource Section Review:** enumeration of embedded resources (icons, version info, and notably embedded PE files within resources — a common dropper technique).
- **APK-Specific:** manifest parsing for dangerous permission combinations, and DEX entropy as a packing/obfuscation indicator.
- **JAR-Specific:** manifest and class file inventory; class file magic-byte validation.

---

## 18. Script Analysis Design

Applies to JS, VBS, BAT, CMD, PS1, SH, PY, and JavaScript extracted from PDFs/HTML.

- **Lexical/Static Pattern Analysis:** identification of suspicious API/cmdlet usage per language (e.g., PowerShell `-EncodedCommand`, `IEX`, `DownloadString`; VBScript `CreateObject("WScript.Shell")`; Bash `curl | sh` patterns).
- **Obfuscation Detection:** heuristics for string concatenation chains, character-code arrays, excessive whitespace/comment padding, and known obfuscator signatures (e.g., common JS obfuscation library fingerprints).
- **Base64/Hex Payload Extraction:** detection and extraction of encoded blocks above a length threshold; extracted payloads are decoded (data transformation only, never executed) and recursively re-analyzed as an embedded artifact with full provenance tracking.
- **Layered Deobfuscation:** iterative decode passes (Base64 → gzip → Base64, etc., a common multi-layer obfuscation chain) up to a configurable depth ceiling, mirroring the archive nesting-depth safeguard.
- **Living-off-the-Land Indicators:** references to legitimate system binaries commonly abused for malicious purposes (LOLBins) within scripts.

---

## 19. Image Analysis Design

- **Container/Magic-Byte Validation:** confirms the file is a structurally valid instance of its claimed image format.
- **Polyglot Detection:** checks whether the file is simultaneously valid as another format (e.g., a JPEG that is also a valid ZIP or HTML document) — a known technique to smuggle payloads past filters that only check the leading magic bytes.
- **EXIF/Metadata Review:** flags anomalous or oversized metadata fields, embedded scripts within metadata fields (e.g., XMP), and GPS/author metadata exposure (privacy-relevant finding, lower severity).
- **Steganography Indicators:** statistical analysis (e.g., chi-square/LSB distribution anomalies) to flag images with a statistically anomalous bit-plane distribution suggestive of hidden payloads; this is an *indicator*, not a confirmed extraction, and is scored/labeled accordingly to avoid overstating confidence.
- **Trailing Data Detection:** identification of appended data after the image's expected end-of-file marker, a common technique for hiding secondary payloads within an otherwise valid image.

---

## 20. IOC Extraction Design

A shared cross-cutting service applied to every analyzed file's extracted text/structural content (not just top-level files):

- **URLs/Domains:** regex and structural extraction (PDF URI actions, HTML `href`/`src`, script string literals, Office document relationships).
- **IP Addresses:** IPv4/IPv6 pattern extraction with private/reserved range filtering to reduce noise.
- **Email Addresses:** extracted from script/document content (relevant for phishing kit identification).
- **File Hashes:** any hash-like strings found within content (e.g., a script referencing a payload hash) are extracted as secondary IOCs.
- **Registry Keys / Mutex Names / File Paths:** extracted from script and executable string tables via static string extraction, where statically derivable.

All extracted IOCs are attached to the Forensic Record with their `evidence_locator` (which file, which offset/object) and are separately passed to the Intelligence Correlation Layer for reputation lookup where existing infrastructure (VirusTotal, Safe Browsing) supports the IOC type.

---

## 21. Threat Intelligence Integration

ATAE reuses the **existing** VirusTotal integration and Google Safe Browsing integration rather than introducing new external clients.

- **Hash Reputation:** every computed SHA256 (and fuzzy hash, see below) is submitted to the existing VirusTotal client; results (detection ratio, vendor labels, first-seen date) are merged into the Forensic Record and contribute directly to the Risk Scoring Engine.
- **Fuzzy Hashing (ssdeep):** in addition to cryptographic hashes, a fuzzy hash is computed to enable similarity matching against previously seen malicious samples in the internal reputation cache, catching minor variants of known threats that would otherwise produce a different SHA256.
- **URL/Domain IOCs:** extracted URLs are passed to the existing Safe Browsing / URL Analysis integration rather than duplicating that capability inside ATAE.
- **Internal Reputation Cache:** a lightweight internal store (hash → last verdict, last seen) avoids redundant external API calls for previously analyzed identical files, subject to a staleness TTL that forces periodic re-verification.

---

## 22. YARA Integration

- **Rule Corpus Management:** YARA rules are organized into namespaced categories (e.g., `office_macros`, `pe_packers`, `pdf_exploits`, `script_obfuscation`, `webshells`, `generic_iocs`) sourced from curated open-source rule sets plus internally authored rules.
- **Compilation Strategy:** rules are pre-compiled and cached at worker startup; a rule-corpus version identifier is recorded in every Forensic Record so that historical verdicts can be understood in the context of the rule set that produced them.
- **Scan Targets:** YARA is run against (a) the raw top-level file, (b) every recursively extracted/embedded artifact, and (c) any decoded payloads produced by script deobfuscation.
- **Match Handling:** each match contributes a `Finding` with the rule name, matched strings/offsets, and the rule's declared severity metadata (rules are authored with a standardized severity tag convention).
- **Governance:** rule updates go through the same change-management process as other detection-content updates (versioned, tested against a regression corpus of known-clean files to monitor false-positive rate before promotion).

---

## 23. Risk Scoring Engine

**Scoring Model:** a weighted, additive composite score (0–100), where each `Finding` contributes a base weight modified by its `confidence` and `severity`, capped and normalized to prevent any single low-confidence heuristic from dominating the score.

**Illustrative Weight Bands (for design purposes — final calibration is a tuning exercise, not fixed policy):**

| Finding Category | Base Weight Range |
|---|---|
| Confirmed VirusTotal detection (multiple vendors) | 40–100 (near-deterministic hard signal) |
| YARA match on high-confidence malware rule | 25–40 |
| Auto-executing macro/action + suspicious API pattern combined | 20–35 |
| Fake extension / magic-byte mismatch | 15–25 |
| Archive bomb / decompression anomaly | 20–30 |
| High entropy without corroborating structural finding | 5–15 |
| Encrypted content unable to inspect | 10–20 |
| Single weak heuristic in isolation (e.g., one suspicious string) | 1–5 |

**Verdict Banding:**
- 0–19: **Clean**
- 20–49: **Suspicious**
- 50–79: **Malicious — High Confidence**
- 80–100: **Malicious — Confirmed** (typically driven by a hard TI/YARA signal)
- Special band: **Unknown — Quarantine for Review**, applied when critical analysis stages were `INCOMPLETE` (timeouts, encrypted content, parser failure) regardless of the numeric score, per the fail-safe principle.

**Score Composition Transparency:** the Forensic Record stores the full list of contributing findings with their individual weights so the final score is always traceable to specific evidence — required for the Gemini Explainability module to generate an accurate narrative and for human analyst review.

---

## 24. False Positive Reduction Strategy

- **Context-Aware Suppression, Not Deletion:** suppressed findings remain visible in the Forensic Record marked `suppressed: true` with a suppression reason — never silently discarded — preserving auditability.
- **Publisher/Signature Allow-listing:** executables with a valid, trusted-chain digital signature from a known-reputable publisher receive a scoring dampener (not a full bypass) for lower-severity heuristic findings.
- **Legitimate Macro Pattern Recognition:** a curated set of benign, extremely common macro patterns (e.g., standard mail-merge boilerplate) reduces false-positive weight when present *without* any co-occurring suspicious API/action pattern.
- **Organizational Allow-lists:** hash- and sender-domain-based allow-lists (configured at the platform level, outside ATAE) can suppress repeated internal false positives for known internal tooling — implemented as a post-scoring override consulted by Email Threat Detection, not baked into ATAE's core scoring to keep ATAE's output independently trustworthy.
- **Hard-Block Non-Overridable Findings:** a small set of findings (e.g., confirmed multi-vendor VirusTotal malware detection) are explicitly exempted from any suppression logic.
- **Confidence-Weighted Aggregation:** the scoring model itself (§23) is the primary false-positive control — no single weak heuristic can independently push a file into the Malicious band.

---

## 25. Future Machine Learning Integration

This phase is explicitly deterministic/static (§2 Goal 1). A future phase may introduce a supervised ML classifier trained on the structural features ATAE already extracts (entropy profiles, import table composition, macro API n-grams, YARA match vectors) rather than raw bytes, allowing the existing local ML Email Classification model's infrastructure to be extended with an attachment-specific feature pipeline. Design implication for this phase: **every analyzer must emit findings in a structured, feature-friendly schema** (not just human-readable strings) so that this future integration does not require re-architecting the analyzers.

---

## 26. Future AI Integration

Beyond the existing Gemini Explainability module (which narrates *why* a verdict was reached), a future phase could use an LLM to assist analysts with ambiguous **Unknown — Quarantine** cases by summarizing extracted script/macro content in natural language to accelerate manual triage. This is explicitly a human-assistive summarization function, not an autonomous verdict-issuing function — the deterministic Risk Scoring Engine remains the sole source of the numeric verdict to preserve auditability and reproducibility.

---

## 27. Attachment Forensic Report Design

The **Attachment Forensic Record** is the structured artifact ATAE produces per attachment; it is a distinct input consumed by the *existing* PDF Report Generator (which already produces the overall email forensic PDF) and the Gemini Explainability module. ATAE does not generate the PDF itself.

Record contents:
- `analysis_id`, timestamps, ATAE/rule-corpus version identifiers.
- File identity: declared vs. true type, filename, size, all computed hashes.
- Full nesting/provenance tree for extracted/embedded artifacts.
- Ordered list of all `Finding` objects (technique, severity, confidence, evidence locator, suppression status).
- Entropy profile (whole-file and per-section where applicable).
- Full IOC list with type and evidence locator.
- YARA match list with rule name and namespace.
- Threat intelligence correlation results (VT detection ratio, vendor labels, fuzzy-hash similarity matches).
- Final risk score, band, and human-readable score-composition breakdown.
- Stage-completion status (to surface any `INCOMPLETE` stages driving an `Unknown` verdict).

---

## 28. Performance Considerations

- **Parallelizable Stages:** entropy computation, IOC extraction, and YARA scanning are independent of each other and are executed concurrently once structural parsing yields extractable content.
- **Early-Exit on Hard Signals:** if a top-level hash returns a high-confidence multi-vendor VirusTotal detection, deep structural parsing may still complete (for forensic completeness) but is de-prioritized in scheduling relative to files with no prior signal.
- **Archive Extraction Cost Control:** streaming decompression with cumulative size tracking avoids materializing an entire bomb before detecting it.
- **Caching:** hash-based reputation caching (§21) avoids redundant external calls for duplicate attachments across different emails, a common occurrence in bulk phishing campaigns.
- **Worker Pool Sizing:** stateless workers scaled horizontally behind a job queue; per-job resource ceilings (§29) allow safe overcommit of worker count relative to host resources.

---

## 29. Security Considerations

- **Untrusted Input Assumption:** every parsing library used is treated as a potential exploitation target; the entire ATAE worker executes as an unprivileged, network-egress-restricted process, in its own container/sandbox separate from the main Django application process, communicating only via the job queue and object storage.
- **No Native Rendering/Execution:** attachments are never opened by Word, Adobe Reader, a browser engine, or an OS shell — all parsing is via dedicated static-parsing libraries operating on bytes.
- **Resource Ceilings Per Job:** CPU time, memory, and disk I/O ceilings enforced at the container/cgroup level, independent of application-level timeouts, as a second line of defense against pathological inputs.
- **Process-Per-File Isolation (optional hardening tier):** for high-risk type families (executables, scripts), spawning a fresh subprocess per file (rather than reusing a long-lived worker process) limits blast radius if a parser is exploited.
- **Least-Privilege Storage Access:** the temp workspace and any extracted-artifact storage are isolated from the primary PostgreSQL database and from any credentialed Gmail API access — ATAE workers do not require Gmail Integration credentials at all.
- **Output Sanitization:** any file paths, strings, or metadata extracted from attachments and destined for the Forensic Record (and ultimately a PDF/HTML report or an LLM prompt to Gemini) are sanitized/escaped to prevent injection into downstream rendering or prompt contexts.

---

## 30. Temporary Storage Strategy

- Each analysis job receives a dedicated, uniquely named temp workspace directory, created at job start and **securely wiped** (not just deleted — overwritten where the underlying storage medium warrants it) at job end regardless of success/failure path.
- Extracted artifacts that contribute to a **Malicious** or **Suspicious** verdict are retained (encrypted at rest, access-logged) in an isolated evidence store for the platform's configured retention period, separate from the primary database, to support later investigation.
- Extracted artifacts from a **Clean** verdict are not retained beyond the analysis job lifetime, to minimize the platform's own exposure to hosting potentially sensitive user content.
- Workspace size is bounded by the cumulative decompression ceiling (§14) and enforced independently by disk quota at the container level.

---

## 31. Resource Management

- Per-stage timeouts (§8) and per-job hard resource ceilings (§29) are both enforced; per-stage timeout is the primary control, the per-job ceiling is the backstop.
- Nesting depth (archives, embedded objects, deobfuscation layers) is tracked as a single unified counter in `AnalysisContext` so that combining techniques (e.g., a script inside an archive inside a document) cannot bypass any individual depth limit.
- Job queue implements backpressure so a burst of large/complex attachments degrades throughput gracefully rather than exhausting host resources.

---

## 32. Error Handling

- **Parser Exceptions:** caught at the individual analyzer boundary; recorded as an `INCOMPLETE` stage finding with the exception category (not full stack trace, to avoid leaking internal detail into the Forensic Record) and do not crash the pipeline for that file.
- **Timeout Exceptions:** treated identically to parser exceptions — `INCOMPLETE` stage, contributes to `Unknown — Quarantine` banding when the incomplete stage is structurally significant (e.g., inability to fully parse a PE header), but not when it's a non-critical stage (e.g., steganography statistical check timing out on the current file).
- **External Dependency Failures (VirusTotal unavailable, etc.):** degrade gracefully — static findings and score still produced, TI-derived score component recorded as `UNAVAILABLE` rather than assumed clean.
- **Retry Policy:** transient failures (network calls to TI services) are retried with backoff at the job level; parser-level failures on the file itself are not retried (deterministic — retrying won't change the outcome) but are logged for corpus/analyzer improvement.

---

## 33. Logging Strategy

- **Structured, per-stage logs** keyed by `analysis_id`, including stage name, duration, outcome, and (for failures) an error category.
- **Security-relevant audit log** separate from operational logs: every access to a retained malicious artifact (§30) is logged with actor and timestamp.
- **No sensitive payload content in logs:** raw attachment bytes, decoded script/macro content, and extracted IOC values are referenced by ID/locator in operational logs, not embedded directly, to keep logs safe to ship to a general-purpose log aggregator.
- **Metrics emitted:** per-stage latency histograms, verdict-band distribution, YARA match rate, TI-cache hit rate, and `INCOMPLETE`-stage rate (a key health metric — a rising rate indicates parser gaps or resource pressure needing attention).

---

## 34. Deployment Requirements

- Containerized worker image, isolated network egress policy (only VirusTotal/Safe Browsing endpoints via the existing integration layer reachable; no general internet egress from the parsing process itself).
- Horizontally scalable via a job queue (existing platform infrastructure pattern, if already used for other async modules; otherwise a standard broker such as the one already selected elsewhere in SecuraMail's stack).
- YARA rule corpus and analyzer plugin set deployed as a versioned artifact alongside the worker image, enabling rollback.
- Resource requests/limits (CPU, memory) defined per worker replica, sized against the performance targets in §4.

---

## 35. Required Python Libraries

*(Representative categories — exact package/version pinning is an implementation-phase decision.)*

- Archive handling: standard library `zipfile`/`tarfile`/`gzip`, plus a 7z/RAR-capable library.
- OLE/Office parsing: an OLE Compound File parser and a VBA macro extraction library; an OOXML-aware document parsing library.
- PDF structural parsing: a PDF object-graph parsing library (non-rendering).
- PE parsing: a PE header/section parsing library.
- YARA: official Python YARA bindings.
- Hashing: standard library `hashlib`; a fuzzy-hashing (ssdeep) binding.
- Image metadata: an EXIF/metadata parsing library.
- General: a magic-byte/file-type identification library.

---

## 36. Required External Tools

- A file-type identification utility (`libmagic`-backed) as the underlying engine behind the magic-byte library.
- A YARA rule compiler/runtime (native binary backing the Python bindings).
- Archive extraction utilities for formats not natively supported by pure-Python libraries (e.g., a native 7z/RAR extraction binary invoked in a sandboxed subprocess with strict argument handling to avoid command-injection risk from attacker-controlled filenames).

---

## 37. Required APIs

- **VirusTotal API** — via the platform's existing integration client (no new credential/integration work required; ATAE is a new *consumer* of the existing client).
- **Google Safe Browsing API** — via the existing integration, for extracted URL IOCs.
- No new external APIs are introduced by ATAE.

---

## 38. Implementation Roadmap

1. **Phase 1 — Core Pipeline & Triage:** Ingestion & Triage layer, true-type identification, fake-extension detection, `AnalysisContext`/`Finding` schema, isolated workspace management.
2. **Phase 2 — Cross-Cutting Services:** Hashing Service, Entropy Engine, IOC Extractor, YARA Engine (with an initial curated rule corpus).
3. **Phase 3 — Archive & Generic Analyzer:** recursive safe extraction with bomb detection; Generic Static Analyzer as the fallback path.
4. **Phase 4 — Document Analyzers:** PDF Analyzer, Office Analyzer (OOXML + legacy OLE), macro/DDE/action detection.
5. **Phase 5 — Executable & Script Analyzers:** PE static analysis, packer/signature checks, script static/obfuscation analysis, layered deobfuscation.
6. **Phase 6 — Image Analyzer & Remaining Type Coverage:** stego/EXIF/polyglot checks; HTML/XML/CSV specialized handling.
7. **Phase 7 — Intelligence Correlation & Scoring:** VirusTotal/Safe Browsing correlation wiring, Risk Scoring Engine, False Positive Reduction.
8. **Phase 8 — Forensic Record & Integration:** Forensic Record Assembler, handoff contracts to Email Threat Detection, PDF Report Generator, and Gemini Explainability.
9. **Phase 9 — Hardening & Performance:** process isolation tier, resource-ceiling enforcement, load testing against performance targets (§4), regression testing against a known-clean corpus for false-positive calibration.

---

## 39. Complexity Analysis

| Component | Time Complexity (typical) | Notes |
|---|---|---|
| Archive recursive extraction | O(n·d) where n = total entries, d = nesting depth | Bounded by depth/size ceilings (§14) to prevent worst-case blowup |
| PDF object graph parsing | O(objects + streams) | Linear in declared object count; cross-ref anomalies require a bounded reconciliation pass |
| Office macro extraction | O(stream size) | VBA decompression is linear in compressed p-code size |
| PE static analysis | O(sections + imports) | Bounded by declared section/import table sizes with sanity ceilings against malformed headers |
| Entropy computation | O(file size) | Single linear pass, byte-frequency histogram |
| YARA scanning | O(rules × file size) in the worst case | Mitigated by rule-set optimization and pre-compilation; typically sub-linear in practice due to YARA's internal Aho-Corasick-based string matching |
| IOC extraction (regex-based) | O(content size) | Bounded regex patterns to avoid catastrophic backtracking (a specific implementation-phase requirement) |
| Risk scoring aggregation | O(number of findings) | Findings count is bounded by the above ceilings, so this stage is effectively constant relative to file size |

Overall, the pipeline's dominant cost driver is archive/nesting depth combined with file size, both of which are explicitly bounded by policy (§14, §31), giving the system a predictable worst-case resource envelope rather than an unbounded one.

---

## 40. Risks & Limitations

- **Static analysis cannot catch runtime-only behavior.** Techniques that only manifest during actual execution (e.g., certain environment-aware payloads that decrypt only under specific runtime conditions) are out of scope until a future dynamic-analysis/sandbox phase is designed and approved separately.
- **Encrypted/password-protected content is a fundamental blind spot** for static inspection; ATAE's mitigation is conservative default scoring (§14, §15) rather than false certainty.
- **Novel obfuscation techniques** not covered by current YARA rules or heuristic patterns may evade detection until the rule corpus and heuristics are updated — this is an ongoing content-maintenance responsibility, not a one-time build task.
- **Parser vulnerabilities are a genuine attack surface** given ATAE's job is to parse untrusted, potentially adversarial files; §29's isolation design is a mitigation, not an elimination, of this risk.
- **False positives on legitimate but heavily macro-driven business documents** are possible; §24's suppression framework reduces but cannot fully eliminate this without risking false negatives.
- **Steganography detection is inherently probabilistic** and should be communicated to end users/analysts as an indicator requiring further review, not a confirmed finding.

---

## 41. Future Enhancements

- Dynamic analysis/sandbox detonation tier for files that remain `Unknown` after static analysis, feeding behavioral findings back into the same `Finding`/scoring schema.
- ML-based classification layer built on ATAE's structured feature output (§25).
- LLM-assisted analyst triage summarization for quarantined files (§26).
- Cross-message correlation (e.g., the same malicious attachment hash appearing across multiple recipients/campaigns) to power organization-wide campaign detection, building on the internal reputation cache (§21).
- Expanded fuzzy-matching/similarity clustering against the organization's own historical malicious-sample corpus to catch minor variants of previously seen internal threats faster than external TI alone.

---

*End of Software Design Specification.*
