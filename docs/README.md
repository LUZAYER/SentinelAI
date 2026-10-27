# SentinelAI — System Architecture & Forensic Coverage Specification

**SentinelAI** is an enterprise-grade digital threat detection, forensic inspection, and incident intelligence platform. It combines deterministic multi-modal heuristics, asynchronous task queuing, and local AI reasoning to deliver end-to-end digital authenticity verification.

---

## 1. System Architecture & Stack

```
[ Frontend: Next.js 16 (React 19 / TS) ] 
       │ HTTP / REST
       ▼
[ API Gateway: FastAPI (Python 3.13) ]
  ├── Native bcrypt Authentication & RBAC (Admin / Analyst)
  ├── Immutable Security Audit Logger (audit_logs table)
  ├── Async SQLAlchemy Engine (asyncpg) ──────► [ PostgreSQL 15 ]
  └── Distributed Task Producer ──────────────► [ Redis 7 Broker ]
                                                       │
                                                       ▼
                                            [ Celery Worker Pool ]
                                              ├── 5 Forensic Engines
                                              ├── PDF / JSON ReportLab
                                              └── [ Local Ollama LLM ]
```

| Component | Technology | Role / Execution Profile |
|---|---|---|
| **Frontend** | Next.js 16 (App Router), TypeScript, Vanilla CSS | Light-first cybersecurity UI, real-time telemetry, 18 verified routes. |
| **API Layer** | FastAPI, Python 3.13, Uvicorn | Async REST endpoints, input sanitization, JWT authorization. |
| **Database** | PostgreSQL 15 (Alpine) | Relational persistence with connection pooling (`pool_size=10`). |
| **Broker / Cache** | Redis 7 (Alpine) | Celery task message broker and in-memory indicator cache. |
| **Worker Queue** | Celery (sync psycopg2 driver) | Asynchronous forensic analysis and dynamic ReportLab PDF compilation. |
| **Reasoning Engine** | Local Ollama (`llama3.1`) | Evidence-grounded plain-language intelligence with heuristic fallback. |
| **Orchestration** | Docker Compose | 5 isolated service containers with healthchecks and volume persistence. |

---

## 2. End-to-End Analysis Workflow Pipeline

![SentinelAI Analysis Workflow](./images/analysis_workflow.jpg)

The platform follows a rigorous 7-stage deterministic and AI-assisted pipeline:
```
User Input ──► Preprocessing & Feature Extraction ──► Specialized AI/ML Detection ──► Risk & Evidence Aggregation ──► Ollama LLM ──► Explanation & Recommendations ──► Security Report
```

1. **User Input**: Multi-modal ingest accepting file binaries, media uploads, URLs, and raw text samples.
2. **Preprocessing & Feature Extraction**: Parsing, normalization, byte frequency calculation, OCR text extraction, and metadata indexing.
3. **Specialized AI/ML Detection**: Isolated execution of domain-specific forensic engines (ELA, FFT spectrum, SSRF validation, PE header triage, urgency NLP).
4. **Risk & Evidence Aggregation**: Weighted confidence scoring (0–100 scale) and cross-indicator correlation matrix.
5. **Ollama LLM**: Local neural reasoning engine (`llama3.1`) synthesizing forensic facts without third-party data leakage.
6. **Explanation & Recommendations**: Plain-language threat briefing tailored to analyst, executive, or legal persona with immediate containment playbooks.
7. **Security Report**: Cryptographically signed forensic report artifact, downloadable as formatted PDF or structured JSON.

---

## 3. Threat Modality & Forensic Engine Coverage

| Modality | Dedicated Studio | Forensic Detection Algorithms & Coverage |
|---|---|---|
| **Deepfake Detection** | `/analysis/deepfake` | • **Error Level Analysis (ELA)**: Quantization noise & compression delta.<br>• **Facial Landmark Stability**: 68-point mesh inter-pupillary jitter.<br>• **2D-FFT Spectrum**: High-frequency GAN checkerboard artifact detection.<br>• **EXIF Camera Forensics**: Sensor signature & generative tool metadata. |
| **Document Forensics** | `/analysis/document` | • **OCR Spatial Alignment**: Baseline elevation & character kerning deltas.<br>• **PDF Incremental Revisions**: Spliced objects & hidden layer detection.<br>• **Font Table Consistency**: Glyph rendering & embedded font variances.<br>• **XMP / EXIF Disparity**: Authoring tool and creation timestamp mismatch. |
| **Phishing Analysis** | `/analysis/phishing` | • **SSRF-Safe Headless Query**: Blocks RFC 1918 private IPs & cloud metadata.<br>• **Multi-Hop Redirect Tracer**: Cascading 301/302 and meta-refresh analysis.<br>• **TLS / SSL Age & Issuer**: Short-lived certificate and issuer validation.<br>• **Typo-squatting & Punycode**: Levenshtein distance against top 500 brands. |
| **Scam Detection** | `/analysis/scam` | • **Manufactured Urgency**: Time pressure & artificial deadline detection.<br>• **Financial Coercion**: Wire, cryptocurrency, and unverified gift card demands.<br>• **Executive Impersonation**: CEO fraud, IRS, and IT support spoofing.<br>• **Psychological Loss Aversion**: Threat of penalty & fear elicitation vectors. |
| **Malware Static Triage** | `/analysis/malware` | • **Zero Execution Guarantee**: Isolated static file parsing without detonation.<br>• **Shannon Byte Entropy**: 0–8.00 index for packed / encrypted payload detection.<br>• **PE Header Inspection**: Section flags (`.text`, `.rdata`, `.data`, `.rsrc`).<br>• **Win32 API Scrutiny**: Suspicious imports (`VirtualAlloc`, `CreateRemoteThread`). |
| **AI Explanation Studio** | `/analysis/ai-explanation` | • **Evidence Grounding**: Direct attribution to raw indicators without hallucination.<br>• **Multi-Persona Briefings**: Tailored for **SOC Analyst**, **Executive**, and **Legal / IR**.<br>• **Incident Recommendations**: Concrete containment and mitigation actions. |

---

## 4. Platform Route Coverage (100% HTTP 200 Verified)

- **Authentication & Onboarding**: `/login`, `/register`, `/forgot-password`, `/reset-password`, `/verify-email`
- **Core Operations**: `/` (Landing Hero), `/dashboard` (Analyst Dashboard), `/analysis` (Command Hub), `/analyses` (History Explorer), `/analysis/[id]` (8-Stage Result Pipeline), `/reports` (In-App PDF Viewer & Generator)
- **Specialized Workstations**: `/analysis/deepfake`, `/analysis/document`, `/analysis/phishing`, `/analysis/scam`, `/analysis/malware`, `/analysis/ai-explanation`
- **Security & Administration**: `/threats` (Threat Intel), `/watchlist` (Target Tracker), `/activity` (Audit Log), `/status` (Service Health), `/settings` (Preferences & LLM Config), `/admin` (Live Superuser Portal)

---

## 5. Security & Compliance Controls

- **Authentication**: JWT access tokens (HS256) with native C-extension `bcrypt` password hashing.
- **Role-Based Access (RBAC)**: Enforced `ADMIN` vs `USER` separation with guardrails against self-demotion or self-suspension.
- **Immutable Audit Trail**: Central `audit_logs` table tracking sensitive operations (`LOGIN`, `REGISTER`, `USER_ROLE_UPDATED`, `USER_STATUS_UPDATED`, `SYSTEM_CACHE_FLUSHED`).
- **Network Safety**: Outbound URL requests pass through an isolated DNS resolver blocking private loopback (127.0.0.1), private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and link-local cloud metadata endpoints (169.254.169.254).

---

## 6. Pre-Configured Demo Credentials

| Role | Username | Email | Password | Access Scope |
|---|---|---|---|---|
| **Administrator** | `admin` | `admin@sentinelai.com` | `AdminSecure123!` | Full superuser access, `/admin` portal, role elevation, live telemetry. |
| **Security Analyst** | `analyst_pro` | `analyst_pro@sentinelai.com` | `SecurePassword123!` | Forensic studios, report generation, intelligence watchlist, history. |

*Quick 1-click credential auto-fill buttons are available on the [Login Page](http://localhost:3000/login).*
