# SentinelAI — Implementation Plan

**AI-Powered Multi-Modal Digital Threat Detection & Digital Authenticity Analysis Platform**

## Environment Summary

| Resource | Status |
|---|---|
| Python 3.13.15 | ✅ Available |
| Node v24.20.0 / NPM 11.19.0 | ✅ Available |
| PostgreSQL 18.6 | ✅ Running on :5432, database `sentinelai` created |
| Redis 8.0.6 | ✅ Running on :6379 |
| Ollama 0.21.0 | ✅ Running on :11434 |
| llama3.1:8b | ✅ Installed (4.9GB, Q4_K_M) |
| qwen3:8b | ✅ Installed (5.2GB, Q4_K_M) |
| Docker / Compose | ✅ Available |
| GPU | ❌ CPU-only (12 cores, 14GB RAM) |

---

## Proposed Changes

This follows the 6-phase priority order from the task specification. Each phase builds on the previous one.

---

### PHASE 1 — Project Architecture, Database, Auth, Frontend Shell, Backend API

This is the foundation. Everything else depends on it.

---

#### Backend (`backend/`)

##### [NEW] `backend/requirements.txt`
Core Python dependencies: FastAPI, uvicorn, SQLAlchemy, asyncpg, alembic, pydantic, python-jose (JWT), passlib, bcrypt, python-multipart, redis, celery, httpx, python-magic, Pillow, opencv-python-headless, scikit-learn, pefile, reportlab, aiofiles.

##### [NEW] `backend/app/__init__.py`
Package init.

##### [NEW] `backend/app/main.py`
FastAPI application entry point with:
- CORS middleware (configurable origins)
- Security headers middleware
- Rate limiting middleware
- Request size limiting
- Router inclusion for all API modules
- Startup/shutdown events for DB connection pool
- Health check endpoint

##### [NEW] `backend/app/core/config.py`
Pydantic Settings class loading from `.env`:
- `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_EXPIRATION`
- `OLLAMA_BASE_URL`, `OLLAMA_MODEL`
- `MAX_UPLOAD_SIZE`, `UPLOAD_DIR`, `ALLOWED_EXTENSIONS`
- `CORS_ORIGINS`
- Optional: `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`

##### [NEW] `backend/app/core/security.py`
- Password hashing (bcrypt via passlib)
- JWT token creation/verification
- Token dependency for FastAPI route protection
- Role-based authorization decorator

##### [NEW] `backend/app/core/database.py`
- Async SQLAlchemy engine + session factory
- `get_db` dependency
- Base declarative model

##### [NEW] `backend/app/models/` (SQLAlchemy ORM models)
- `user.py` — User, Role (USER/ADMIN), password hash, timestamps
- `analysis.py` — Analysis (id, user_id, analysis_type, status, input_type, created_at, updated_at)
- `analysis_input.py` — AnalysisInput (file ref, URL, text content)
- `detection_result.py` — DetectionResult (analysis_id, detector_type, risk_score, confidence, status, indicators JSON, evidence JSON, limitations JSON)
- `risk_assessment.py` — RiskAssessment (overall_score, severity, combined_evidence)
- `llm_explanation.py` — LLMExplanation (model_used, explanation text, recommendations, raw_response)
- `report.py` — Report (analysis_id, content JSON, pdf_path, generated_at)
- `uploaded_file.py` — UploadedFile (original_name, stored_name UUID, mime_type, sha256, size, storage_path)
- `audit_log.py` — AuditLog (user_id, action, resource, details, ip, timestamp)

##### [NEW] `backend/alembic/` + `alembic.ini`
Database migration configuration. Initial migration creates all tables.

##### [NEW] `backend/app/schemas/` (Pydantic request/response schemas)
- `auth.py` — UserCreate, UserLogin, UserResponse, TokenResponse
- `analysis.py` — AnalysisCreate, AnalysisResponse, AnalysisListResponse
- `detection.py` — DetectionResultSchema (common schema across all detectors)
- `report.py` — ReportResponse

##### [NEW] `backend/app/api/` (FastAPI routers)
- `auth.py` — POST `/register`, POST `/login`, GET `/me`, POST `/logout`
- `analysis.py` — POST `/analysis`, GET `/analysis/{id}`, GET `/analysis` (list with pagination/filter)
- `reports.py` — GET `/reports/{id}`, GET `/reports/{id}/pdf`, GET `/reports/{id}/json`
- `health.py` — GET `/health` (DB, Redis, Ollama connectivity checks)
- `llm.py` — GET `/llm/models`, POST `/llm/config`
- `admin.py` — GET `/admin/users`, GET `/admin/stats`, GET `/admin/audit-logs`, GET `/admin/system-health`

---

#### Frontend (`frontend/`)

##### [NEW] Next.js project via `npx create-next-app`
TypeScript, Tailwind CSS (as specified in the task), App Router.

##### [NEW] `frontend/src/lib/api.ts`
Typed API client wrapping fetch with auth token injection, error handling, base URL config.

##### [NEW] `frontend/src/lib/auth.ts`
Auth context provider — login, logout, register, token storage, protected route wrapper.

##### [NEW] `frontend/src/app/` pages
- `page.tsx` — Landing page (what SentinelAI is, features, how it works)
- `login/page.tsx` — Login form
- `register/page.tsx` — Registration form
- `dashboard/page.tsx` — Dashboard (stats, recent analyses, risk distribution)
- `analysis/new/page.tsx` — New analysis (type selector + dynamic input)
- `analysis/[id]/page.tsx` — Analysis details (status, results, evidence, explanation)
- `reports/page.tsx` — Report listing (search, filter, sort)
- `settings/page.tsx` — Settings (profile, Ollama config, model selection)
- `admin/page.tsx` — Admin panel

##### [NEW] `frontend/src/components/`
- `Navbar.tsx`, `Sidebar.tsx`, `Footer.tsx`
- `RiskScore.tsx` — visual risk score gauge
- `StatusBadge.tsx` — analysis status indicator
- `FileUpload.tsx` — drag-and-drop file upload
- `AnalysisCard.tsx` — analysis summary card
- `EvidenceList.tsx` — structured evidence display

---

#### Infrastructure

##### [NEW] `.env.example`
All environment variables with safe defaults.

##### [NEW] `docker-compose.yml`
Services: frontend, backend, postgres, redis, worker, ollama. Health checks, environment variable pass-through.

---

### PHASE 2 — File Upload, Analysis Orchestration, Risk Engine

---

#### [NEW] `backend/app/services/file_service.py`
- File validation: size limits, MIME detection (python-magic), extension whitelist, filename sanitization
- UUID-based storage naming
- SHA-256 hashing
- Secure storage path management
- Cleanup policies

#### [NEW] `backend/app/services/orchestrator.py`
The central analysis orchestration service:
1. Receives analysis request
2. Validates input
3. Determines appropriate detector(s) based on input type
4. Creates Analysis + AnalysisInput DB records (status: QUEUED)
5. Dispatches to Celery worker
6. Returns analysis ID for polling

#### [NEW] `backend/app/workers/celery_app.py`
Celery application config with Redis broker.

#### [NEW] `backend/app/workers/analysis_worker.py`
Celery task that:
1. Updates status → PROCESSING
2. Runs preprocessing
3. Runs detector → status ANALYZING
4. Runs risk aggregation
5. Sends to LLM → status GENERATING_REPORT
6. Generates report
7. Updates status → COMPLETED (or FAILED on error)

#### [NEW] `backend/app/services/risk_engine.py`
- Normalizes all detector outputs to common schema
- Weighted risk score aggregation (documented methodology)
- Severity classification: LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100)
- Evidence combination
- High-risk indicator identification

#### [NEW] `backend/app/detectors/base.py`
Abstract `BaseDetector` class:
```python
class BaseDetector(ABC):
    @abstractmethod
    async def analyze(self, input_data) -> DetectionResult
    
    @abstractmethod
    def supported_input_types(self) -> list[str]
```

---

### PHASE 3 — Detection Modules

Each detector implements `BaseDetector` and returns a standardized `DetectionResult`.

---

#### [NEW] `backend/app/detectors/deepfake/detector.py`
- **Image**: EXIF metadata extraction, ELA (Error Level Analysis) via Pillow, face detection (OpenCV Haar/DNN), compression artifact analysis, AI-generation indicators (frequency domain analysis)
- **Video**: Frame extraction (OpenCV), face detection per frame, temporal consistency check, frame-level confidence aggregation
- **Audio**: Audio extraction (ffmpeg/pydub), spectral analysis (librosa), basic synthetic voice indicators
- Returns: authenticity_score, manipulation_probability, confidence, detected_faces, suspicious_regions, technical_indicators

#### [NEW] `backend/app/detectors/deepfake/preprocessing.py`
Image/video/audio preprocessing utilities.

#### [NEW] `backend/app/detectors/document/detector.py`
- OCR (pytesseract/easyocr)
- Metadata extraction
- Font consistency analysis
- Layout analysis
- Copy-paste artifact detection (ELA)
- Compression inconsistency detection
- Text pattern analysis
- Returns: manipulation indicators, suspicious regions, OCR text, formatting anomalies

#### [NEW] `backend/app/detectors/phishing/detector.py`
- URL parsing and structural analysis
- Domain analysis (length, suspicious keywords, brand impersonation, homoglyph detection)
- TLS/SSL certificate check (httpx)
- Redirect chain analysis (with SSRF protection — allowlist, no internal IPs)
- Content analysis if safely fetchable
- Returns: classification (Safe/Suspicious/Malicious/Unknown), risk_score, evidence

#### [NEW] `backend/app/detectors/scam/detector.py`
- NLP-based text analysis: urgency detection, threat patterns, financial request patterns
- Keyword/pattern matching for common scam categories
- Suspicious link extraction
- Emotional manipulation indicators
- Delegates to LLM for deeper analysis
- Returns: scam_probability, scam_category, evidence, indicators

#### [NEW] `backend/app/detectors/malware/detector.py`
- File type identification (magic bytes)
- SHA-256/MD5 hash calculation
- Strings extraction (printable strings analysis)
- PE analysis (pefile library for Windows executables)
- ELF analysis (for Linux binaries)
- Entropy analysis (detect packed/encrypted content)
- Archive inspection (safe listing of zip/tar contents)
- Embedded object detection
- Suspicious extension detection (double extensions, etc.)
- Returns: file_classification, risk_level, hash, indicators, suspicious_characteristics

> [!IMPORTANT]
> No uploaded file is ever executed. All analysis is static. The malware detector runs in the worker process which has no special privileges.

---

### PHASE 4 — Ollama LLM Integration

---

#### [NEW] `backend/app/services/llm/provider.py`
Abstract LLM provider interface.

#### [NEW] `backend/app/services/llm/ollama.py`
- Connection management to Ollama API
- Model listing (`/api/tags`)
- Model availability check
- Health check
- Chat completion with structured prompts
- Streaming support for long explanations
- Timeout and error handling (Ollama down, model not loaded)
- Configurable model selection (llama3.1 / qwen3)

#### [NEW] `backend/app/services/llm/prompts.py`
Structured prompt templates per analysis type:
- System prompt: "You are a cybersecurity analyst. Never invent evidence. Only explain evidence supplied by the detection pipeline."
- Per-detector prompt templates that format evidence into structured context
- Output format instructions (explanation, risk summary, recommendations)

#### [NEW] `backend/app/services/explanation_service.py`
- Takes aggregated `DetectionResult` + `RiskAssessment`
- Formats evidence into LLM prompt
- Calls Ollama
- Parses response into structured explanation + recommendations
- Stores `LLMExplanation` in DB

---

### PHASE 5 — Reports, Dashboard, Admin

---

#### [NEW] `backend/app/services/report_service.py`
- Generate structured report from analysis data
- PDF generation (ReportLab): Executive Summary → Risk Assessment → Detection Findings → Evidence → AI Explanation → Recommendations → Technical Details → Limitations
- JSON export
- Report persistence

#### Frontend Dashboard enhancements
- Real-time stats from API (total analyses, high-risk count, recent analyses)
- Risk distribution chart (Recharts or Chart.js)
- Detection category breakdown
- Recent threats list

#### Frontend Admin panel
- User management table
- System health indicators (DB, Redis, Ollama status)
- Analysis statistics
- Failed job listing
- Audit log viewer

---

### PHASE 6 — Security Hardening, Testing, Docker, Documentation

---

#### Security
- CORS strict configuration
- Rate limiting (slowapi)
- Input validation on all endpoints
- SQL injection prevention (SQLAlchemy parameterized queries)
- XSS protection headers
- SSRF protection in phishing detector (IP allowlist, no internal ranges)
- Path traversal prevention in file storage
- Audit logging on sensitive actions

#### Testing (`backend/tests/`)
- `test_auth.py` — Registration, login, JWT validation, role-based access
- `test_analysis_api.py` — CRUD operations, file upload
- `test_detectors.py` — Each detector with sample inputs
- `test_file_validation.py` — Size limits, MIME checks, extension validation
- `test_risk_engine.py` — Score aggregation, severity classification
- `test_security.py` — Path traversal, SSRF, file upload security

#### Docker
- `infra/docker/Dockerfile.backend`
- `infra/docker/Dockerfile.frontend`
- `docker-compose.yml` with all 6 services + health checks

#### Documentation
- `README.md` — Full project documentation
- `docs/architecture.md` — System architecture with diagrams
- `docs/api.md` — API reference
- `docs/security.md` — Security design decisions
- `docs/deployment.md` — Deployment guide

---

## Project Structure

```
sentinelai/
├── frontend/
│   ├── src/
│   │   ├── app/              # Next.js App Router pages
│   │   ├── components/       # Reusable UI components
│   │   ├── lib/              # API client, auth, utilities
│   │   ├── hooks/            # Custom React hooks
│   │   └── types/            # TypeScript type definitions
│   ├── public/
│   ├── package.json
│   ├── tailwind.config.ts
│   └── tsconfig.json
├── backend/
│   ├── app/
│   │   ├── api/              # FastAPI route handlers
│   │   ├── core/             # Config, security, database
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── services/         # Business logic services
│   │   │   ├── llm/          # Ollama integration
│   │   │   └── ...
│   │   ├── detectors/        # Detection modules
│   │   │   ├── base.py
│   │   │   ├── deepfake/
│   │   │   ├── document/
│   │   │   ├── phishing/
│   │   │   ├── scam/
│   │   │   └── malware/
│   │   ├── workers/          # Celery background tasks
│   │   └── storage/          # File storage abstraction
│   ├── alembic/              # Database migrations
│   ├── tests/
│   ├── requirements.txt
│   └── alembic.ini
├── infra/
│   ├── docker/
│   └── nginx/
├── docs/
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Verification Plan

### Automated Tests
```bash
# Backend tests
cd backend && pytest tests/ -v

# Frontend build check
cd frontend && npm run build
```

### Manual Verification
1. Start all services (`docker compose up` or direct)
2. Register a new user → verify DB entry
3. Login → verify JWT token returned
4. Upload an image → verify deepfake analysis runs end-to-end
5. Submit a URL → verify phishing analysis
6. Submit text → verify scam detection
7. Upload a document → verify document forgery analysis
8. Upload a binary → verify malware static analysis
9. Verify Ollama generates explanation for each
10. Verify report generation and PDF download
11. Verify dashboard shows real statistics
12. Verify admin panel shows system health

---

## Open Questions

> [!IMPORTANT]
> **Tailwind CSS version**: The task specifies Tailwind CSS. Next.js with `create-next-app` will default to Tailwind v4. Is that acceptable, or do you prefer v3?

> [!IMPORTANT]
> **Local development approach**: Should I build everything to run directly on your machine (PostgreSQL + Redis + Ollama already running, just `npm run dev` + `uvicorn` + `celery worker`)? Or do you prefer the Docker Compose approach from the start? Running locally is faster for development iteration.

> [!NOTE]
> **CPU-only ML**: Since there's no GPU, all ML inference will run on CPU. Models like ELA, face detection (OpenCV), and frequency analysis work fine on CPU. Deep learning models (if added later) will be slower but functional. Ollama's LLM models are already optimized for CPU with Q4_K_M quantization.
