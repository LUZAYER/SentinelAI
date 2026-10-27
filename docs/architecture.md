# Architecture Overview

SentinelAI uses a modern, decoupled microservices architecture designed for scalability and robust digital forensics.

## Frontend (Next.js)
The presentation layer is built with Next.js 15 (App Router). It features a sleek, dark-themed UI with robust authentication state management using React Context. It communicates with the backend via a customized Axios client with JWT interceptors.

## Backend (FastAPI)
The core API is built on FastAPI, leveraging async programming for high concurrency.
- **Database**: PostgreSQL (via asyncpg) for persistent storage of users, analyses, and logs.
- **ORM**: SQLAlchemy 2.0 with Alembic for migrations.
- **Workers**: Celery workers handle heavy lifting (running ML models, CV heuristics) using a Redis message broker.

## Detection Modules
Located in `backend/app/detectors/`, the platform provides a unified `BaseDetector` interface. Each module (Deepfake, Malware, Phishing, Scam, Document) returns standardized results (risk score, confidence, indicators) that are aggregated by the orchestration engine.

## LLM Integration
The platform integrates with local LLMs (like Llama 3.1 via Ollama) to parse raw forensic heuristics and generate readable executive summaries and detailed explanations.
