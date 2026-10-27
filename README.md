# SentinelAI

AI-Powered Multi-Modal Digital Threat Detection & Authenticity Analysis Platform.

## Overview
SentinelAI is a digital forensics platform designed to detect deepfakes, manipulated documents, phishing URLs, and social engineering scams. It uses a scalable backend architecture powered by FastAPI, Celery, and PostgreSQL, along with a rich Next.js frontend.

## Features
- **Deepfake Detection**: Analyzes media files for manipulation using Error Level Analysis (ELA) and metadata inspection.
- **Document Forgery**: Detects tampered PDFs and documents using OCR and structural analysis.
- **Phishing & Scam Detection**: Analyzes URLs and text for social engineering patterns using NLP and heuristics.
- **AI-Powered Explanations**: Generates human-readable forensic reports using local LLMs (Ollama) or cloud APIs.
- **Comprehensive Reports**: Exports detailed findings in PDF and JSON formats.

## Quick Start (Docker)
Ensure you have Docker and Docker Compose installed.

1. Clone the repository and navigate to the project directory.
2. Run `docker-compose up -d --build`.
3. The platform will be available at `http://localhost:3000`.

## Manual Setup
See the `docs/` folder for detailed deployment instructions, API references, and architecture overview.
