# SentinelAI

## AI-Powered Multi-Modal Digital Threat Detection & Digital Authenticity Analysis Platform

SentinelAI is a unified AI-powered cybersecurity and digital authenticity analysis platform designed to identify, analyze, and explain modern digital threats from a single interface.

The platform combines specialized AI/ML detection systems, digital forensics, cybersecurity analysis, risk assessment, evidence aggregation, and locally hosted Large Language Models (LLMs) through **Ollama**.

SentinelAI is designed to analyze multiple types of digital content including **images, videos, audio, documents, URLs, messages, and potentially malicious files**.

---

## 🚀 Project Overview

The rapid development of Generative AI has made digital manipulation easier and significantly more convincing.

Deepfake videos, AI-generated voices, manipulated images, forged documents, phishing websites, scam messages, impersonation attempts, and malicious files can now appear highly realistic.

Traditional security tools are often specialized. A user may need separate solutions for deepfake detection, document analysis, phishing detection, malware analysis, and scam identification.

**SentinelAI addresses this problem by bringing these capabilities into one unified platform.**

The system analyzes submitted content using specialized detection modules, aggregates the resulting evidence, calculates an overall risk assessment, and uses a local LLM to explain the findings and generate a structured security report.

---

## 🎯 Core Objectives

SentinelAI aims to provide a centralized platform for AI-assisted digital threat detection and authenticity analysis.

The system is designed to answer questions such as:

* Is this image or video potentially AI-generated or manipulated?
* Does this audio contain characteristics of synthetic speech?
* Has this document been digitally altered?
* Is this URL potentially a phishing website?
* Does this message contain scam or social-engineering indicators?
* Does this file contain suspicious or malicious characteristics?
* What evidence supports the detection?
* How serious is the identified risk?
* What actions should the user take?

---

## 🔍 Core Features

### 1. Deepfake Detection

Analyzes potentially manipulated multimedia content.

**Supported targets:**

* Images
* Videos
* Audio / voice recordings

**Potential indicators:**

* Facial inconsistencies
* Visual artifacts
* Temporal inconsistencies
* Frame-level anomalies
* Synthetic texture patterns
* Audio artifacts
* Synthetic speech characteristics
* Metadata anomalies

---

### 2. Document Manipulation Detection

Analyzes digital and scanned documents for potential manipulation.

**Analysis may include:**

* Metadata inconsistencies
* Font inconsistencies
* Layout anomalies
* Image manipulation
* Text/image inconsistencies
* Compression differences
* Structural anomalies

Potential use cases include certificates, forms, scanned documents, official-looking documents, and other digital records.

> SentinelAI provides an analytical assessment and does not provide legal certification of document authenticity.

---

### 3. Phishing Detection

Analyzes URLs and related indicators for potentially malicious or deceptive behavior.

**Analysis may include:**

* Suspicious domains
* Domain impersonation
* URL obfuscation
* Suspicious redirects
* Threat indicators
* Credential-harvesting characteristics
* Reputation-based indicators

---

### 4. Scam & Social Engineering Detection

Analyzes suspicious messages and text for social-engineering patterns.

**Examples include:**

* Impersonation
* Urgency-based manipulation
* Financial requests
* Credential requests
* Suspicious links
* Authority impersonation
* Prize and investment scams
* Account takeover attempts

---

### 5. Malicious File Analysis

Provides static analysis of potentially malicious files.

**Possible analysis includes:**

* File identification
* Cryptographic hashes
* Metadata extraction
* String analysis
* Entropy analysis
* PE/ELF characteristics
* Suspicious imports
* Embedded objects
* Static indicators of compromise

> **Security:** Untrusted files must never be executed directly on the main application server. Dynamic analysis requires a properly isolated sandbox.

---

## 🤖 AI & LLM Integration

SentinelAI uses **Ollama** to run Large Language Models locally.

### Supported Models

* **Llama 3.1**
* **Qwen3**

The LLM layer is responsible for:

* Explaining detection results
* Summarizing evidence
* Correlating findings
* Generating recommendations
* Producing human-readable reports

The LLM is **not the primary detection mechanism**.

Specialized detection modules generate evidence and scores first. The LLM receives those structured findings and converts them into an understandable security assessment.

This follows an **evidence-first architecture** and reduces the risk of unsupported LLM-generated security conclusions.

---

## 🔄 System Methodology

```text
                     USER INPUT
                         |
                         v
             PREPROCESSING & FEATURE
                   EXTRACTION
                         |
                         v
              SPECIALIZED AI DETECTION
                         |
                         v
              RISK & EVIDENCE
                 AGGREGATION
                         |
                         v
                      OLLAMA
                 Llama 3.1 / Qwen3
                         |
                         v
              EXPLANATION &
               RECOMMENDATION
                         |
                         v
               FINAL SECURITY REPORT
```

---

## 🏗️ High-Level Architecture

```text
                    +----------------------+
                    |      WEB FRONTEND    |
                    |   Next.js / React    |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |     API / BACKEND    |
                    |        FastAPI       |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | ANALYSIS ORCHESTRATOR|
                    +----------+-----------+
                               |
        +-----------+----------+----------+-----------+
        |           |          |          |           |
        v           v          v          v           v
   +---------+ +---------+ +---------+ +---------+ +---------+
   |Deepfake | |Document | |Phishing | |  Scam   | | Malware |
   |Detection| |Analysis | |Detection| |Analysis | |Analysis |
   +----+----+ +----+----+ +----+----+ +----+----+ +----+----+
        |           |          |          |           |
        +-----------+----------+----------+-----------+
                               |
                               v
                  +-------------------------+
                  | RISK & EVIDENCE         |
                  | AGGREGATION             |
                  +------------+------------+
                               |
                               v
                  +-------------------------+
                  |        OLLAMA           |
                  | Llama 3.1 / Qwen3       |
                  +------------+------------+
                               |
                               v
                  +-------------------------+
                  |    REPORT GENERATOR     |
                  +-------------------------+
```

---

## 🧰 Technology Stack

| Category      | Technology                               |
| ------------- | ---------------------------------------- |
| Frontend      | Next.js, TypeScript, React, Tailwind CSS |
| Backend       | Python, FastAPI, Pydantic                |
| AI / ML       | PyTorch, OpenCV, Scikit-learn            |
| LLM           | Ollama, Llama 3.1, Qwen3                 |
| Database      | PostgreSQL                               |
| Cache / Queue | Redis                                    |
| Deployment    | Docker, Docker Compose                   |

---

## 📁 Project Structure

```text
SentinelAI/
│
├── frontend/          # Frontend web application
│
├── backend/           # FastAPI backend and APIs
│
├── ml/                # AI/ML detection modules
│
├── docs/              # Technical documentation
│
├── infra/             # Infrastructure and deployment
│
├── uploads/           # File storage
│
├── docker-compose.yml
│
└── README.md
```

---

## ⚙️ Installation

### Requirements

* Python 3.11+
* Node.js 20+
* PostgreSQL
* Redis
* Docker
* Docker Compose
* Ollama

### Clone the Repository

```bash
git clone https://github.com/LUZAYER/SentinelAI.git
cd SentinelAI
```

### Backend

```bash
cd backend

python -m venv venv
```

Linux/macOS:

```bash
source venv/bin/activate
```

Windows:

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Frontend

```bash
cd ../frontend
npm install
```

### Ollama

Install Ollama and pull the required models:

```bash
ollama pull llama3.1
ollama pull qwen3
```

Configure the required environment variables and start the required services using Docker Compose or the project's development commands.

> Never commit passwords, API keys, tokens, or other secrets to GitHub.

---

## 🔐 Security Design

SentinelAI follows a security-first architecture because it processes potentially malicious content.

Important security controls include:

* Authentication and authorization
* Input validation
* Secure file handling
* File type and size restrictions
* Path traversal protection
* SSRF protection
* Rate limiting
* Audit logging
* Secure database access
* Isolated analysis services
* Temporary file cleanup

All uploaded content must be treated as **untrusted input**.

Malware samples should be analyzed statically unless a dedicated and properly isolated sandbox is available.

---

## 📊 Risk & Evidence Aggregation

SentinelAI does not rely on a single detector to determine the final result.

Individual modules produce structured findings containing information such as:

```text
Detection Type
Score
Confidence
Indicators
Evidence
Metadata
Detector Information
```

These findings are passed to the **Risk & Evidence Aggregation Engine**, which produces a unified assessment.

The aggregated findings are then provided to the local LLM for explanation and report generation.

### Conceptual Risk Levels

|  Score | Classification |
| -----: | -------------- |
|   0–19 | Low            |
|  20–39 | Guarded        |
|  40–59 | Medium         |
|  60–79 | High           |
| 80–100 | Critical       |

The scoring system can be further calibrated as the underlying detection models and validation datasets evolve.

---

## 📄 Security Reports

The final analysis report can contain:

* Analysis information
* Input details
* Hash information
* Detector results
* Evidence
* Confidence scores
* Overall risk score
* Risk classification
* LLM-generated explanation
* Recommended actions
* Analysis limitations

Possible output formats:

* Web report
* JSON
* PDF

---

## 🧠 Design Principles

### Evidence First

Security conclusions should be supported by observable evidence.

### Modular Architecture

Each detection capability should remain independently maintainable.

### Explainability

Users should understand why an artifact was classified as suspicious.

### Local AI

LLM processing can be performed locally through Ollama.

### Security by Design

The platform assumes that user-provided content may be malicious.

### Extensibility

New detection models and security-analysis modules can be added without redesigning the entire system.

---

## 🚧 Project Status

SentinelAI is an actively developed **AI and cybersecurity research project**.

The platform is being developed with a focus on:

* Deepfake detection
* Digital forensics
* Document authenticity analysis
* Phishing detection
* Scam detection
* Malware analysis
* Explainable AI
* Local LLM inference
* Multi-modal security analysis

---

## 🛣️ Roadmap

* [ ] Advanced image deepfake detection
* [ ] Advanced video deepfake detection
* [ ] AI-generated voice detection
* [ ] Improved document forensics
* [ ] OCR-assisted document analysis
* [ ] Advanced phishing analysis
* [ ] Expanded scam detection
* [ ] Threat-intelligence integration
* [ ] Improved risk calibration
* [ ] Model benchmarking
* [ ] Advanced security dashboard
* [ ] Production-grade malware sandbox
* [ ] GPU-accelerated inference
* [ ] Additional local LLM support

---

## ⚠️ Limitations

SentinelAI is an analytical decision-support system and does not guarantee absolute authenticity or maliciousness.

AI/ML-based detection may produce:

* False positives
* False negatives
* Model uncertainty
* Dataset bias
* Generalization errors
* Adversarial evasion

High-impact decisions should therefore include appropriate human review and established forensic or cybersecurity procedures.

---

## 🛡️ Responsible Use

SentinelAI is intended for:

* Defensive cybersecurity
* Security research
* Digital forensics
* Academic research
* Authorized security testing
* Fraud and threat awareness

Users are responsible for ensuring that their use of SentinelAI complies with applicable laws, regulations, organizational policies, and authorization requirements.

---

## 👨‍💻 Author

**Reyazul Islam**

GitHub:
https://github.com/LUZAYER

Repository:
https://github.com/LUZAYER/SentinelAI

---

## ⭐ Project

**SentinelAI — AI-Powered Multi-Modal Digital Threat Detection & Digital Authenticity Analysis Platform**

> Detect. Analyze. Explain. Protect.
