# 🔐 Intelligent API Security Platform

> A unified API security platform combining **ML-based passive monitoring** (Phase 1) and **active vulnerability testing** (Phase 2). Built with FastAPI, Isolation Forest, Ollama local LLMs, and PostgreSQL.

---

## 📋 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Tech Stack](#3-tech-stack)
4. [Prerequisites](#4-prerequisites)
5. [Project Structure](#5-project-structure)
6. [Setup Guide](#6-setup-guide)
7. [Database Setup](#7-database-setup)
8. [Ollama Local Models Setup](#8-ollama-local-models-setup)
9. [Configuration (.env)](#9-configuration-env)
10. [Running the Application](#10-running-the-application)
11. [Training the ML Model](#11-training-the-ml-model)
12. [API Rules System (api_rules.yaml)](#12-api-rules-system-api_rulesyaml)
13. [Testing API Endpoints in Postman](#13-testing-api-endpoints-in-postman)
14. [Explanation Engine](#14-explanation-engine)
15. [Alerting System](#15-alerting-system)
16. [Current Status & Roadmap](#16-current-status--roadmap)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Project Overview

This platform solves a critical gap in API security tooling — most organizations use **separate, disconnected tools** for monitoring and testing with no feedback loop between them.

### Phase 1 — ML Monitoring (Built)
- Captures all API traffic via an ingestion endpoint
- Learns normal behavior automatically per endpoint (schema learning)
- Detects anomalies using **Isolation Forest** ML model
- Explains suspicious requests via **local LLM** (Ollama) or **rules engine** fallback
- Fires real-time alerts to console and Slack

### Phase 2 — Active Testing (Planned)
- Replays captured requests with modifications
- Automated fuzzing (SQLi, XSS, IDOR, JWT manipulation)
- Vulnerability detection and PDF report generation

### Key Differentiator
When Phase 1 detects a threat → automatically triggers Phase 2 scan → findings improve Phase 1 detection rules. A continuous adaptive security loop.

---

## 2. Architecture

```
API Traffic (Postman / mitmproxy / SDK)
            ↓
POST /api/traffic/ingest
            ↓
    ┌───────────────────┐
    │  Traffic Service  │
    │  - Embed via      │
    │    Ollama         │
    │  - Store in DB    │
    └────────┬──────────┘
             ↓
    ┌───────────────────┐
    │  Schema Learner   │
    │  - Learns fields  │
    │  - Tracks status  │
    │  - Flags drift    │
    └────────┬──────────┘
             ↓
    ┌───────────────────┐
    │  Anomaly Service  │
    │  - Isolation      │
    │    Forest score   │
    │  - Rule checks    │
    │  - Doc rules      │
    └────────┬──────────┘
             ↓
    ┌───────────────────┐
    │  Explanation      │
    │  LLM (primary)    │
    │  Rules (fallback) │
    └────────┬──────────┘
             ↓
    ┌───────────────────┐
    │  Alert Service    │
    │  Console + Slack  │
    └───────────────────┘
```

---

## 3. Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend API | FastAPI (Python 3.11+) | Async REST API |
| Database | PostgreSQL 16 | Structured storage |
| Time-series | TimescaleDB (planned) | High-volume logs |
| Search | Elasticsearch 8.x | Log search |
| Cache / Queue | Redis 7 | Task queue |
| ML — Anomaly | scikit-learn (Isolation Forest) | Anomaly scoring |
| ML — Embeddings | nomic-embed-text via Ollama | Traffic vectorization |
| ML — LLM | llama3.2:1b via Ollama | Natural language explanation |
| Migrations | Alembic | Database schema versioning |
| ORM | SQLAlchemy (async) | Database access |
| Container | Docker + Docker Compose | Infrastructure |
| Frontend | React + TypeScript (planned) | Dashboard |

---

## 4. Prerequisites

Install these before starting:

| Tool | Download | Version |
|---|---|---|
| Python | python.org | 3.11 or higher |
| Node.js | nodejs.org | 18 or higher |
| Git | git-scm.com | Any recent |
| Docker Desktop | docker.com/products/docker-desktop | Latest |
| Ollama | ollama.com/download | Latest |
| Postman | postman.com | Latest |

> **Windows users:** All commands in this guide use Windows Command Prompt syntax (`^` for line continuation). If you use PowerShell, replace `^` with a backtick `` ` ``.

---

## 5. Project Structure

```
api-security/
├── backend/
│   ├── app/
│   │   ├── api/                  ← Route handlers
│   │   │   ├── __init__.py
│   │   │   ├── traffic.py        ← Traffic ingestion & retrieval
│   │   │   ├── schema.py         ← Learned schema browser
│   │   │   ├── anomaly.py        ← ML training & scoring
│   │   │   └── rules.py          ← Rules doc management
│   │   ├── core/                 ← App configuration
│   │   │   ├── config.py         ← Settings (reads .env)
│   │   │   └── database.py       ← Async DB connection
│   │   ├── ml/                   ← ML layer
│   │   │   ├── base.py           ← Abstract model provider
│   │   │   ├── factory.py        ← Provider selector
│   │   │   ├── features.py       ← Feature extraction
│   │   │   ├── anomaly_detector.py ← Isolation Forest
│   │   │   └── providers/
│   │   │       ├── ollama_provider.py  ← Local LLM (active)
│   │   │       └── openai_provider.py  ← Cloud LLM (stub)
│   │   ├── models/               ← Database models
│   │   │   ├── traffic.py        ← TrafficLog table
│   │   │   ├── schema_model.py   ← LearnedSchema table
│   │   │   ├── finding.py        ← Finding table
│   │   │   └── scan.py           ← ScanJob table
│   │   └── services/             ← Business logic
│   │       ├── traffic_service.py
│   │       ├── schema_service.py
│   │       ├── anomaly_service.py
│   │       ├── rules_service.py
│   │       └── alert_service.py
│   ├── migrations/               ← Alembic migration files
│   ├── main.py                   ← FastAPI app entry point
│   ├── seed.py                   ← Test data seeder
│   ├── requirements.txt
│   └── alembic.ini
├── docs/
│   └── api_rules.yaml            ← Security rules definition
├── frontend/                     ← React dashboard (coming soon)
├── proxy/                        ← mitmproxy scripts (coming soon)
├── docker-compose.yml            ← Infrastructure services
├── .env                          ← Environment config (never commit)
├── .gitignore
└── README.md
```

---

## 6. Setup Guide

### Step 1 — Clone and enter the project

```bash
git clone <your-repo-url>
cd api-security
```

### Step 2 — Start infrastructure services

```bash
docker compose up -d
```

This starts PostgreSQL (port 5433), Redis (port 6379), and Elasticsearch (port 9200).

Verify all three are running:

```bash
docker ps
```

You should see `apisec_postgres`, `apisec_redis`, and `apisec_elastic` with status `Up`.

### Step 3 — Create Python virtual environment

```bash
cd backend
python -m venv .venv
```

**Activate it:**

- Windows Command Prompt: `.venv\Scripts\activate`
- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- macOS / Linux: `source .venv/bin/activate`

Your terminal prompt should now show `(.venv)`.

### Step 4 — Install Python dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, install manually:

```bash
pip install fastapi uvicorn sqlalchemy asyncpg alembic pydantic-settings python-dotenv httpx celery redis elasticsearch ollama scikit-learn numpy pandas pyyaml
```

---

## 7. Database Setup

> **Important for Windows users with a local PostgreSQL installation:** If you already have PostgreSQL installed on your machine, it occupies port 5432. Our Docker container is configured to use port **5433** to avoid conflicts.

### Step 1 — Verify PostgreSQL container is running

```bash
docker exec -it apisec_postgres psql -U apisec -d apisecdb -c "SELECT current_user;"
```

Expected output:
```
 current_user
--------------
 apisec
```

If this fails, run `docker compose down -v && docker compose up -d` and try again.

### Step 2 — Check your .env has the correct database URL

Open `.env` and confirm:

```env
DATABASE_URL=postgresql://apisec:apisec123@127.0.0.1:5433/apisecdb
```

> **Note:** Use `127.0.0.1` not `localhost`. On Windows, `localhost` sometimes resolves to IPv6 (`::1`) which can cause authentication failures.

### Step 3 — Run database migrations

```bash
cd backend
alembic upgrade head
```

Expected output:
```
INFO  [alembic.runtime.migration] Running upgrade -> abc123, initial tables
```

### Step 4 — Verify tables were created

```bash
docker exec -it apisec_postgres psql -U apisec -d apisecdb -c "\dt"
```

Expected output:
```
          List of relations
 Schema |      Name       | Type  | Owner
--------+-----------------+-------+--------
 public | alembic_version | table | apisec
 public | findings        | table | apisec
 public | learned_schemas | table | apisec
 public | scan_jobs       | table | apisec
 public | traffic_logs    | table | apisec
```

### Re-running migrations after model changes

If you add new database columns or tables:

```bash
alembic revision --autogenerate -m "describe your change"
alembic upgrade head
```

### Resetting the database completely

```bash
docker compose down -v
docker compose up -d
alembic upgrade head
```

> ⚠️ This deletes ALL data. Use only in development.

---

## 8. Ollama Local Models Setup

Ollama runs AI models locally — no data leaves your machine.

### Step 1 — Install Ollama

Download from **https://ollama.com/download** and run the installer.

### Step 2 — Pull the required models

Open a terminal and run:

```bash
ollama pull nomic-embed-text
ollama pull llama3.2:1b
```

- `nomic-embed-text` — converts API traffic into vectors for ML (274 MB)
- `llama3.2:1b` — generates natural language security explanations (1.3 GB)

### Step 3 — Verify models are available

```bash
ollama list
```

Expected output:
```
NAME                       SIZE
llama3.2:1b                1.3 GB
nomic-embed-text:latest    274 MB
```

### Step 4 — Test the models work

```bash
ollama run llama3.2:1b "Say hello in one sentence"
```

If you see a response, the LLM is working.

### GPU Memory Issues

If Ollama fails with `out of memory`, your GPU doesn't have enough free VRAM. Fix:

**Option A — Force CPU mode (Windows):**
```bash
set CUDA_VISIBLE_DEVICES=
ollama serve
```

**Option B — Use rules engine fallback:**

The platform automatically falls back to the rules engine if the LLM is unavailable. No action needed — it just works.

**Option C — Switch to cloud LLM:**

Change `MODEL_PROVIDER=openai` in `.env` and add `OPENAI_API_KEY`. No code changes required.

---

## 9. Configuration (.env)

The `.env` file lives at `D:\api-security\.env`. It controls all platform settings.

```env
# ── Database ──────────────────────────────────────────────
# Use 127.0.0.1 not localhost (avoids IPv6 issues on Windows)
# Use port 5433 if you have a local PostgreSQL on 5432
DATABASE_URL=postgresql://apisec:apisec123@127.0.0.1:5433/apisecdb

# ── Infrastructure ────────────────────────────────────────
REDIS_URL=redis://localhost:6379
ELASTIC_URL=http://localhost:9200

# ── Ollama Local Models ───────────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_EMBED_MODEL=nomic-embed-text
OLLAMA_LLM_MODEL=llama3.2:1b     # Change to llama3.2 for larger model

# ── Model Provider ────────────────────────────────────────
# Options: ollama | openai
# To switch providers: change this value + add required keys below
MODEL_PROVIDER=ollama

# ── Alerting (optional) ───────────────────────────────────
# Leave blank to disable Slack alerts (console alerts always active)
SLACK_WEBHOOK_URL=

# ── App ───────────────────────────────────────────────────
APP_ENV=development
SECRET_KEY=changethislater_use_openssl_rand
```

### Switching from Ollama to OpenAI

1. Change `MODEL_PROVIDER=openai`
2. Add `OPENAI_API_KEY=sk-...`
3. Restart the server

No code changes needed anywhere.

### Enabling Slack Alerts

1. Go to your Slack workspace → Apps → Incoming Webhooks → Create
2. Copy the webhook URL
3. Set `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`
4. Restart the server

---

## 10. Running the Application

### Start infrastructure (if not already running)

```bash
cd api-security
docker compose up -d
```

### Start the backend server

```bash
cd api-security\backend
.venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

### Verify everything is running

Open your browser:

| URL | Expected |
|---|---|
| http://localhost:8000/health | `{"status":"ok","ml_available":true}` |
| http://localhost:8000/docs | Swagger UI with all endpoints |

### Seed test data (first time only)

```bash
cd backend
python seed.py
```

This sends 50 realistic traffic records to populate the database and train the schema learner.

---

## 11. Training the ML Model

The ML model (Isolation Forest) must be trained before it can score traffic. Training uses stored traffic logs to learn what normal behavior looks like.

### When to train

- After first setup (seed data first)
- After loading rules from `api_rules.yaml`
- After significant new traffic accumulates (weekly recommended)
- After adding new endpoints to the rules doc

### Method 1 — Train on real traffic only

Requires 20+ traffic logs in the database.

**In Postman:** `POST http://localhost:8000/api/anomaly/train`

Expected response:
```json
{
  "success": true,
  "samples_used": 82,
  "model_trained": true
}
```

### Method 2 — Train using rules doc (recommended)

This combines synthetic baseline data from `api_rules.yaml` with real traffic. Solves the cold-start problem — new endpoints are known before any traffic arrives.

**In Postman:** `POST http://localhost:8000/api/rules/reload`

Expected response:
```json
{
  "schemas_seeded": 8,
  "synthetic_vectors": 160,
  "real_vectors": 82,
  "total_training_vectors": 242,
  "model_retrained": true
}
```

> **Always use Method 2** after editing `api_rules.yaml`. It combines doc knowledge with real traffic for the best model accuracy.

### Score all existing unscored logs

After training, run this to retroactively score logs that arrived before the model was trained:

**In Postman:** `POST http://localhost:8000/api/anomaly/analyze-all`

Expected response:
```json
{
  "high": 8,
  "medium": 24,
  "low": 50,
  "total": 82
}
```

### Model persistence

The trained model is saved to disk at:
```
backend/app/ml/isolation_forest.pkl
backend/app/ml/scaler.pkl
```

The model automatically reloads on server restart — you do not need to retrain after every restart.

---

## 12. API Rules System (api_rules.yaml)

The rules file lives at `docs/api_rules.yaml`. It serves two purposes:

1. **Pre-seeds schemas** so the ML model knows about endpoints before traffic arrives (solves cold-start)
2. **Defines security rules** that run on every request regardless of ML score

### File structure

```yaml
version: "1.0"

global_rules:
  require_auth_by_default: true      # Flag any unauth request by default
  max_latency_ms: 2000               # Flag requests slower than this
  flag_admin_without_auth: true      # Always flag admin access without token
  flag_delete_without_auth: true     # Always flag DELETE without token

endpoints:
  - path: /api/users/login           # Exact path (no domain)
    method: POST                     # HTTP method (uppercase)
    auth_required: false             # Does this endpoint need a Bearer token?
    admin_only: false                # Is this an admin-only endpoint?
    expected_status: [200, 401, 429] # Normal response codes for this endpoint
    normal_latency_ms: 300           # Expected average latency
    request_fields:                  # Fields expected in request body
      - name: email
        type: string
        required: true
      - name: password
        type: string
        required: true
    risk_notes: "Monitor for credential stuffing"
```

### How to add a new endpoint

1. Open `docs/api_rules.yaml`
2. Add a new entry under `endpoints:`:

```yaml
  - path: /api/payments/charge
    method: POST
    auth_required: true
    admin_only: false
    expected_status: [200, 400, 401, 402]
    normal_latency_ms: 500
    request_fields:
      - name: amount
        type: integer
        required: true
      - name: currency
        type: string
        required: true
      - name: card_token
        type: string
        required: true
    risk_notes: "High value endpoint — flag any access without auth or unusual amounts"
```

3. Save the file
4. Call the reload endpoint:

**In Postman:** `POST http://localhost:8000/api/rules/reload`

The system will immediately:
- Create a learned schema for `/api/payments/charge POST`
- Generate synthetic training data for this endpoint
- Retrain the model combining new + existing data

> You do **not** need to restart the server.

### How rules affect scoring

| Condition | Severity | Effect |
|---|---|---|
| Admin endpoint accessed without Bearer token | High | Forces risk to HIGH regardless of ML score |
| DELETE/PUT/PATCH without Bearer token | High | Forces risk to HIGH |
| Status code not in `expected_status` | Medium | Boosts risk to MEDIUM if ML says LOW |
| Request latency > `max_latency_ms` | Medium | Boosts risk to MEDIUM |
| Unknown field in request body | Medium | Boosts risk to MEDIUM |
| Missing required field | High | Forces risk to HIGH |

### Viewing current rules

**In Postman:** `GET http://localhost:8000/api/rules/view`

### Checking rules for a specific endpoint

**In Postman:** `GET http://localhost:8000/api/rules/check/POST/api/users/login`

---

## 13. Testing API Endpoints in Postman

Import this collection manually or set up each request as described below.

Set your **Base URL** as a Postman variable: `{{base_url}} = http://localhost:8000`

---

### 🟢 Health Check

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/health` |
| Body | None |

Expected response:
```json
{
  "status": "ok",
  "version": "0.1.0",
  "env": "development",
  "model_provider": "ollama",
  "ml_available": true
}
```

---

### 🟡 Ingest Normal Traffic

| Field | Value |
|---|---|
| Method | POST |
| URL | `{{base_url}}/api/traffic/ingest` |
| Body type | raw → JSON |

Body:
```json
{
  "method": "POST",
  "url": "http://target-api.com/api/users/login",
  "request_headers": {
    "content-type": "application/json",
    "user-agent": "Mozilla/5.0"
  },
  "request_body": "{\"email\":\"user@example.com\",\"password\":\"secret123\"}",
  "status_code": 200,
  "latency_ms": 145.5,
  "source_ip": "192.168.1.10",
  "session_id": "sess_abc123"
}
```

Expected response:
```json
{
  "risk_level": "low",
  "anomaly_score": 0.12,
  "is_flagged": false,
  "explanation": "Request is within normal parameters.",
  "explanation_source": "rules_engine"
}
```

---

### 🔴 Ingest Suspicious Traffic (Admin without auth)

Body:
```json
{
  "method": "DELETE",
  "url": "http://target-api.com/api/admin/users/99",
  "request_headers": {
    "user-agent": "python-httpx"
  },
  "status_code": 200,
  "latency_ms": 120.0,
  "source_ip": "185.220.101.5"
}
```

Expected response:
```json
{
  "risk_level": "high",
  "anomaly_score": 0.75,
  "is_flagged": true,
  "explanation": "[Rules Engine] This request was flagged due to: missing or invalid authorization header; access to administrative endpoint; destructive HTTP method (DELETE)...",
  "explanation_source": "rules_engine"
}
```

---

### 🔴 Ingest High Latency Attack Probe

Body:
```json
{
  "method": "POST",
  "url": "http://target-api.com/api/users/login",
  "request_headers": {
    "content-type": "application/json"
  },
  "request_body": "{\"email\":\"admin' OR 1=1--\",\"password\":\"anything\"}",
  "status_code": 500,
  "latency_ms": 3200.0,
  "source_ip": "45.33.32.156"
}
```

---

### 📋 Get Recent Traffic Logs

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/traffic/recent?limit=20` |
| Body | None |

---

### 📊 Get Traffic Stats

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/traffic/stats` |

Expected response:
```json
{
  "total_requests": 82,
  "flagged_count": 8,
  "by_risk_level": {
    "low": 50,
    "medium": 24,
    "high": 8
  }
}
```

---

### 🧠 Train the ML Model

| Field | Value |
|---|---|
| Method | POST |
| URL | `{{base_url}}/api/anomaly/train` |
| Body | None |

> Run this after seeding data. Requires 20+ traffic logs.

---

### 🔍 Analyze a Specific Log

| Field | Value |
|---|---|
| Method | POST |
| URL | `{{base_url}}/api/anomaly/analyze/{log_id}` |
| Body | None |

Replace `{log_id}` with a UUID from the recent traffic response.

Expected response:
```json
{
  "anomaly_score": 0.82,
  "risk_level": "high",
  "is_flagged": true,
  "deviations": [
    {
      "type": "missing_required_auth",
      "detail": "DELETE /api/admin/users/99 requires authentication",
      "severity": "high",
      "source": "endpoint_rule"
    }
  ],
  "explanation": "[Rules Engine] This request was flagged due to...",
  "explanation_source": "rules_engine",
  "model_trained": true
}
```

---

### 🔍 Score All Unscored Logs

| Field | Value |
|---|---|
| Method | POST |
| URL | `{{base_url}}/api/anomaly/analyze-all` |

---

### 🚨 Get All Flagged Requests

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/anomaly/flagged` |

---

### 📖 View All Learned Schemas

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/schema/all` |

---

### 📖 View Schema for Specific Endpoint

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/schema/POST/api/users/login` |

---

### 📜 View Current Rules

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/rules/view` |

---

### 🔄 Reload Rules + Retrain Model

| Field | Value |
|---|---|
| Method | POST |
| URL | `{{base_url}}/api/rules/reload` |

> Call this every time you edit `api_rules.yaml`.

---

### 🔎 Check Rules for an Endpoint

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/api/rules/check/DELETE/api/admin/users/5` |

---

## 14. Explanation Engine

Every flagged request gets an explanation of why it was flagged. The platform uses two engines:

### Engine 1 — LLM (Primary)

Uses `llama3.2:1b` running locally via Ollama. Generates natural language explanations like a security analyst would write.

**When active:** `"explanation_source": "llm"`

**Requirements:** Ollama running + model pulled + sufficient GPU/CPU memory

**Sample output:**
```
This DELETE request to an admin endpoint with no authorization header strongly 
suggests an unauthorized access attempt, possibly automated. The source IP 
185.220.101.5 is a known Tor exit node, indicating the attacker may be 
attempting to cover their tracks while probing for privilege escalation 
vulnerabilities.
```

### Engine 2 — Rules Engine (Fallback)

Deterministic, instant explanations based on security rules. Always available — no hardware requirements.

**When active:** `"explanation_source": "rules_engine"`

**Sample output:**
```
[Rules Engine] This request was flagged due to: missing or invalid authorization 
header; access to administrative endpoint; destructive HTTP method (DELETE). 
Anomaly score of 0.75 indicates possible privilege escalation or unauthorized 
admin access. Recommend investigating source IP 185.220.101.5.
```

### Switching between engines

Edit `.env` — no code changes needed:

```env
# Use local Ollama LLM
MODEL_PROVIDER=ollama
OLLAMA_LLM_MODEL=llama3.2:1b

# Use OpenAI instead (future)
MODEL_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

The rules engine fallback is always active regardless of setting.

---

## 15. Alerting System

### Console Alerts (Always Active)

Every HIGH risk request prints to the uvicorn terminal:

```
============================================================
🚨 [HIGH] ANOMALY DETECTED
   DELETE /api/admin/users/99
   Score: 0.75 | IP: 185.220.101.5
   Status: 200 | Latency: 120.0ms
   Deviations:
     - admin_access_without_auth: Admin endpoint accessed without valid auth token
     - destructive_method_without_auth: DELETE request made without authorization
============================================================
```

### Slack Alerts (Optional)

1. Create a Slack Incoming Webhook at https://api.slack.com/apps
2. Add to `.env`:
```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```
3. Restart the server

Slack messages include: risk level, endpoint, IP, score, deviations, and LLM explanation.

---

## 16. Current Status & Roadmap

### ✅ Built and Working

- Traffic ingestion API with Ollama embeddings
- Automatic schema learning per endpoint
- Isolation Forest anomaly detection (ML)
- Rule-based detection engine
- Doc-driven rules (`api_rules.yaml`)
- Cold-start solution (synthetic training from docs)
- LLM explanation with rules engine fallback
- Console and Slack alerting
- Abstracted ML provider (swap Ollama ↔ OpenAI via config)
- Model persistence across server restarts

### ⏳ In Progress

- React dashboard (traffic feed, risk heatmap, anomaly timeline)

### 📋 Planned — Phase 2

- mitmproxy capture (intercept real traffic automatically)
- Request replayer (Burp Repeater equivalent)
- Fuzzing engine (SQLi, XSS, IDOR, JWT attacks)
- Vulnerability detection and report generation
- PDF export of findings
- Adaptive feedback loop (Phase 1 anomaly → trigger Phase 2 scan)

---

## 17. Troubleshooting

### `password authentication failed for user "apisec"`

Your local PostgreSQL on port 5432 is intercepting the connection.

**Fix:** Ensure `.env` uses port `5433` and `127.0.0.1`:
```env
DATABASE_URL=postgresql://apisec:apisec123@127.0.0.1:5433/apisecdb
```

### `Ollama completion failed: out of memory`

Your GPU doesn't have enough free VRAM.

**Fix A:** Force CPU mode:
```bash
set CUDA_VISIBLE_DEVICES=
ollama serve
```
**Fix B:** The platform automatically falls back to the rules engine. No action needed.

### `Need 20+ logs` when training

Not enough traffic data in the database.

**Fix:** Run the seeder first:
```bash
python seed.py
```
Then call `POST /api/rules/reload` which combines synthetic + real data.

### `ModuleNotFoundError` on startup

Virtual environment not activated or packages not installed.

**Fix:**
```bash
cd backend
.venv\Scripts\activate
pip install -r requirements.txt
```

### Alembic `Can't locate revision` error

Migration history is inconsistent.

**Fix (development only — deletes data):**
```bash
docker compose down -v
docker compose up -d
alembic upgrade head
```

### Model scores everything as `low` risk

Model was trained before schema learner had stable data, or not trained at all.

**Fix:**
1. Run `python seed.py` to populate data
2. Call `POST /api/rules/reload` to seed schemas + retrain
3. Call `POST /api/anomaly/analyze-all` to re-score existing logs

---

## Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make changes
3. Test all affected endpoints in Postman
4. If you add new endpoints — add them to `docs/api_rules.yaml`
5. Run `POST /api/rules/reload` after editing the rules file
6. Commit: `git commit -m "feat: describe your change"`

---

*README last updated: Phase 1 complete. React dashboard in progress.*
