# 🔐 Intelligent API Security Platform

> A unified API security platform combining **ML-based passive monitoring** (Phase 1) and **active vulnerability testing** (Phase 2). Built with FastAPI, Isolation Forest, Ollama local LLMs, PostgreSQL, and a React dashboard.

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
11. [React Dashboard](#11-react-dashboard)
12. [Training the ML Model](#12-training-the-ml-model)
13. [API Rules System (api_rules.yaml)](#13-api-rules-system-api_rulesyaml)
14. [Testing API Endpoints in Postman](#14-testing-api-endpoints-in-postman)
15. [Testing a Real API](#15-testing-a-real-api)
16. [Explanation Engine](#16-explanation-engine)
17. [Alerting System](#17-alerting-system)
18. [Current Status & Roadmap](#18-current-status--roadmap)
19. [Troubleshooting](#19-troubleshooting)

---

## 1. Project Overview

This platform solves a critical gap in API security tooling — most organizations use **separate, disconnected tools** for monitoring and testing with no feedback loop between them.

### Phase 1 — ML Monitoring (Built ✅)
- Captures all API traffic via an ingestion endpoint
- Learns normal behavior automatically per endpoint (schema learning)
- Detects anomalies using **Isolation Forest** ML model
- Explains suspicious requests via **local LLM** (Ollama) or **rules engine** fallback
- Fires real-time alerts to console and Slack
- **React dashboard** with live traffic feed, risk heatmap, flagged request viewer, schema browser

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
    └────────┬──────────┘
             ↓
    ┌───────────────────┐
    │  React Dashboard  │
    │  localhost:5173   │
    └───────────────────┘
```

---

## 3. Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend API | FastAPI (Python 3.11+) | Async REST API |
| Database | PostgreSQL 16 | Structured storage |
| Search | Elasticsearch 8.x | Log search |
| Cache / Queue | Redis 7 | Task queue |
| ML — Anomaly | scikit-learn (Isolation Forest) | Anomaly scoring |
| ML — Embeddings | nomic-embed-text via Ollama | Traffic vectorization |
| ML — LLM | llama3.2:1b via Ollama | Natural language explanation |
| Migrations | Alembic | Database schema versioning |
| ORM | SQLAlchemy (async) | Database access |
| Container | Docker + Docker Compose | Infrastructure |
| Frontend | React + TypeScript + Vite | Dashboard |
| Charts | Recharts | Data visualization |
| Icons | Lucide React | UI icons |

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
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── client.ts         ← Axios base client
│   │   │   └── endpoints.ts      ← All API calls
│   │   ├── App.tsx               ← Main dashboard component
│   │   ├── App.css               ← Dashboard styles
│   │   ├── index.css             ← Global styles & CSS variables
│   │   └── main.tsx              ← React entry point
│   ├── package.json
│   └── vite.config.ts
├── proxy/                        ← mitmproxy scripts (Phase 2)
├── docker-compose.yml            ← Infrastructure services
├── .env                          ← Environment config (never commit)
├── .env.example                  ← Safe template to share
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

### Step 2 — Copy environment config

```bash
copy .env.example .env
```

Edit `.env` with your values (see [Section 9](#9-configuration-env)).

### Step 3 — Start infrastructure services

```bash
docker compose up -d
```

This starts PostgreSQL (port 5433), Redis (port 6379), and Elasticsearch (port 9200).

Verify all three are running:

```bash
docker ps
```

You should see `apisec_postgres`, `apisec_redis`, and `apisec_elastic` with status `Up`.

### Step 4 — Create Python virtual environment

```bash
cd backend
python -m venv .venv
```

**Activate it:**

- Windows Command Prompt: `.venv\Scripts\activate`
- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- macOS / Linux: `source .venv/bin/activate`

Your terminal prompt should now show `(.venv)`.

### Step 5 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 6 — Install frontend dependencies

Open a second terminal:

```bash
cd frontend
npm install
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

> **Note:** Use `127.0.0.1` not `localhost`. On Windows, `localhost` sometimes resolves to IPv6 (`::1`) which causes authentication failures.

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

### GPU Memory Issues

If Ollama fails with `out of memory`, your GPU doesn't have enough free VRAM.

**Option A — Force CPU mode (Windows):**
```bash
set CUDA_VISIBLE_DEVICES=
ollama serve
```

**Option B — Use rules engine fallback:**

The platform automatically falls back to the rules engine if the LLM is unavailable. No action needed — it just works. Every response will show `"explanation_source": "rules_engine"` instead of `"llm"`.

**Option C — Switch to cloud LLM:**

Change `MODEL_PROVIDER=openai` in `.env` and add `OPENAI_API_KEY`. No code changes required.

---

## 9. Configuration (.env)

The `.env` file lives at the project root `api-security/.env`. It controls all platform settings. Never commit this file — use `.env.example` as the shareable template.

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
OLLAMA_LLM_MODEL=llama3.2:1b

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
3. Restart the server — no code changes needed

### Enabling Slack Alerts

1. Go to your Slack workspace → Apps → Incoming Webhooks → Create
2. Copy the webhook URL
3. Set `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`
4. Restart the server

---

## 10. Running the Application

You need **two terminals** running simultaneously — one for the backend, one for the frontend.

### Terminal 1 — Backend

```bash
cd api-security\backend
.venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

### Terminal 2 — Frontend

```bash
cd api-security\frontend
npm run dev
```

### Verify everything is running

| URL | What you should see |
|---|---|
| http://localhost:8000/health | `{"status":"ok","ml_available":true}` |
| http://localhost:8000/docs | Swagger UI with all API endpoints |
| http://localhost:5173 | React dashboard |

### Seed test data (first time only)

Open a third terminal:

```bash
cd api-security\backend
.venv\Scripts\activate
python seed.py
```

This sends 50 realistic traffic records to populate the database and train the schema learner.

---

## 11. React Dashboard

Open **http://localhost:5173** in your browser. The dashboard auto-refreshes every 15 seconds.

### Overview Tab
- **Stat cards** — Total requests, flagged count, high risk count, schemas learned
- **Latency timeline** — Area chart of the last 40 requests
- **Risk breakdown** — Bar chart of High / Medium / Low distribution
- **Endpoint risk heatmap** — Top 8 endpoints ranked by flagged request ratio

### Traffic Tab
- Full scrollable table of all captured traffic
- Color-coded method tags (GET=blue, POST=green, DELETE=red, etc.)
- Color-coded status codes (2xx=green, 4xx=yellow, 5xx=red)
- Risk badges and anomaly scores per request
- Latency highlighted red when above 1000ms

### Flagged Tab
- All requests flagged as HIGH risk
- Click any row to expand and see full analysis:
  - Anomaly score and risk level
  - All rule violations and deviations with severity
  - Full explanation from rules engine or LLM
  - Shows `explanation_source: llm` or `rules_engine`

### Schemas Tab
- Cards showing what the ML model has learned about each endpoint
- Sample count, average latency, known status codes
- Request field names with frequency % and required/optional status
- Stability indicator (stable after 10+ samples)

### Sidebar Actions
| Button | What it does |
|---|---|
| Reload Rules | Re-reads `api_rules.yaml`, seeds schemas, retrains model |
| Train Model | Trains Isolation Forest on all stored traffic |
| Score All Logs | Runs anomaly scoring on all unscored logs |
| Refresh Data | Manually triggers a data refresh |

---

## 12. Training the ML Model

The ML model (Isolation Forest) must be trained before it can score traffic. Training uses stored traffic logs to learn what normal behavior looks like.

### When to train

- After first setup (seed data first)
- After loading rules from `api_rules.yaml`
- After significant new traffic accumulates
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

Combines synthetic baseline data from `api_rules.yaml` with real traffic. Solves the cold-start problem — new endpoints are known before any traffic arrives.

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

> **Always use Method 2** after editing `api_rules.yaml`.

### Score all existing unscored logs

After training, run this to retroactively score logs:

**In Postman:** `POST http://localhost:8000/api/anomaly/analyze-all`

### Model persistence

The trained model is saved to disk at:
```
backend/app/ml/isolation_forest.pkl
backend/app/ml/scaler.pkl
```

The model automatically reloads on server restart — no retraining needed after every restart.

---

## 13. API Rules System (api_rules.yaml)

The rules file lives at `docs/api_rules.yaml`. It serves two purposes:

1. **Pre-seeds schemas** so the ML model knows about endpoints before traffic arrives
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
    risk_notes: "High value endpoint — flag any access without auth"
```

3. Save the file
4. Call the reload endpoint in Postman: `POST http://localhost:8000/api/rules/reload`

The system immediately creates a learned schema, generates synthetic training data, and retrains the model. No server restart needed.

### How rules affect scoring

| Condition | Severity | Effect on Risk |
|---|---|---|
| Admin endpoint without Bearer token | High | Forces HIGH regardless of ML score |
| DELETE/PUT/PATCH without Bearer token | High | Forces HIGH |
| Status code not in `expected_status` | Medium | Boosts to MEDIUM if ML says LOW |
| Latency > `max_latency_ms` | Medium | Boosts to MEDIUM |
| Unknown field in request body | Medium | Boosts to MEDIUM |
| Missing required field | High | Forces HIGH |

### Viewing current rules

`GET http://localhost:8000/api/rules/view`

### Checking rules for a specific endpoint

`GET http://localhost:8000/api/rules/check/POST/api/users/login`

---

## 14. Testing API Endpoints in Postman

Set your **Base URL** as a Postman variable: `{{base_url}} = http://localhost:8000`

> **Important:** When ingesting traffic, the `url` field in the body is just data describing what request was observed — you are NOT making a request to that URL. You are sending metadata to your platform's ingest endpoint.

---

### 🟢 Health Check

| Field | Value |
|---|---|
| Method | GET |
| URL | `{{base_url}}/health` |

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
| Body | raw → JSON |

```json
{
  "method": "POST",
  "url": "http://target-api.com/api/users/login",
  "request_headers": {
    "content-type": "application/json",
    "authorization": "Bearer valid_token_abc",
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

### 🔴 Ingest Suspicious Traffic — Admin without auth

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

Expected:
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

### 🔴 Ingest SQL Injection Attempt

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

| Method | GET |
|---|---|
| URL | `{{base_url}}/api/traffic/recent?limit=50` |

---

### 📊 Get Traffic Stats

| Method | GET |
|---|---|
| URL | `{{base_url}}/api/traffic/stats` |

---

### 🧠 Train the ML Model

| Method | POST |
|---|---|
| URL | `{{base_url}}/api/anomaly/train` |

Requires 20+ traffic logs. Run seed.py first if needed.

---

### 🔍 Analyze a Specific Log

| Method | POST |
|---|---|
| URL | `{{base_url}}/api/anomaly/analyze/{log_id}` |

Replace `{log_id}` with a UUID from the recent traffic response.

Expected response:
```json
{
  "anomaly_score": 0.82,
  "risk_level": "high",
  "is_flagged": true,
  "deviations": [
    {
      "type": "admin_access_without_auth",
      "detail": "Admin endpoint accessed without valid auth token",
      "severity": "high",
      "source": "global_rule"
    }
  ],
  "explanation": "[Rules Engine] This request was flagged due to...",
  "explanation_source": "rules_engine",
  "model_trained": true
}
```

---

### 🔍 Score All Unscored Logs

| Method | POST |
|---|---|
| URL | `{{base_url}}/api/anomaly/analyze-all` |

---

### 🚨 Get All Flagged Requests

| Method | GET |
|---|---|
| URL | `{{base_url}}/api/anomaly/flagged` |

---

### 📖 View All Learned Schemas

| Method | GET |
|---|---|
| URL | `{{base_url}}/api/schema/all` |

---

### 🔄 Reload Rules + Retrain Model

| Method | POST |
|---|---|
| URL | `{{base_url}}/api/rules/reload` |

Call this every time you edit `api_rules.yaml`.

---

## 15. Testing a Real API

You can feed real API traffic into the platform for analysis. Here is an example using a live endpoint.

### Step 1 — Hit the real API in Postman

```
GET https://shopqa.leykart.com/rest/V1/stores-list/top-level
```

Note the response time shown at the bottom of Postman (e.g. `380ms`).

### Step 2 — Add the endpoint to api_rules.yaml

```yaml
  - path: /rest/V1/stores-list/top-level
    method: GET
    auth_required: false
    admin_only: false
    expected_status: [200]
    normal_latency_ms: 400
    request_fields: []
    risk_notes: "Public endpoint — monitor for scraping"
```

Then call `POST http://localhost:8000/api/rules/reload`.

### Step 3 — Ingest the real request into the platform

```json
POST http://localhost:8000/api/traffic/ingest

{
  "method": "GET",
  "url": "https://shopqa.leykart.com/rest/V1/stores-list/top-level",
  "request_headers": {
    "user-agent": "PostmanRuntime/7.36",
    "accept": "*/*"
  },
  "status_code": 200,
  "latency_ms": 380.0,
  "source_ip": "103.21.58.10"
}
```

### Step 4 — Simulate attack scenarios

**Scanner probe (sqlmap):**
```json
{
  "method": "GET",
  "url": "https://shopqa.leykart.com/rest/V1/stores-list/top-level",
  "request_headers": { "user-agent": "sqlmap/1.7.8#stable" },
  "status_code": 200,
  "latency_ms": 89.0,
  "source_ip": "185.220.101.5"
}
```

**DoS probe (high latency + server error):**
```json
{
  "method": "GET",
  "url": "https://shopqa.leykart.com/rest/V1/stores-list/top-level",
  "request_headers": { "user-agent": "Mozilla/5.0" },
  "status_code": 500,
  "latency_ms": 8500.0,
  "source_ip": "92.118.160.11"
}
```

**Admin endpoint enumeration:**
```json
{
  "method": "GET",
  "url": "https://shopqa.leykart.com/rest/V1/admin/users",
  "request_headers": { "user-agent": "python-requests/2.31.0" },
  "status_code": 403,
  "latency_ms": 120.0,
  "source_ip": "185.220.101.5"
}
```

### Step 5 — Check the dashboard

Go to `http://localhost:5173` → Refresh → Flagged tab. Click any flagged row to see the full analysis with rule violations and explanation.

> **Note:** In production, a mitmproxy layer will capture real traffic automatically and feed it to the ingest endpoint — no manual Postman steps needed. This is planned for Phase 2.

---

## 16. Explanation Engine

Every medium/high risk request gets an explanation of why it was flagged. The platform has two engines and automatically falls back from LLM to rules engine if needed.

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

Deterministic, instant explanations based on security rules. Always available — no hardware requirements. Activates automatically when LLM is unavailable.

**When active:** `"explanation_source": "rules_engine"`

**Sample output:**
```
[Rules Engine] This request was flagged due to: missing or invalid authorization 
header; access to administrative endpoint; destructive HTTP method (DELETE). 
Anomaly score of 0.75 indicates possible privilege escalation or unauthorized 
admin access. Recommend investigating source IP 185.220.101.5.
```

### Switching between engines

Edit `.env` only — no code changes needed:

```env
# Local Ollama (default)
MODEL_PROVIDER=ollama
OLLAMA_LLM_MODEL=llama3.2:1b

# OpenAI cloud (swap in anytime)
MODEL_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

---

## 17. Alerting System

### Console Alerts (Always Active)

Every HIGH risk request prints immediately to the uvicorn terminal:

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

Slack messages include: risk level, endpoint, source IP, anomaly score, all deviations, and the full explanation text.

---

## 18. Current Status & Roadmap

### ✅ Built and Working

- Traffic ingestion API with Ollama embeddings
- Automatic schema learning per endpoint
- Isolation Forest anomaly detection (ML)
- Rule-based detection engine
- Doc-driven rules (`api_rules.yaml`)
- Cold-start solution (synthetic training from docs)
- LLM explanation with rules engine fallback
- Abstracted ML provider (swap Ollama ↔ OpenAI via `.env`)
- Model persistence across server restarts
- Console and Slack alerting
- React dashboard with 4 tabs:
  - Overview (stats, latency chart, risk breakdown, endpoint heatmap)
  - Traffic (live scrollable table with risk scores)
  - Flagged (expandable rows with full analysis + deviations + explanation)
  - Schemas (learned endpoint behavior cards)
- Real API testing workflow (Postman → ingest → dashboard)

### 📋 Planned — Phase 2

- mitmproxy proxy layer (automatic real traffic capture)
- Request replayer (Burp Suite Repeater equivalent)
- Fuzzing engine (SQLi, XSS, IDOR, JWT attacks)
- Attack template engine (OWASP Top 10 coverage)
- Vulnerability detection and findings database
- PDF report generation and export
- Adaptive feedback loop (Phase 1 anomaly → trigger Phase 2 scan)
- RBAC and multi-tenant support

---

## 19. Troubleshooting

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

**Fix:** Run the seeder first, then reload rules:
```bash
python seed.py
```
Then call `POST http://localhost:8000/api/rules/reload`.

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

**Fix (development only — deletes all data):**
```bash
docker compose down -v
docker compose up -d
alembic upgrade head
```

### Model scores everything as `low` risk

Model was trained before schema learner had stable data, or not trained at all.

**Fix — run these in order:**
1. `python seed.py`
2. `POST http://localhost:8000/api/rules/reload`
3. `POST http://localhost:8000/api/anomaly/analyze-all`

### Dashboard shows `⚠ Could not reach backend`

uvicorn is not running or crashed.

**Fix:**
```bash
cd backend
.venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

### Frontend won't start — `npm run dev` fails

Node modules not installed.

**Fix:**
```bash
cd frontend
npm install
npm run dev
```

---

## Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make changes to backend or frontend
3. Test all affected endpoints in Postman
4. If you add new API endpoints — add them to `docs/api_rules.yaml`
5. Run `POST http://localhost:8000/api/rules/reload` after editing the rules file
6. Commit: `git commit -m "feat: describe your change"`
7. Push and open a pull request

---

*README last updated: Phase 1 complete including React dashboard. Phase 2 active testing engine in planning.*
