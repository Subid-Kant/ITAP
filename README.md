# ITAP — Integrated Threat Assessment Platform

### An Autonomous Multi-Vector Cyber Threat Intelligence, Prediction & Incident Response Platform

> *"Advanced Intelligence, Integrated Defence."*

**Authors:** Subid Kant & Sparsh Sant Lal
**Institution:** SRMCEM Lucknow | B.Tech Final Year 2025–26 | Cyber Security (CY)

---

## 🏗️ Architecture — 5 Intelligent Layers

| Layer | Name | Components |
|-------|------|------------|
| **L1** | OSINT Data Ingestion | Shodan, VirusTotal, Censys, AlienVault OTX, CVE/NVD, Nmap Active Scanning |
| **L2** | AI/ML Engine | LSTM Predictor, Autoencoder (Zero-Day Detection), NLP Classifier, Severity Scorer, Local LLM Service |
| **L3** | Threat Intelligence Core | MITRE ATT&CK Mapper, Kill-Chain Engine, Threat DNA Fingerprinter, IOC Enrichment, Threat Actor DB |
| **L4** | Response & SOAR Engine | LLM Playbook Generator, Auto-Alerts (Email/Slack/Teams/Webhook), Mock Firewall IP Blocking |
| **L5** | SOC Dashboard | Heatmap, Timeline, ATT&CK Matrix, Geolocation Map, PDF Export, Command Palette, Live System Log |

---

## 📁 Project Structure

```
ITAP/
├── backend/                    # FastAPI backend (Python)
│   ├── main.py                 # Application entry point
│   ├── seed_data.py            # Database seeder with realistic threat data
│   ├── requirements.txt        # Production dependencies
│   ├── requirements-dev.txt    # Test/dev dependencies
│   ├── pytest.ini              # Test configuration
│   ├── .env.example            # Environment variable template
│   └── app/
│       ├── api/routes/         # REST API & WebSocket endpoints
│       ├── core/               # Config, security, middleware, caching
│       ├── db/                 # Database engine & session management
│       ├── models/             # SQLAlchemy ORM models
│       ├── schemas/            # Pydantic request/response schemas
│       └── services/
│           ├── ml/             # LSTM, Autoencoder, LLM, severity scoring
│           ├── osint/          # Shodan, VirusTotal, NVD, AlienVault, Nmap
│           ├── threat_intel/   # MITRE ATT&CK, Kill-Chain, Threat DNA, IOC
│           ├── response/       # Playbook generation, auto-alerting
│           └── monitoring/     # Server monitor, global threat feed, machine scanner
├── frontend/                   # React 19 + Vite 8 SPA
│   └── src/
│       ├── components/         # Dashboard, Scanner, MITRE, GeoMap, Reports, etc.
│       ├── hooks/              # Custom hooks (WebSocket, etc.)
│       └── services/           # API client layer
├── ai_training/                # Kaggle notebooks & dataset generation scripts
│   ├── datasets/               # Training datasets
│   └── *.ipynb                 # LSTM, Autoencoder, OSINT training notebooks
├── weights/                    # Pre-trained model weights (.h5)
├── data/                       # Telemetry datasets
└── docker-compose.yml          # Docker orchestration
```

---

## 🚀 Quick Start

### Prerequisites

- **Python** 3.10+ (tested up to 3.14)
- **Node.js** 18+ and **npm**
- **Nmap** (optional — for active scanning)
- **Redis** (optional — for scan result caching)

### Backend (FastAPI)

<details>
<summary><strong>🪟 Windows (PowerShell)</strong></summary>

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Copy and configure environment variables
copy .env.example .env
# IMPORTANT: Edit .env and set a proper SECRET_KEY (see instructions inside .env)

# Seed the database with realistic ITAP data (optional)
python seed_data.py

# Start server
uvicorn main:app --reload --port 8000
```
</details>

<details>
<summary><strong>🐧 Linux / macOS (Bash)</strong></summary>

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# IMPORTANT: Edit .env and set a proper SECRET_KEY (see instructions inside .env)

# Seed the database with realistic ITAP data (optional)
python seed_data.py

# Start server
uvicorn main:app --reload --port 8000
```
</details>

> **⚠️ SECRET_KEY is mandatory.** The app will refuse to start with the default placeholder.
> Generate one with: `python -c "import secrets; print(secrets.token_urlsafe(64))"`

### Frontend (React 19 + Vite 8)

```bash
cd frontend
npm install
npm run dev
```

### Docker (Full Stack)

```bash
docker-compose up --build
```

### Access Points

| Service | URL |
|---------|-----|
| **SOC Dashboard** | http://localhost:5173 |
| **API Docs (Swagger)** | http://localhost:8000/docs |
| **API Docs (ReDoc)** | http://localhost:8000/redoc |
| **API Base** | http://localhost:8000/api/v1 |
| **WebSocket Live Feed** | ws://localhost:8000/ws/live |
| **Health Check** | http://localhost:8000/health |

### Default Users

| Username | Role | Default Password |
|----------|------|------------------|
| `admin` | Admin | `ITAP@Admin2025!` |
| `analyst` | Analyst | `ITAP@Analyst2025!` |
| `viewer` | Viewer | `ITAP@Viewer2025!` |

> Change these via `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, `VIEWER_PASSWORD` in `backend/.env`.

---

## 📡 API Endpoints

All endpoints are prefixed with `/api/v1`. Authentication is via JWT Bearer token.

### 🔐 Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Authenticate and receive JWT tokens |
| POST | `/auth/refresh` | Refresh an expired access token |
| POST | `/auth/logout` | Revoke tokens |
| GET | `/auth/me` | Get current user info |

### 🎯 Targets

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/targets` | Add a monitoring target |
| GET | `/targets` | List all targets |
| GET | `/targets/{target_id}` | Get target by ID |
| DELETE | `/targets/{target_id}` | Delete a target |

### 🔍 OSINT Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Run multi-source OSINT scan |
| POST | `/scan/nmap` | Run active Nmap scan |
| GET | `/scan/{scan_id}` | Get scan results |

### 🤖 AI/ML Engine

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ml/status` | Get ML model status |
| POST | `/ml/predict` | LSTM threat prediction (24–72h horizon) |
| POST | `/ml/anomaly-detect` | Zero-day detection via autoencoder |
| POST | `/ml/severity-score` | Threat severity scoring |

### 🛡️ Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/threats` | List all threats |
| GET | `/threats/{threat_id}` | Get threat details |
| PUT | `/threats/{threat_id}/resolve` | Mark threat as resolved |
| GET | `/mitre/matrix` | Full MITRE ATT&CK matrix |
| GET | `/mitre/threat-actors` | Known threat actor database |
| POST | `/mitre/map` | Auto-map threat to MITRE techniques |
| POST | `/threat-intel/kill-chain` | Kill chain analysis |
| POST | `/threat-intel/ioc-enrich` | Single IOC enrichment |
| POST | `/threat-intel/ioc-bulk` | Bulk IOC enrichment |

### 🚨 Incident Response

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/incidents` | Create a new incident |
| GET | `/incidents` | List all incidents |
| GET | `/incidents/{incident_id}` | Get incident details |
| PUT | `/incidents/{incident_id}/status` | Update incident status |
| POST | `/playbook/generate` | AI-generated remediation playbook |

### 📊 Dashboard & Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard/stats` | Aggregated SOC statistics |
| GET | `/dashboard/threat-timeline` | Threat event timeline |
| GET | `/dashboard/metrics` | Dashboard metrics |
| GET | `/monitoring/server-status` | Server health & resource usage |
| GET | `/monitoring/global-threats` | Global threat feed |
| GET | `/monitoring/machine-scan` | Host machine network scan results |

### 🤖 SOAR (Security Orchestration)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/soar/block-ip` | Block IP via mock firewall (admin only) |
| GET | `/soar/blocked-ips` | List all blocked IPs |
| DELETE | `/soar/blocked-ips/{ip}` | Unblock an IP |

### 📋 Reports & System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/reports/generate` | Generate PDF/export report |
| POST | `/system/new-session` | Create new analysis session |
| GET | `/history/summary` | Historical analysis summary |
| DELETE | `/history/all` | Clear all history |
| GET | `/history/target/{target_id}` | Target-specific history |
| GET | `/system/audit-log` | Security audit trail |

---

## 🔑 OSINT API Keys

Add to `backend/.env` for live OSINT data (demo mode works without keys):

```env
SHODAN_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
ALIENVAULT_OTX_KEY=your_key
NVD_API_KEY=your_key
```

---

## 🧪 Running Tests

```bash
cd backend

# Install dev dependencies
pip install -r requirements-dev.txt

# Run the full test suite
pytest

# Run specific test files
pytest test_integration.py
pytest test_security_hardening.py
pytest test_ai_accuracy.py
pytest test_ml_metrics.py
pytest test_audit_trail.py
pytest test_telemetry_concurrency.py
pytest test_ai_output_integrity.py
```

Tests are configured with `asyncio_mode = auto` and a 120-second per-test timeout. See `pytest.ini` for details.

---

## 🧠 AI/ML Training

The `ai_training/` directory contains Kaggle notebooks and dataset generation scripts:

| Notebook | Purpose |
|----------|---------|
| `Kaggle_ITAP_OSINT_Training.ipynb` | OSINT data feature extraction & classification |
| `Kaggle_LSTM_KillChain.ipynb` | LSTM model for kill chain stage prediction |
| `Kaggle_LSTM_WAF_Payloads.ipynb` | LSTM model for WAF payload detection |
| `Kaggle_Autoencoder_Network.ipynb` | Autoencoder for zero-day anomaly detection |

Pre-trained model weights are stored in `weights/` (`.h5` format).

---

## ⚙️ Environment Configuration

See `backend/.env.example` for the complete configuration template. Key sections:

| Category | Variables |
|----------|-----------|
| **Application** | `ENVIRONMENT`, `DEBUG`, `HOST`, `PORT` |
| **Database** | `DATABASE_URL` (SQLite dev / PostgreSQL prod), `REDIS_URL` |
| **Security** | `SECRET_KEY`, `ACCESS_TOKEN_EXPIRE_MINUTES`, role passwords |
| **CORS** | `ALLOWED_ORIGINS` |
| **Rate Limiting** | `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW_SECONDS` |
| **OSINT** | Shodan, VirusTotal, Censys, AlienVault, NVD API keys |
| **Email Alerts** | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` |
| **Webhooks** | `SLACK_WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`, `WEBHOOK_URLS` |
| **Machine Scanner** | `MACHINE_SCAN_ENABLED`, `MACHINE_SCAN_INTERVAL_SECONDS` |

---

## 🛡️ Key Features

- **Predictive Threat Forecasting** — LSTM neural network predicts exploits 24–72 hours ahead
- **Real-Time OSINT Correlation** — Multi-source intelligence aggregation (Shodan, VirusTotal, NVD, OTX)
- **Active Network Scanning** — Nmap integration for host and service discovery
- **MITRE ATT&CK Auto-Mapping** — Automatic tactic/technique classification with full matrix
- **Kill Chain Analysis** — Lockheed Martin Cyber Kill Chain stage identification
- **AI Playbook Generator** — Context-aware remediation instructions in plain English
- **Threat DNA Fingerprinting** — Zero-day detection via autoencoder anomaly scoring
- **SOAR Integration** — Automated IP blocking with mock firewall (extensible)
- **Multi-Channel Alerting** — Email (SMTP), Slack, Microsoft Teams, and custom webhooks
- **JWT Authentication** — Role-based access (Admin, Analyst, Viewer) with brute-force throttling
- **Real-Time WebSocket Feed** — Authenticated live stream of threats, scans, and system events
- **Industry-Ready SOC Dashboard** — Heatmaps, timelines, geolocation, command palette, PDF reports
- **Comprehensive Audit Trail** — Security-relevant actions logged with IP, user, and timestamps
- **Background Monitoring** — Server health, global threat feed, and machine network scanning

---

## 🚢 Production Deployment Checklist

- [ ] `SECRET_KEY` set to a 64+ character random string
- [ ] `DEBUG=False`
- [ ] `ENVIRONMENT=production`
- [ ] `ALLOWED_ORIGINS` set to actual frontend domain(s)
- [ ] All default user passwords changed
- [ ] `DATABASE_URL` points to PostgreSQL with SSL
- [ ] SMTP configured for real alert delivery
- [ ] OSINT API keys configured
- [ ] TLS/HTTPS enabled via reverse proxy (Nginx / Caddy)
- [ ] Firewall restricts port 8000 to reverse proxy only
- [ ] Redis configured for scan result caching

---

## 📄 License

This project is developed as part of a B.Tech Final Year project at SRMCEM Lucknow.
