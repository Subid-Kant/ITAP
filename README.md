# ITAP (Integrated Threat Assessment Platform)
### An Autonomous Multi-Vector Cyber Threat Intelligence, Prediction & Incident Response Platform

> *"Advanced Intelligence, Integrated Defence."*

**Authors:** Subid Kant & Sparsh Sant Lal  
**Institution:** SRMCEM Lucknow | B.Tech Final Year 2025-26 | Cyber Security (CY)

---

## 🏗️ Architecture — 5 Intelligent Layers

| Layer | Name | Components |
|-------|------|-----------|
| **L1** | OSINT Data Ingestion | Shodan, VirusTotal, Censys, AlienVault OTX, CVE/NVD |
| **L2** | AI/ML Engine | LSTM Predictor, Autoencoder, NLP Classifier, Severity Scorer |
| **L3** | Threat Intelligence Core | MITRE ATT&CK Mapper, Kill-Chain Engine, Threat DNA, IOC Enrichment |
| **L4** | Response Engine | LLM Playbook Generator, Auto-Alerts, SIEM Integration |
| **L5** | SOC Dashboard | Heatmap, Timeline, ATT&CK Matrix, Geolocation, PDF Export |

## 🚀 Quick Start

### Backend (FastAPI)
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# To seed database with realistic ITAP data:
python seed_data.py
# Start server:
uvicorn main:app --reload --port 8000
```

### Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```

### Access
- **Dashboard:** http://localhost:5173
- **API Docs:** http://localhost:8000/docs
- **API Base:** http://localhost:8000/api/v1

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/targets` | Add monitoring target |
| POST | `/api/v1/scan` | Run OSINT scan |
| POST | `/api/v1/ml/predict` | LSTM threat prediction |
| POST | `/api/v1/ml/anomaly-detect` | Zero-day detection |
| GET | `/api/v1/threats` | List threats |
| GET | `/api/v1/mitre/matrix` | MITRE ATT&CK matrix |
| POST | `/api/v1/threat-intel/kill-chain` | Kill chain analysis |
| POST | `/api/v1/playbook/generate` | AI playbook generation |
| GET | `/api/v1/dashboard/stats` | Dashboard statistics |

## 🔑 OSINT API Keys (Optional)
Add to `backend/.env` for live data (demo mode works without keys):
```
SHODAN_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ALIENVAULT_OTX_KEY=your_key
```

## 🛡️ Key Features
- **Predictive Threat Forecasting** — LSTM neural network predicts exploits 24-72 hours ahead
- **Real-Time OSINT Correlation** — Multi-source intelligence aggregation
- **MITRE ATT&CK Auto-Mapping** — Automatic tactic/technique classification
- **AI Playbook Generator** — Context-aware remediation in plain English
- **Threat DNA Fingerprinting** — Zero-day detection via autoencoder anomaly scoring
- **Industry-Ready SOC Dashboard** — Heatmaps, timelines, geolocation, PDF reports
