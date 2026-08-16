# SecureCode Sentinel - Backend Service

FastAPI backend application for the SecureCode Sentinel SAST platform.

## Architecture

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app initialization and CORS middleware
│   ├── routes/          # API route definitions
│   │   ├── __init__.py
│   │   └── health.py    # System health check endpoint
│   ├── analyzers/       # Static analysis engine wrappers (Planned)
│   ├── scoring/         # Vulnerability severity & risk scoring engine (Planned)
│   ├── remediation/     # Secure coding advice & remediation logic (Planned)
│   └── models/          # Pydantic schemas and domain models
├── requirements.txt     # Python dependencies
└── README.md
```

## Getting Started

### 1. Prerequisites
- Python 3.10+ installed

### 2. Setup Virtual Environment
```bash
python -m venv venv
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Development Server
```bash
uvicorn app.main:app --reload --port 8000
```

The API will be available at:
- **Health Check**: [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Interactive OpenAPI Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
