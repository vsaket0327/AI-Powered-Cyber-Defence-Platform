# AI-Powered Cyber Defence Platform — Starter

## Prerequisites
Python 3.11+, Node.js 20+, Docker Desktop, Git.

## Start PostgreSQL
From the project root:
```powershell
docker compose up -d db
```

## Start API (Windows PowerShell)
```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/health and http://127.0.0.1:8000/docs.

## Start frontend in a second terminal
```powershell
cd frontend
npm install
npm run dev
```
Open http://localhost:5173.

## Test backend
From `backend` with its virtual environment active: `pytest`

This first milestone is only a foundation: health endpoint, React status dashboard, PostgreSQL service and API tests. It does not claim real threat reputation or scan systems. Next milestone: validated indicator-analysis API.
