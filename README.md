# AI Issue-to-Fix Agent

FastAPI backend (screening, analysis, patch validation, signed approvals) serving a static frontend.
Tests run in a sandboxed iframe in the browser; the server never executes submitted code.

## Run locally
    cd backend
    pip install -r requirements.txt
    uvicorn app.main:app --reload
    # open http://127.0.0.1:8000

## Deploy on Render
1. Push this folder to a GitHub repo (render.yaml at the repo root).
2. Render dashboard > New > Blueprint > pick the repo > Apply.
   (Or New > Web Service with: build `pip install -r backend/requirements.txt`,
   start `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`,
   health check `/healthz`, env var SECRET_KEY = any long random string.)
3. Open the generated onrender.com URL.

Free instances sleep after inactivity, so the first request can take about 50 seconds.
Audit entries are in memory and reset on restart; add PostgreSQL to persist them.
