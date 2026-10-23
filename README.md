# AI Issue-to-Fix Agent

FastAPI app for issue analysis, patch generation and validation, isolated test execution, human review, and audit tracking.

## Capabilities

- Uses an optional OpenAI-compatible LLM to analyze issue context and source code beyond predefined patterns.
- Uses conservative local rules when no LLM API key is configured. A configured LLM failure is reported instead of silently falling back.
- Generates a patch only when a supported finding exists; validates the target path and patch before review.
- Runs user-provided JavaScript tests in a network-restricted browser Web Worker that is terminated on timeout. Submitted code is never executed on the backend.
- Records each run, browser test results, approval/rejection, and audit events in SQLite. Patch approval is bound to the exact original file and validated patch.
- Does not write changes to a repository; an approved patch can be reviewed and copied.

## Run locally

```powershell
cd backend
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-value"
$env:OPENAI_API_KEY = "your-server-side-api-key" # optional
# Optional: $env:LLM_MODEL = "gpt-4o-mini"
# Optional: $env:LLM_API_URL = "https://api.openai.com/v1/chat/completions"
# Optional: $env:AUDIT_DB_PATH = "C:\data\ai-issue-audit.sqlite3"
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. Never put the LLM API key in the frontend. Without `OPENAI_API_KEY`, only the built-in limited rule analyzer runs.

Run backend tests from the repository root:

```powershell
python -m unittest discover -s backend/tests
```

## Deploy on Render

1. Push this repository to GitHub.
2. In Render, choose **New > Blueprint** and select the repository.
3. Configure `SECRET_KEY` and (optionally) `OPENAI_API_KEY`, `LLM_MODEL`, and `LLM_API_URL` in the service environment.
4. Open the generated `onrender.com` URL.

`render.yaml` sets the start command and health check. SQLite audit data is stored at `AUDIT_DB_PATH` or `backend/audit.sqlite3` by default. Render's free filesystem is ephemeral; use a persistent disk or durable database and set `AUDIT_DB_PATH` there if audit history must survive instance replacement/deploys.

Free instances sleep after inactivity, so the first request can take about 50 seconds.
