import hashlib
import secrets
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import engine, security

app = FastAPI(title="AI Issue-to-Fix Agent")
AUDIT: deque = deque(maxlen=200)


def audit(event: str, **data):
    AUDIT.append(dict(ts=time.time(), event=event, **data))


class AnalyzeIn(BaseModel):
    title: str = Field("", max_length=300)
    body: str = Field("", max_length=5000)
    path: str = Field(..., max_length=300)
    code: str = Field(..., max_length=100_000)


class AuthorizeIn(BaseModel):
    path: str = Field(..., max_length=300)
    patched: str = Field(..., max_length=100_000)
    patch_token: str
    phrase: str


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/api/analyze")
def analyze(req: AnalyzeIn):
    result = engine.analyze(req.title, req.body, req.path, req.code)
    result["patch_token"] = (
        security.patch_token(req.path, result["patched"]) if result["ok"] else None
    )
    audit("analyze", path=req.path, ok=result["ok"], injection_hits=result["screen_hits"])
    return result


@app.post("/api/authorize")
def authorize(req: AuthorizeIn):
    if req.phrase != "APPROVE":
        raise HTTPException(400, "Explicit approval phrase required")
    if not security.verify_token(req.path, req.patched, req.patch_token):
        audit("authorize_denied", path=req.path)
        raise HTTPException(403, "Patch was not validated by the server or was modified")
    approval_id = secrets.token_hex(6)
    audit("authorized", path=req.path, approval_id=approval_id,
          sha256=hashlib.sha256(req.patched.encode()).hexdigest())
    return {"approval_id": approval_id, "path": req.path}


@app.get("/api/audit")
def get_audit():
    return list(AUDIT)[-50:]


FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
