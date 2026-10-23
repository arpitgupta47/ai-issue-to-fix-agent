import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import engine, llm, security

app = FastAPI(title="AI Issue-to-Fix Agent")
AUDIT_DB = Path(os.environ.get(
    "AUDIT_DB_PATH", str(Path(__file__).resolve().parents[1] / "audit.sqlite3")
))


@contextmanager
def connect_db():
    connection = sqlite3.connect(AUDIT_DB, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_db():
    AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                original_sha256 TEXT NOT NULL,
                patched_sha256 TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                ts REAL NOT NULL,
                event TEXT NOT NULL,
                data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS test_results (
                run_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                test_index INTEGER NOT NULL,
                name TEXT NOT NULL,
                passed INTEGER NOT NULL,
                error TEXT,
                created_at REAL NOT NULL,
                PRIMARY KEY (run_id, phase, test_index)
            );
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                path TEXT NOT NULL,
                decision TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)


initialize_db()


def audit(event: str, run_id: Optional[str] = None, **data):
    with connect_db() as db:
        db.execute(
            "INSERT INTO audit_events(run_id, ts, event, data_json) VALUES (?, ?, ?, ?)",
            (run_id, time.time(), event, json.dumps(data, ensure_ascii=True)),
        )


def set_run(run_id: str, status: str, patched: Optional[str] = None):
    with connect_db() as db:
        db.execute(
            "UPDATE runs SET status = ?, patched_sha256 = COALESCE(?, patched_sha256) "
            "WHERE run_id = ?",
            (status, hashlib.sha256(patched.encode()).hexdigest() if patched else None,
             run_id),
        )


class AnalyzeIn(BaseModel):
    title: str = Field("", max_length=300)
    body: str = Field("", max_length=5000)
    path: str = Field(..., max_length=300)
    code: str = Field(..., max_length=100_000)


class TestResult(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    passed: bool
    error: str = Field("", max_length=2000)


class TestResultsIn(BaseModel):
    path: str = Field(..., max_length=300)
    original: str = Field(..., max_length=100_000)
    patched: str = Field(..., max_length=100_000)
    patch_token: str
    before: list[TestResult] = Field(..., max_length=100)
    after: list[TestResult] = Field(..., max_length=100)


class AuthorizeIn(BaseModel):
    run_id: str
    path: str = Field(..., max_length=300)
    original: str = Field(..., max_length=100_000)
    patched: str = Field(..., max_length=100_000)
    patch_token: str
    phrase: str


class RejectIn(BaseModel):
    run_id: str


def require_run(run_id: str):
    with connect_db() as db:
        row = db.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Run not found")
    return row


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/api/analyze")
def analyze(req: AnalyzeIn):
    if not engine.validate_path(req.path):
        raise HTTPException(422, "File path is protected or invalid")
    run_id = secrets.token_urlsafe(18)
    with connect_db() as db:
        db.execute(
            "INSERT INTO runs(run_id, created_at, path, status, original_sha256) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, time.time(), req.path,
             "analyzing", hashlib.sha256(req.code.encode()).hexdigest()),
        )
    try:
        result = engine.analyze(req.title, req.body, req.path, req.code, llm)
    except RuntimeError as exc:
        set_run(run_id, "failed")
        audit("analysis_failed", run_id, reason=str(exc))
        raise HTTPException(502, str(exc)) from exc
    result["run_id"] = run_id
    result["patch_token"] = (
        security.patch_token(req.path, req.code, result["patched"]) if result["ok"] else None
    )
    set_run(run_id, "proposed" if result["ok"] else "no_patch", result["patched"])
    audit(
        "analysis_completed", run_id, path=req.path, ok=result["ok"],
        provider=result["provider"], findings=len(result["findings"]),
        injection_hits=result["screen_hits"],
    )
    return result


@app.post("/api/runs/{run_id}/tests")
def record_tests(run_id: str, req: TestResultsIn):
    run = require_run(run_id)
    if run["status"] != "proposed" or req.path != run["path"]:
        raise HTTPException(409, "Run is not awaiting test results")
    if hashlib.sha256(req.original.encode()).hexdigest() != run["original_sha256"]:
        raise HTTPException(403, "Original file does not match the analyzed run")
    if not security.verify_token(req.path, req.original, req.patched, req.patch_token):
        raise HTTPException(403, "Patch changed after server validation")
    if not engine.validate_patch(req.path, req.original, req.patched)["ok"]:
        raise HTTPException(422, "Patch failed validation")
    with connect_db() as db:
        for phase, tests in (("before", req.before), ("after", req.after)):
            for index, test in enumerate(tests):
                db.execute(
                    "INSERT INTO test_results "
                    "(run_id, phase, test_index, name, passed, error, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (run_id, phase, index, test.name, int(test.passed),
                     test.error, time.time()),
                )
    set_run(run_id, "tested")
    audit(
        "tests_completed", run_id, before_passed=sum(test.passed for test in req.before),
        before_total=len(req.before), after_passed=sum(test.passed for test in req.after),
        after_total=len(req.after),
    )
    return {"run_id": run_id, "status": "tested"}


@app.post("/api/authorize")
def authorize(req: AuthorizeIn):
    if req.phrase != "APPROVE":
        raise HTTPException(400, "Explicit approval phrase required")
    run = require_run(req.run_id)
    if run["status"] != "tested":
        raise HTTPException(409, "Record sandbox test results before approval")
    if req.path != run["path"] or hashlib.sha256(
        req.original.encode()
    ).hexdigest() != run["original_sha256"]:
        raise HTTPException(403, "Approval does not match the analyzed file")
    if not security.verify_token(req.path, req.original, req.patched, req.patch_token):
        audit("approval_denied", req.run_id, path=req.path, reason="patch changed")
        raise HTTPException(403, "Patch changed after server validation")
    validation = engine.validate_patch(req.path, req.original, req.patched)
    if not validation["ok"]:
        audit("approval_denied", req.run_id, path=req.path, reason="validation failed")
        raise HTTPException(403, "Patch failed server validation")
    approval_id = secrets.token_hex(8)
    digest = hashlib.sha256(req.patched.encode()).hexdigest()
    with connect_db() as db:
        db.execute(
            "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?)",
            (approval_id, req.run_id, req.path, "approved", digest, time.time()),
        )
    set_run(req.run_id, "approved")
    audit("approved", req.run_id, path=req.path, approval_id=approval_id, sha256=digest)
    return {"approval_id": approval_id, "run_id": req.run_id, "path": req.path}


@app.post("/api/reject")
def reject(req: RejectIn):
    run = require_run(req.run_id)
    if run["status"] not in {"proposed", "tested"}:
        raise HTTPException(409, "Run is not awaiting a review decision")
    approval_id = secrets.token_hex(8)
    with connect_db() as db:
        db.execute(
            "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?)",
            (approval_id, req.run_id, run["path"], "rejected",
             run["patched_sha256"] or "", time.time()),
        )
    set_run(req.run_id, "rejected")
    audit("rejected", req.run_id, path=run["path"], approval_id=approval_id)
    return {"approval_id": approval_id, "run_id": req.run_id, "status": "rejected"}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    run = require_run(run_id)
    with connect_db() as db:
        tests = db.execute(
            "SELECT phase, test_index, name, passed, error, created_at "
            "FROM test_results WHERE run_id = ? ORDER BY phase, test_index",
            (run_id,),
        ).fetchall()
        approval = db.execute(
            "SELECT approval_id, decision, sha256, created_at FROM approvals "
            "WHERE run_id = ? ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        ).fetchone()
    return {
        "run_id": run["run_id"], "created_at": run["created_at"],
        "path": run["path"], "status": run["status"],
        "original_sha256": run["original_sha256"],
        "patched_sha256": run["patched_sha256"],
        "test_results": [dict(row) for row in tests],
        "approval": dict(approval) if approval else None,
    }


@app.get("/api/audit")
def get_audit():
    with connect_db() as db:
        rows = db.execute(
            "SELECT id, run_id, ts, event, data_json FROM audit_events "
            "ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return [
        {
            "id": row["id"], "run_id": row["run_id"], "ts": row["ts"],
            "event": row["event"], "data": json.loads(row["data_json"]),
        }
        for row in reversed(rows)
    ]


FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
