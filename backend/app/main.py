from __future__ import annotations
import json, logging, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .analyzer.engine import analyze_policy
from .analyzer.parser import PolicyValidationError
from .analyzer.rules import RULES
from . import database

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("cloudsentinel")
app = FastAPI(title="CloudSentinel API", version="1.0.0", description="Local-only, deterministic AWS IAM policy analysis.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])
SAMPLES = Path(__file__).resolve().parents[2] / "sample_policies"

class AnalyzeRequest(BaseModel):
    policy: dict[str, Any] | str
    policy_name: str | None = Field(None, max_length=120)

@app.get("/api/health")
def health(): return {"status": "ok", "service": "CloudSentinel"}

@app.post("/api/analyze", status_code=201)
def analyze(request: AnalyzeRequest):
    raw = request.policy if isinstance(request.policy, str) else json.dumps(request.policy)
    if len(raw.encode()) > 256_000: raise HTTPException(413, "Policy exceeds the 256 KB analysis limit.")
    try: report = analyze_policy(request.policy)
    except PolicyValidationError as exc: raise HTTPException(422, str(exc)) from exc
    scan_id, timestamp = str(uuid.uuid4()), datetime.now(timezone.utc).isoformat()
    stored = database.save_scan(report, scan_id, timestamp, request.policy_name)
    logger.info("saved scan %s score=%s", scan_id, report["risk_score"])
    return stored | {"scan_id": scan_id, "timestamp": timestamp}

@app.get("/api/scans")
def scans(): return database.list_scans()
@app.get("/api/scans/{scan_id}")
def scan(scan_id: str):
    result = database.get_scan(scan_id)
    if not result: raise HTTPException(404, "Scan not found.")
    return result
@app.delete("/api/scans/{scan_id}", status_code=204)
def delete(scan_id: str):
    if not database.delete_scan(scan_id): raise HTTPException(404, "Scan not found.")
@app.delete("/api/scans")
def clear_history(): database.clear_scans(); return {"message": "History cleared."}
@app.get("/api/samples")
def samples(): return [{"name": path.stem, "label": path.stem.replace("_", " ").title()} for path in SAMPLES.glob("*.json")]
@app.get("/api/samples/{name}")
def sample(name: str):
    path = (SAMPLES / f"{name}.json").resolve()
    if path.parent != SAMPLES.resolve() or not path.exists(): raise HTTPException(404, "Sample not found.")
    return {"name": name, "policy": json.loads(path.read_text(encoding="utf-8"))}
@app.get("/api/rules")
def rules(): return [{"rule_id": r[0], "title": r[1], "default_severity": r[2]} for r in RULES]
