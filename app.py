"""
Public HTTPS endpoint for the Harness Engineering assignment.

Run locally:
    uvicorn app:app --host 0.0.0.0 --port 8000

Deploy (pick one — all have a free tier and give you a public HTTPS URL):
    Render.com      -> "Web Service" from this folder, start command:
                        uvicorn app:app --host 0.0.0.0 --port $PORT
    Railway.app     -> same start command, auto-detects PORT
    Fly.io          -> fly launch (uses the Dockerfile included here)

POST route to give the grader: https://<your-app>/classify
"""

import time
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from llm_classifier import classify_batch_async

app = FastAPI()


@app.get("/")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/classify")
async def classify(request: Request):
    start = time.time()
    try:
        body: Dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})

    profile = body.get("profile", "agent-harness-2026-09")
    batch_id = body.get("batchId")
    cases: List[Dict[str, Any]] = body.get("cases") or []

    seen_ids = set()
    valid_cases = []
    for case in cases:
        case_id = case.get("caseId")
        if case_id is None or case_id in seen_ids:
            continue
        seen_ids.add(case_id)
        valid_cases.append(case)

    decisions = await classify_batch_async(valid_cases)
    results = [
        {"caseId": case.get("caseId"), **decision}
        for case, decision in zip(valid_cases, decisions)
    ]

    response = {
        "profile": profile,
        "batchId": batch_id,
        "results": results,
    }
    return JSONResponse(content=response, media_type="application/json")
