"""FastAPI application — replaces the Next.js API routes."""
from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from app import scan_store
from app.coral import clear_sql_log, get_sql_log
from app.gemini import generate_repo_agent_reply
from app.models import (
    ChatRequest,
    ChatResponse,
    ScanDetailResponse,
    ScanRequest,
    ScansListResponse,
)
from app.scanner import run_scan

app = FastAPI(title="KEVGuard API", version="1.0.0")

# Allow the React dev server (port 5173) and any other origin in dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── POST /api/scan  (SSE stream) ─────────────────────────────────────────────

@app.post("/api/scan")
async def post_scan(body: ScanRequest) -> EventSourceResponse:
    """Stream scan progress + final result as SSE events."""

    async def event_generator() -> AsyncGenerator[dict, None]:
        async for msg in run_scan(body.repo_url):
            yield {"event": msg["event"], "data": json.dumps(msg["data"])}

    return EventSourceResponse(
        event_generator(),
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",   # disable nginx/proxy buffering
        },
    )


# ── GET /api/scans ────────────────────────────────────────────────────────────

@app.get("/api/scans", response_model=ScansListResponse)
async def get_scans() -> ScansListResponse:
    return ScansListResponse(scans=scan_store.list_recent_scans())


# ── GET /api/scans/{id} ───────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str) -> ScanDetailResponse:
    scan = scan_store.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ── POST /api/chat ────────────────────────────────────────────────────────────

@app.post("/api/chat", response_model=ChatResponse)
async def post_chat(body: ChatRequest) -> ChatResponse:
    if not body.question or not body.repo:
        raise HTTPException(status_code=400, detail="Invalid chat request")
    answer = await generate_repo_agent_reply(
        repo=body.repo,
        question=body.question,
        findings=body.findings,
    )
    return ChatResponse(answer=answer)


# ── GET /api/sql-log ──────────────────────────────────────────────────────────

@app.get("/api/sql-log")
async def get_sql_log_endpoint() -> dict:
    return {"entries": get_sql_log()}


@app.delete("/api/sql-log")
async def clear_sql_log_endpoint() -> dict:
    clear_sql_log()
    return {"ok": True}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
