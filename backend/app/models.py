from __future__ import annotations

from typing import Any
from pydantic import BaseModel


# ── Dependency / finding types ────────────────────────────────────────────────

class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str
    is_direct: bool = True


class VulnItem(BaseModel):
    id: str
    cve_id: str | None = None
    summary: str | None = None
    severity: str | None = None
    fixed_in: str | None = None
    affected_versions: str | None = None
    advisory_url: str | None = None
    epss_score: float | None = None
    is_direct: bool = True
    references: list[dict[str, Any]] = []
    kev: bool = False


# ── Scan store types ──────────────────────────────────────────────────────────

class PersistedFinding(BaseModel):
    package_name: str
    ecosystem: str
    vulnerability_id: str
    cve_id: str | None = None
    kev_status: bool = False
    severity: str = "unknown"
    summary: str = "No summary available"
    fix: str = "unknown"
    affected_versions: str | None = None
    advisory_url: str | None = None
    epss_score: float | None = None
    is_direct: bool = True


class ScanJob(BaseModel):
    id: str
    repository_url: str
    owner: str
    repo: str
    branch: str | None = None
    commit_sha: str | None = None
    status: str  # queued | scanning | completed | failed
    created_at: str


class RecentScan(BaseModel):
    id: str
    repository_url: str
    owner: str
    repo: str
    commit_sha: str | None = None
    status: str
    created_at: str
    findings_count: int
    vulnerable_dependencies: int
    kev_count: int


# ── API request / response bodies ────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str


class ChatRequest(BaseModel):
    repo: str
    question: str
    findings: dict[str, list[VulnItem]] = {}


class ChatResponse(BaseModel):
    answer: str


class ScansListResponse(BaseModel):
    scans: list[RecentScan]


class ScanDetailResponse(BaseModel):
    job: ScanJob
    findings: list[PersistedFinding]
