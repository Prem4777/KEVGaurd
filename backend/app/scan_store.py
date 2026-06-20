"""In-memory scan store — identical logic to the original TypeScript scan-store.ts."""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.models import PersistedFinding, RecentScan, ScanDetailResponse, ScanJob

# ── Storage ───────────────────────────────────────────────────────────────────

_jobs: Dict[str, ScanJob] = {}
_findings_by_job: Dict[str, List[PersistedFinding]] = {}
_sha_index: Dict[str, str] = {}  # commitSha → scanJobId


def _make_id() -> str:
    return str(_uuid.uuid4())


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_scan_job(
    repository_url: str,
    owner: str,
    repo: str,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
) -> ScanJob:
    job = ScanJob(
        id=_make_id(),
        repository_url=repository_url,
        owner=owner,
        repo=repo,
        branch=branch,
        commit_sha=commit_sha,
        status="scanning",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _jobs[job.id] = job
    _findings_by_job[job.id] = []
    return job


def complete_scan_job(scan_job_id: str) -> None:
    job = _jobs.get(scan_job_id)
    if job:
        job.status = "completed"
        if job.commit_sha:
            _sha_index[job.commit_sha] = job.id


def fail_scan_job(scan_job_id: str) -> None:
    job = _jobs.get(scan_job_id)
    if job:
        job.status = "failed"


def save_scan_findings(scan_job_id: str, findings: List[PersistedFinding]) -> None:
    if not findings:
        return
    existing = _findings_by_job.get(scan_job_id, [])
    _findings_by_job[scan_job_id] = existing + findings


def list_recent_scans(limit: int = 10) -> List[RecentScan]:
    sorted_jobs = sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)
    result: List[RecentScan] = []
    for job in sorted_jobs[:limit]:
        job_findings = _findings_by_job.get(job.id, [])
        vulnerable_deps = len({f.package_name for f in job_findings})
        kev_count = sum(1 for f in job_findings if f.kev_status)
        result.append(
            RecentScan(
                id=job.id,
                repository_url=job.repository_url,
                owner=job.owner,
                repo=job.repo,
                commit_sha=job.commit_sha,
                status=job.status,
                created_at=job.created_at,
                findings_count=len(job_findings),
                vulnerable_dependencies=vulnerable_deps,
                kev_count=kev_count,
            )
        )
    return result


def get_scan_by_id(scan_id: str) -> Optional[ScanDetailResponse]:
    job = _jobs.get(scan_id)
    if not job:
        return None
    findings = _findings_by_job.get(scan_id, [])
    return ScanDetailResponse(job=job, findings=findings)


def find_scan_by_commit_sha(commit_sha: str) -> Optional[ScanDetailResponse]:
    job_id = _sha_index.get(commit_sha)
    if not job_id:
        return None
    return get_scan_by_id(job_id)
