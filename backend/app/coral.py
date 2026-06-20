"""
Coral bridge client — Python port of src/lib/coral.ts

Tries CORAL_BRIDGE_URL first (new bridge), falls back to CORAL_ENDPOINT
(legacy). If neither is configured, run_coral_sql() returns None and the
callers fall back to plain HTTP APIs.

SQL log is process-global (same as the in-memory TS version).
"""
from __future__ import annotations

import time
import uuid
from collections import deque
from typing import Any, Deque, List, Optional

import httpx

from app.config import settings

# ── SQL log ───────────────────────────────────────────────────────────────────

MAX_LOG = 100

_sql_log: Deque[dict] = deque(maxlen=MAX_LOG)


def _make_id() -> str:
    return f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:5]}"


def _record_log(
    label: str,
    sql: str,
    source: str,
    row_count: Optional[int],
    duration_ms: int,
    error: Optional[str],
) -> None:
    _sql_log.appendleft(
        {
            "id": _make_id(),
            "label": label,
            "sql": sql,
            "source": source,
            "rowCount": row_count,
            "durationMs": duration_ms,
            "error": error,
            "timestamp": _iso_now(),
        }
    )


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def get_sql_log() -> List[dict]:
    return list(_sql_log)


def clear_sql_log() -> None:
    _sql_log.clear()


# ── Row normalisation (same as TS normalizeRows) ──────────────────────────────

def _normalize_rows(payload: Any) -> List[Any]:
    if not payload or not isinstance(payload, dict):
        if isinstance(payload, list):
            return payload
        return []
    rows = payload.get("items") or payload.get("rows") or payload.get("vulnerabilities")
    if isinstance(rows, list):
        return rows
    data = payload.get("data")
    if isinstance(data, list):
        return data
    return []


# ── SQL literal escaping ──────────────────────────────────────────────────────

def sql_string(value: str) -> str:
    """Wrap a value as a single-quoted SQL string literal, escaping inner quotes."""
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


# ── Bridge calls ──────────────────────────────────────────────────────────────

async def _post_coral_sql(
    sql: str, label: str, silent: bool, client: httpx.AsyncClient
) -> Optional[List[Any]]:
    bridge_url = settings.coral_bridge_url
    if not bridge_url:
        return None

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.coral_bridge_token:
        headers["x-coral-bridge-token"] = settings.coral_bridge_token

    t0 = int(time.time() * 1000)
    try:
        url = bridge_url.rstrip("/") + "/mcp/sql"
        res = await client.post(url, json={"sql": sql}, headers=headers, timeout=30)
        duration = int(time.time() * 1000) - t0

        if not res.is_success:
            if not silent:
                _record_log(label, sql, "coral", None, duration, f"HTTP {res.status_code}")
            return None

        rows = _normalize_rows(res.json())
        if not silent:
            _record_log(label, sql, "coral", len(rows) if isinstance(rows, list) else None, duration, None)
        return rows

    except Exception as exc:
        duration = int(time.time() * 1000) - t0
        if not silent:
            _record_log(label, sql, "coral", None, duration, str(exc))
        return None


async def _post_legacy_coral_sql(
    sql: str, label: str, silent: bool, client: httpx.AsyncClient
) -> Optional[List[Any]]:
    endpoint = settings.coral_endpoint
    if not endpoint:
        return None

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.coral_api_key:
        headers["Authorization"] = f"Bearer {settings.coral_api_key}"

    t0 = int(time.time() * 1000)
    try:
        res = await client.post(endpoint, json={"sql": sql}, headers=headers, timeout=30)
        duration = int(time.time() * 1000) - t0

        if not res.is_success:
            if not silent:
                _record_log(label, sql, "legacy", None, duration, f"HTTP {res.status_code}")
            return None

        rows = _normalize_rows(res.json())
        if not silent:
            _record_log(label, sql, "legacy", len(rows) if isinstance(rows, list) else None, duration, None)
        return rows

    except Exception as exc:
        duration = int(time.time() * 1000) - t0
        if not silent:
            _record_log(label, sql, "legacy", None, duration, str(exc))
        return None


async def run_coral_sql(
    sql: str,
    label: str = "query",
    silent: bool = False,
    client: Optional[httpx.AsyncClient] = None,
) -> Optional[List[Any]]:
    """
    Try coral bridge first, fall back to legacy endpoint.
    Returns a list of row dicts, or None if Coral is not configured / failed.
    Callers must fall back to HTTP APIs when None is returned.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(follow_redirects=True)

    try:
        result = await _post_coral_sql(sql, label, silent, client)
        if result is None:
            result = await _post_legacy_coral_sql(sql, label, silent, client)
        return result
    finally:
        if own_client:
            await client.aclose()


# ── Coral assistant context (injected into Gemini prompts) ────────────────────

def get_coral_assistant_context() -> str:
    return """
## Coral Data Sources (verified against live bridge)

### GitHub
- `github.contents` — required filters: owner, repo, path
  - SELECT content_text FROM github.contents WHERE owner = 'OWNER' AND repo = 'REPO' AND path = 'package.json' LIMIT 1

### OSV
- `osv.query_by_version` — required filters: package_name, ecosystem, version
  - Columns: id, summary, details, published, modified, aliases (JSON string), references (JSON string), severity (JSON string), affected (JSON string), database_specific (JSON string), raw (JSON string)
  - severity format: [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/..."}] — parse JSON, then compute score from CVSS vector
  - aliases format: ["CVE-2020-11023","BIT-..."] — used to join with cisa_kev

### CISA KEV
- `cisa_kev.vulnerabilities` — flat table
  - Columns: cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, cwes

### Cross-source JOIN (OSV + KEV in one query)
  SELECT v.id, v.summary, v.severity, v.affected, v.references, v.aliases,
         k.cve_id          AS kev_cve_id,
         k.vulnerability_name AS kev_name,
         k.date_added      AS kev_date_added,
         k.required_action AS kev_required_action
  FROM osv.query_by_version v
  LEFT JOIN cisa_kev.vulnerabilities k
    ON v.aliases LIKE '%' || k.cve_id || '%'
  WHERE v.package_name = 'jquery'
    AND v.ecosystem    = 'npm'
    AND v.version      = '3.4.1'
  LIMIT 50

- kev_cve_id IS NOT NULL → actively exploited (CISA KEV)

## Rules
- Prefer the cross-join query — it gives KEV status in one round trip.
- Do not use osv.vulnerabilities, osv.affected, osv.severity, osv.references — those tables do not exist.
- json_each() is not available — use LIKE for JSON string matching.
""".strip()
