"""
Security helpers — manifest parsers + data fetchers.

Query priority (mirrors the original TypeScript exactly):
  1. Coral bridge  (CORAL_BRIDGE_URL)
  2. Legacy Coral  (CORAL_ENDPOINT)
  3. HTTP fallback (public APIs — used when Coral is not configured)
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

import httpx

from app.coral import run_coral_sql, sql_string
from app.models import Dependency, VulnItem


# ── helpers ───────────────────────────────────────────────────────────────────

def _extract_rows(payload: Any) -> List[Any]:
    if isinstance(payload, list):
        return payload
    if not payload or not isinstance(payload, dict):
        return []
    return (
        payload.get("items")
        or payload.get("rows")
        or payload.get("vulnerabilities")
        or []
    )


def _try_json(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return None


# ── GitHub file fetching ──────────────────────────────────────────────────────

async def fetch_github_file(
    owner: str, repo: str, path: str, client: httpx.AsyncClient
) -> Optional[str]:
    """Coral first, then raw.githubusercontent fallback."""
    rows = _extract_rows(
        await run_coral_sql(
            f"SELECT content_text FROM github.contents"
            f" WHERE owner = {sql_string(owner)}"
            f"   AND repo  = {sql_string(repo)}"
            f"   AND path  = {sql_string(path)}"
            f" LIMIT 1",
            label=f"github.contents — {owner}/{repo}/{path}",
            silent=True,
            client=client,
        )
    )
    if rows:
        first = rows[0]
        if isinstance(first, dict) and "content_text" in first:
            return str(first["content_text"] or "")

    # HTTP fallback
    try:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
        r = await client.get(url, timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


async def fetch_commit_sha(
    owner: str, repo: str, client: httpx.AsyncClient
) -> Optional[str]:
    """Coral first, then GitHub REST fallback."""
    try:
        rows = _extract_rows(
            await run_coral_sql(
                f"SELECT sha FROM github.repo_git_commits"
                f" WHERE owner = {sql_string(owner)}"
                f"   AND repo  = {sql_string(repo)}"
                f" LIMIT 1",
                label=f"github.commits — {owner}/{repo}",
                silent=True,
                client=client,
            )
        )
        if rows and isinstance(rows[0], dict) and rows[0].get("sha"):
            return str(rows[0]["sha"])
    except Exception:
        pass

    # HTTP fallback
    try:
        r = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=8,
        )
        if r.is_success:
            return r.json().get("sha")
    except Exception:
        pass
    return None


# ── Manifest parsers (pure Python — no network) ───────────────────────────────

def parse_package_json(content: str) -> List[Dependency]:
    try:
        data = json.loads(content)
        direct = set(data.get("dependencies", {}).keys())
        deps_map = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        result = [
            Dependency(
                name=name,
                version=re.sub(r"^[^0-9]*", "", str(ver)),
                ecosystem="npm",
                is_direct=name in direct,
            )
            for name, ver in deps_map.items()
        ]
        # Also scan the package itself (e.g. lodash scanned against lodash vulns)
        own_name = data.get("name", "").strip()
        own_ver  = re.sub(r"^[^0-9]*", "", str(data.get("version", "")).strip())
        if own_name and own_ver and own_name not in deps_map:
            result.insert(0, Dependency(name=own_name, version=own_ver, ecosystem="npm", is_direct=True))
        return result
    except Exception:
        return []


def parse_requirements_txt(content: str) -> List[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([^=<>!~\[\]\s]+)\s*(?:[=<>~!]+)?\s*([\d\.a-zA-Z\-]*)", line)
        deps.append(Dependency(name=m.group(1) if m else line, version=m.group(2) if m else "", ecosystem="pypi"))
    return deps


def parse_go_mod(content: str) -> List[Dependency]:
    deps, in_req = [], False
    module_self: Optional[Dependency] = None
    for line in content.splitlines():
        t = line.strip()
        if t.startswith("module ") and not module_self:
            # e.g. "module github.com/some/repo" — no version here, skip scanning self
            pass
        if t == "require (":
            in_req = True; continue
        if t == ")" and in_req:
            in_req = False; continue
        if t.startswith("require ") or in_req:
            m = re.match(r"^(?:require\s+)?(\S+)\s+v([\d\.\-a-zA-Z]+)", t)
            if m:
                deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem="golang", is_direct=True))
    return deps


def parse_go_sum(content: str) -> List[Dependency]:
    deps: List[Dependency] = []
    seen: Set[str] = set()
    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or "/go.mod" in parts[1]:
            continue
        module, ver = parts[0], parts[1].lstrip("v")
        key = f"{module}@{ver}"
        if key not in seen:
            seen.add(key)
            deps.append(Dependency(name=module, version=ver, ecosystem="golang", is_direct=False))
    return deps


def parse_cargo_lock(content: str) -> List[Dependency]:
    deps, cur = [], {}
    for line in content.splitlines():
        t = line.strip()
        if t == "[[package]]":
            if cur.get("name") and cur.get("version"):
                deps.append(Dependency(name=cur["name"], version=cur["version"], ecosystem="cargo", is_direct=False))
            cur = {}
        elif t.startswith("name = "):
            cur["name"] = t[7:].strip('"')
        elif t.startswith("version = "):
            cur["version"] = t[10:].strip('"')
    if cur.get("name") and cur.get("version"):
        deps.append(Dependency(name=cur["name"], version=cur["version"], ecosystem="cargo", is_direct=False))
    return deps


def parse_cargo_toml(content: str) -> Set[str]:
    direct: Set[str] = set()
    in_deps = False
    for line in content.splitlines():
        t = line.strip()
        if t in ("[dependencies]", "[dev-dependencies]"):
            in_deps = True; continue
        if t.startswith("[") and in_deps:
            in_deps = False; continue
        if in_deps:
            m = re.match(r"^([a-zA-Z0-9_\-]+)\s*=", t)
            if m:
                direct.add(m.group(1))
    return direct


def parse_pom_xml(content: str) -> List[Dependency]:
    deps = []
    try:
        root = ET.fromstring(content)
        ns = "http://maven.apache.org/POM/4.0.0"

        def txt(el: ET.Element, tag: str) -> str:
            c = el.find(f"{{{ns}}}{tag}") or el.find(tag)
            return (c.text or "").strip() if c is not None else ""

        for dep in root.iter(f"{{{ns}}}dependency"):
            gid, aid = txt(dep, "groupId"), txt(dep, "artifactId")
            ver, scope = txt(dep, "version"), txt(dep, "scope") or "compile"
            if gid and aid:
                deps.append(Dependency(
                    name=f"{gid}:{aid}",
                    version="" if ver.startswith("$") else ver,
                    ecosystem="maven",
                    is_direct=(scope != "test"),
                ))
    except Exception:
        pass
    return deps


# ── CVSS helpers ──────────────────────────────────────────────────────────────

def _cvss_score_to_label(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _cvss_vector_to_score(vector: str) -> Optional[float]:
    m = re.match(
        r"CVSS:3\.[01]/(AV:[NALP])/(AC:[LH])/(PR:[NLH])/(UI:[NR])/(S:[UC])/(C:[NLH])/(I:[NLH])/(A:[NLH])",
        vector,
    )
    if not m:
        return None
    av, ac, pr, ui, s, c, i, a = m.groups()
    cs = 0.56 if c == "C:H" else 0.22 if c == "C:L" else 0.0
    i_s = 0.56 if i == "I:H" else 0.22 if i == "I:L" else 0.0
    a_s = 0.56 if a == "A:H" else 0.22 if a == "A:L" else 0.0
    iss = 1 - (1 - cs) * (1 - i_s) * (1 - a_s)
    impact = 6.42 * iss if s == "S:U" else 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
    if impact <= 0:
        return 0.0
    av_w = {"AV:N": 0.85, "AV:A": 0.62, "AV:L": 0.55}.get(av, 0.2)
    ac_w = 0.77 if ac == "AC:L" else 0.44
    pr_w = 0.85 if pr == "PR:N" else (0.68 if s == "S:C" else 0.62) if pr == "PR:L" else (0.5 if s == "S:C" else 0.27)
    ui_w = 0.85 if ui == "UI:N" else 0.62
    exp = 8.22 * av_w * ac_w * pr_w * ui_w
    base = min((impact + exp) if s == "S:U" else 1.08 * (impact + exp), 10)
    return round(base * 10) / 10


def _normalize_severity_label(raw: str) -> Optional[str]:
    u = raw.upper().strip()
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM", "LOW": "LOW"}.get(u)


def _extract_severity(raw: Any) -> Optional[str]:
    if not raw:
        return None
    if isinstance(raw, str):
        lbl = _normalize_severity_label(raw)
        if lbl:
            return lbl
        sc = _cvss_vector_to_score(raw)
        return _cvss_score_to_label(sc) if sc is not None else None
    items = raw if isinstance(raw, list) else [raw]
    for item in items:
        if not item:
            continue
        score_str = str(item.get("score", ""))
        try:
            n = float(score_str)
            if n > 0:
                return _cvss_score_to_label(n)
        except ValueError:
            pass
        if score_str.startswith("CVSS:"):
            sc = _cvss_vector_to_score(score_str)
            if sc is not None:
                return _cvss_score_to_label(sc)
        t = item.get("type", "")
        if t:
            lbl = _normalize_severity_label(str(t))
            if lbl:
                return lbl
    return None


def _extract_fixed_version(affected: Any) -> Optional[str]:
    if not isinstance(affected, list):
        return None
    for a in affected:
        for rng in a.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return None


# ── OSV + KEV query — Coral cross-join, HTTP fallback ─────────────────────────

def _map_osv_row(v: dict) -> dict:
    """Map a raw Coral OSV×KEV row into our internal vuln dict (mirrors mapOsvRow in TS)."""
    severity_raw = _try_json(v["severity"]) if isinstance(v.get("severity"), str) else v.get("severity")
    refs_raw     = _try_json(v["references"]) if isinstance(v.get("references"), str) else v.get("references")
    affected_raw = _try_json(v["affected"])   if isinstance(v.get("affected"),   str) else v.get("affected")

    refs = [{"url": r.get("url", ""), "type": r.get("type")} for r in (refs_raw or [])]

    advisory_url = next(
        (r["url"] for r in refs if r.get("type") == "ADVISORY"), None
    ) or next((r["url"] for r in refs if "nvd.nist.gov" in r.get("url", "")), None) \
      or next((r["url"] for r in refs if "github.com/advisories" in r.get("url", "")), None) \
      or (refs[0]["url"] if refs else None)

    severity = _extract_severity(severity_raw)

    affected_versions: List[str] = []
    if isinstance(affected_raw, list):
        for a in affected_raw:
            affected_versions.extend(a.get("versions", []))

    aliases_raw = _try_json(v["aliases"]) if isinstance(v.get("aliases"), str) else v.get("aliases")
    cve_id: Optional[str] = None
    for alias in (aliases_raw or []):
        if re.match(r"CVE-\d{4}-\d{4,7}", str(alias), re.IGNORECASE):
            cve_id = str(alias).upper()
            break
    if not cve_id:
        vid = v.get("id", "")
        if re.match(r"CVE-\d{4}-\d{4,7}", vid, re.IGNORECASE):
            cve_id = vid.upper()
    # kev_cve_id from the LEFT JOIN
    kev_cve_id = v.get("kev_cve_id")
    if not cve_id and kev_cve_id:
        cve_id = str(kev_cve_id).upper()

    return {
        "id": v.get("id", "unknown"),
        "cve_id": cve_id,
        "summary": v.get("summary") or v.get("details"),
        "severity": severity,
        "fixed_in": _extract_fixed_version(affected_raw),
        "affected_versions": ", ".join(affected_versions[:20]) if affected_versions else None,
        "advisory_url": advisory_url,
        "references": refs,
        "kev": kev_cve_id is not None,          # direct from JOIN — no extra lookup needed
        "_kev_cve_id": kev_cve_id,
        "_kev_name": v.get("kev_name"),
        "_kev_date_added": v.get("kev_date_added"),
    }


async def query_osv(
    dep: Dependency, client: httpx.AsyncClient
) -> List[dict]:
    """
    OSV × CISA KEV cross-join via Coral.
    Falls back to OSV REST API when Coral is not available.
    """
    # ── Coral path ────────────────────────────────────────────────────────────
    coral_rows = _extract_rows(
        await run_coral_sql(
            f"""SELECT v.id, v.summary, v.details, v.severity, v.affected, v.references, v.aliases,
                       k.cve_id          AS kev_cve_id,
                       k.vulnerability_name AS kev_name,
                       k.date_added      AS kev_date_added,
                       k.required_action AS kev_required_action
              FROM osv.query_by_version v
              LEFT JOIN cisa_kev.vulnerabilities k
                ON v.aliases LIKE '%' || k.cve_id || '%'
             WHERE v.package_name = {sql_string(dep.name)}
               AND v.ecosystem    = {sql_string(dep.ecosystem)}
               AND v.version      = {sql_string(dep.version)}
             LIMIT 50""",
            label=f"OSV × KEV — {dep.name}@{dep.version} ({dep.ecosystem})",
            client=client,
        )
    )
    # Only skip HTTP fallback if Coral returned actual rows.
    # An empty list means "no vulns found by Coral" which could be a Coral gap — fall through.
    if coral_rows:
        return [_map_osv_row(r) for r in coral_rows if isinstance(r, dict)]

    # ── HTTP fallback ─────────────────────────────────────────────────────────
    try:
        r = await client.post(
            "https://api.osv.dev/v1/query",
            json={"version": dep.version, "package": {"name": dep.name, "ecosystem": dep.ecosystem}},
            timeout=15,
        )
        if not r.is_success:
            return []
        vulns = r.json().get("vulns", [])
    except Exception:
        return []

    result = []
    for v in vulns:
        refs = [{"url": ref.get("url", ""), "type": ref.get("type")} for ref in v.get("references", [])]
        advisory_url = next((ref["url"] for ref in refs if ref.get("type") == "ADVISORY"), None) \
                    or next((ref["url"] for ref in refs if "nvd.nist.gov" in ref.get("url", "")), None) \
                    or next((ref["url"] for ref in refs if "github.com/advisories" in ref.get("url", "")), None) \
                    or (refs[0]["url"] if refs else None)
        affected_versions: List[str] = []
        for aff in v.get("affected", []):
            affected_versions.extend(aff.get("versions", []))
        cve_id: Optional[str] = None
        for alias in v.get("aliases", []):
            if re.match(r"CVE-\d{4}-\d{4,7}", alias, re.IGNORECASE):
                cve_id = alias.upper(); break
        if not cve_id and re.match(r"CVE-\d{4}-\d{4,7}", v.get("id", ""), re.IGNORECASE):
            cve_id = v["id"].upper()
        result.append({
            "id": v.get("id", "unknown"),
            "cve_id": cve_id,
            "summary": v.get("summary") or v.get("details"),
            "severity": _extract_severity(v.get("severity")),
            "fixed_in": _extract_fixed_version(v.get("affected")),
            "affected_versions": ", ".join(affected_versions[:20]) if affected_versions else None,
            "advisory_url": advisory_url,
            "references": refs,
            "kev": False,   # resolved later via load_kev()
            "_kev_cve_id": None,
        })
    return result


# ── KEV set — Coral first, CISA HTTP fallback ─────────────────────────────────

_kev_cache: Optional[Set[str]] = None
_kev_lock = asyncio.Lock()


async def load_kev(client: httpx.AsyncClient) -> Set[str]:
    """
    Load the full CISA KEV CVE-ID set.
    Coral path: SELECT cve_id FROM cisa_kev.vulnerabilities
    Fallback:   CISA JSON feed
    """
    global _kev_cache
    async with _kev_lock:
        if _kev_cache is not None:
            return _kev_cache

        kev_set: Set[str] = set()

        # Coral path
        rows = _extract_rows(
            await run_coral_sql(
                "SELECT cve_id FROM cisa_kev.vulnerabilities",
                label="cisa_kev — load all CVE IDs",
                silent=True,
                client=client,
            )
        )
        if rows:
            for row in rows:
                cve = str(row.get("cve_id", "") if isinstance(row, dict) else row)
                if re.match(r"CVE-\d{4}-\d{4,7}", cve, re.IGNORECASE):
                    kev_set.add(cve.upper())
            _kev_cache = kev_set
            return kev_set

        # HTTP fallback
        try:
            r = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=15,
            )
            if r.is_success:
                for entry in r.json().get("vulnerabilities", []):
                    cve = entry.get("cveID", "")
                    if re.match(r"CVE-\d{4}-\d{4,7}", cve, re.IGNORECASE):
                        kev_set.add(cve.upper())
        except Exception:
            pass

        _kev_cache = kev_set
        return kev_set


# ── EPSS score — HTTP only (no Coral source) ──────────────────────────────────

_epss_cache: Dict[str, Optional[float]] = {}


async def fetch_epss_score(cve_id: str, client: httpx.AsyncClient) -> Optional[float]:
    if cve_id in _epss_cache:
        return _epss_cache[cve_id]
    try:
        r = await client.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=5
        )
        if r.is_success:
            items = r.json().get("data", [])
            score = float(items[0]["epss"]) if items else None
            _epss_cache[cve_id] = score
            return score
    except Exception:
        pass
    _epss_cache[cve_id] = None
    return None


# ── NVD severity — HTTP fallback only ────────────────────────────────────────

_nvd_cache: Dict[str, Optional[str]] = {}


async def fetch_nvd_severity(cve_id: str, client: httpx.AsyncClient) -> Optional[str]:
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]
    try:
        r = await client.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=5
        )
        if r.is_success:
            metrics = (
                r.json().get("vulnerabilities", [{}])[0]
                .get("cve", {}).get("metrics", {})
            )
            score = (
                (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {}).get("baseScore")
                or (metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {}).get("baseScore")
            )
            sev = _cvss_score_to_label(float(score)) if score is not None else None
            _nvd_cache[cve_id] = sev
            return sev
    except Exception:
        pass
    _nvd_cache[cve_id] = None
    return None
