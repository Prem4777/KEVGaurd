"""
Core scan orchestration — mirrors runScanChain in langchain.ts exactly.

KEV status priority:
  1. _kev_from_join = True  → set by Coral OSV×KEV cross-join (most accurate)
  2. kev_set lookup          → loaded via load_kev() (Coral or HTTP fallback)
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncGenerator
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from app import scan_store
from app.gemini import generate_security_summary
from app.models import Dependency, PersistedFinding, VulnItem
from app.security import (
    fetch_commit_sha,
    fetch_epss_score,
    fetch_github_file,
    fetch_nvd_severity,
    load_kev,
    parse_cargo_lock,
    parse_cargo_toml,
    parse_go_mod,
    parse_go_sum,
    parse_package_json,
    parse_pom_xml,
    parse_requirements_txt,
    query_osv,
)

CONCURRENCY = 8
MANIFESTS = ["package.json", "requirements.txt", "go.mod", "go.sum", "Cargo.lock", "Cargo.toml", "pom.xml"]


def _parse_repo(url: str) -> Optional[tuple[str, str]]:
    try:
        parts = [p for p in urlparse(url).path.split("/") if p]
        if len(parts) >= 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return None


async def run_scan(repo_url: str) -> AsyncGenerator[dict[str, Any], None]:
    parsed = _parse_repo(repo_url)
    if not parsed:
        yield {"event": "error", "data": {"message": "Invalid repository URL"}}
        return

    owner, repo = parsed

    async with httpx.AsyncClient(follow_redirects=True) as client:

        # ── SHA-based cache check ─────────────────────────────────────────
        yield {"event": "progress", "data": {"type": "started", "message": f"Resolving commit SHA for {owner}/{repo}"}}
        commit_sha = await fetch_commit_sha(owner, repo, client)

        if commit_sha:
            cached = scan_store.find_scan_by_commit_sha(commit_sha)
            if cached:
                yield {"event": "progress", "data": {"type": "cache_hit", "message": "Returning cached scan for this commit"}}
                findings_map: dict[str, list[dict]] = {}
                for f in cached.findings:
                    key = f"{f.package_name}@{f.ecosystem}"
                    findings_map.setdefault(key, []).append({
                        "id": f.vulnerability_id, "cve_id": f.cve_id,
                        "summary": f.summary, "severity": f.severity,
                        "fixed_in": f.fix, "affected_versions": f.affected_versions,
                        "advisory_url": f.advisory_url, "epss_score": f.epss_score,
                        "is_direct": f.is_direct, "references": [], "kev": f.kev_status,
                    })
                yield {"event": "result", "data": {
                    "scanId": cached.job.id, "repo": f"{owner}/{repo}",
                    "findings": findings_map, "summary": None, "cachedSha": commit_sha,
                }}
                return

        job = scan_store.create_scan_job(
            repository_url=repo_url, owner=owner, repo=repo, commit_sha=commit_sha
        )

        try:
            yield {"event": "progress", "data": {"type": "started", "message": f"Scan started for {owner}/{repo}"}}

            # ── Fetch manifests in parallel ───────────────────────────────
            fetch_results = await asyncio.gather(
                *[fetch_github_file(owner, repo, path, client) for path in MANIFESTS],
                return_exceptions=True,
            )
            fetched: dict[str, Optional[str]] = {}
            for path, res in zip(MANIFESTS, fetch_results):
                fetched[path] = res if isinstance(res, str) else None
                yield {"event": "progress", "data": {
                    "type": "fetched",
                    "message": f"Fetched {path}" if fetched[path] else f"Missing {path}",
                    "meta": {"path": path},
                }}

            # ── Parse dependencies ────────────────────────────────────────
            deps: list[Dependency] = []

            if fetched["package.json"]:
                deps.extend(parse_package_json(fetched["package.json"]))
                yield {"event": "progress", "data": {"type": "parsed", "message": "Parsed package.json (npm)"}}
            if fetched["requirements.txt"]:
                deps.extend(parse_requirements_txt(fetched["requirements.txt"]))
                yield {"event": "progress", "data": {"type": "parsed", "message": "Parsed requirements.txt (PyPI)"}}
            if fetched["go.mod"]:
                go_mod_deps = parse_go_mod(fetched["go.mod"])
                direct_names = {d.name for d in go_mod_deps if d.is_direct}
                if fetched["go.sum"]:
                    go_sum_deps = parse_go_sum(fetched["go.sum"])
                    for d in go_sum_deps:
                        d.is_direct = d.name in direct_names
                    deps.extend(go_sum_deps)
                else:
                    deps.extend(go_mod_deps)
                yield {"event": "progress", "data": {"type": "parsed", "message": "Parsed go.mod / go.sum (Go)"}}
            if fetched["Cargo.lock"]:
                cargo_deps = parse_cargo_lock(fetched["Cargo.lock"])
                direct_cargo = parse_cargo_toml(fetched["Cargo.toml"]) if fetched["Cargo.toml"] else set()
                for d in cargo_deps:
                    d.is_direct = d.name in direct_cargo
                deps.extend(cargo_deps)
                yield {"event": "progress", "data": {"type": "parsed", "message": "Parsed Cargo.lock (Rust)"}}
            if fetched["pom.xml"]:
                deps.extend(parse_pom_xml(fetched["pom.xml"]))
                yield {"event": "progress", "data": {"type": "parsed", "message": "Parsed pom.xml (Maven)"}}

            # Deduplicate, cap at 100
            unique: dict[str, Dependency] = {}
            for d in deps[:100]:
                k = f"{d.name}@{d.version}@{d.ecosystem}"
                if k not in unique:
                    unique[k] = d
            dep_list = list(unique.values())

            # ── Load KEV set (used as fallback when Coral join not available) ──
            kev_set = await load_kev(client)

            # ── Query OSV per dependency ──────────────────────────────────
            results: dict[str, list[dict]] = {}
            findings_to_persist: list[PersistedFinding] = []

            async def process_one(dep: Dependency, index: int) -> tuple[str, list[dict]]:
                key = f"{dep.name}@{dep.version}@{dep.ecosystem}"
                try:
                    raw_vulns = await query_osv(dep, client)
                except Exception:
                    return key, []

                mapped: list[dict] = []
                for v in raw_vulns:
                    # ── KEV status ──────────────────────────────────────────
                    # Priority 1: came directly from the Coral OSV×KEV JOIN
                    kev_status: bool = bool(v.get("_kev_cve_id"))

                    # Priority 2: fall back to the separately loaded KEV set
                    if not kev_status:
                        cve = v.get("cve_id", "")
                        if cve and cve.upper() in kev_set:
                            kev_status = True
                    if not kev_status:
                        for ref in v.get("references", []):
                            m = re.search(r"CVE-\d{4}-\d{4,7}", ref.get("url", ""), re.IGNORECASE)
                            if m and m.group(0).upper() in kev_set:
                                kev_status = True
                                break
                    if not kev_status and v.get("id"):
                        m2 = re.match(r"CVE-\d{4}-\d{4,7}", v["id"], re.IGNORECASE)
                        if m2 and m2.group(0).upper() in kev_set:
                            kev_status = True

                    # ── CVE ID ──────────────────────────────────────────────
                    cve_id: Optional[str] = (
                        v.get("cve_id")
                        or (v.get("_kev_cve_id") and str(v["_kev_cve_id"]).upper())
                        or None
                    )

                    # ── Severity — NVD HTTP fallback if unknown ─────────────
                    severity = v.get("severity")
                    if (not severity or severity == "unknown") and cve_id:
                        nvd_sev = await fetch_nvd_severity(cve_id, client)
                        if nvd_sev:
                            severity = nvd_sev

                    # ── EPSS score ──────────────────────────────────────────
                    epss_score: Optional[float] = None
                    if cve_id:
                        epss_score = await fetch_epss_score(cve_id, client)

                    findings_to_persist.append(PersistedFinding(
                        package_name=dep.name, ecosystem=dep.ecosystem,
                        vulnerability_id=v["id"], cve_id=cve_id,
                        kev_status=kev_status, severity=str(severity or "unknown"),
                        summary=str(v.get("summary") or "No summary available"),
                        fix=str(v.get("fixed_in") or "unknown"),
                        affected_versions=v.get("affected_versions"),
                        advisory_url=v.get("advisory_url"),
                        epss_score=epss_score, is_direct=dep.is_direct,
                    ))
                    mapped.append({
                        "id": v["id"], "cve_id": cve_id,
                        "summary": v.get("summary"), "severity": severity,
                        "fixed_in": v.get("fixed_in"), "affected_versions": v.get("affected_versions"),
                        "advisory_url": v.get("advisory_url"), "epss_score": epss_score,
                        "is_direct": dep.is_direct, "references": v.get("references", []),
                        "kev": kev_status,
                    })
                return key, mapped

            for i in range(0, len(dep_list), CONCURRENCY):
                batch = dep_list[i:i + CONCURRENCY]
                batch_results = await asyncio.gather(
                    *[process_one(d, i + j + 1) for j, d in enumerate(batch)],
                    return_exceptions=True,
                )
                for r in batch_results:
                    if isinstance(r, tuple):
                        k, mapped = r
                        results[k] = mapped
                yield {"event": "progress", "data": {
                    "type": "processing",
                    "message": f"Checked {min(i + CONCURRENCY, len(dep_list))}/{len(dep_list)} packages",
                }}

            # ── Persist ───────────────────────────────────────────────────
            yield {"event": "progress", "data": {"type": "persisting", "message": "Saving findings"}}
            scan_store.save_scan_findings(job.id, findings_to_persist)
            scan_store.complete_scan_job(job.id)

            # ── AI summary ────────────────────────────────────────────────
            yield {"event": "progress", "data": {"type": "summarizing", "message": "Generating AI summary"}}
            vuln_map: dict[str, list[VulnItem]] = {
                k: [VulnItem(**{fk: fv for fk, fv in item.items() if not fk.startswith("_")})
                    for item in v]
                for k, v in results.items()
            }
            summary = await generate_security_summary(f"{owner}/{repo}", vuln_map)

            yield {"event": "progress", "data": {"type": "done", "message": "Scan completed"}}
            yield {"event": "result", "data": {
                "scanId": job.id, "repo": f"{owner}/{repo}",
                "findings": results, "summary": summary, "cachedSha": None,
            }}

        except Exception as exc:
            scan_store.fail_scan_job(job.id)
            yield {"event": "error", "data": {"message": str(exc)}}
