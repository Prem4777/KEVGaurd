"""Gemini AI integration — security summary + repo chat agent."""
from __future__ import annotations

import httpx

from app.config import settings
from app.coral import get_coral_assistant_context
from app.models import VulnItem


def _severity_score(v: VulnItem) -> int:
    sev = (v.severity or "").upper()
    base = (
        4 if "CRITICAL" in sev
        else 3 if "HIGH" in sev
        else 2 if "MEDIUM" in sev or "MODERATE" in sev
        else 1 if "LOW" in sev
        else 0
    )
    return base + (2 if v.kev else 0)


def _top_findings(findings: dict[str, list[VulnItem]], n: int = 6) -> list[tuple[str, VulnItem]]:
    flat = [
        (dep, vuln)
        for dep, vulns in findings.items()
        for vuln in vulns
    ]
    flat.sort(key=lambda x: _severity_score(x[1]), reverse=True)
    return flat[:n]


def _fallback_answer(question: str, findings: dict[str, list[VulnItem]]) -> str:
    q = question.lower()
    top = _top_findings(findings, 1)
    if "fix first" in q or "priority" in q:
        return (
            f"Start with {top[0][0]} — it is the highest risk item in the current scan."
            if top else "No vulnerabilities found. Keep dependencies pinned and rescan after changes."
        )
    if "dangerous" in q:
        return (
            f"{top[0][0]} is the most dangerous dependency in the report."
            if top else "No dangerous dependency identified from the current scan data."
        )
    if "summarize" in q or "risk" in q:
        items = _top_findings(findings)
        return (
            f"The scan found {len(items)} high-priority issues. Focus on KEV and critical items first."
            if items else "The repository looks clean from the current scan data."
        )
    return "Ask for priority, dangerous dependencies, or a short repo risk summary."


async def _call_gemini(prompt: str) -> str | None:
    if not settings.gemini_api_key:
        return None
    model = settings.gemini_model
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={settings.gemini_api_key}"
    )
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(
                url,
                json={"contents": [{"role": "user", "parts": [{"text": prompt}]}]},
                timeout=20,
            )
            if not r.is_success:
                return None
            data = r.json()
            parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
            return "\n".join(p.get("text", "") for p in parts).strip() or None
        except Exception:
            return None


async def generate_security_summary(
    repo: str,
    findings: dict[str, list[VulnItem]],
) -> str | None:
    if not settings.gemini_api_key:
        return None
    top = _top_findings(findings, 5)
    lines = [
        "You are a security engineer. Summarize the repo risk in short, actionable language.",
        get_coral_assistant_context(),
        f"Repository: {repo}",
        "Findings:",
    ]
    for dep, v in top:
        lines.append(
            f"- {dep}: {v.id} | severity={v.severity or 'n/a'} | kev={'yes' if v.kev else 'no'} | fix={v.fixed_in or 'unknown'} | {v.summary or ''}"
        )
    lines.append(
        "Return plain text only. Start with one sentence risk summary, then list the top fixes in priority order."
    )
    return await _call_gemini("\n".join(lines))


async def generate_repo_agent_reply(
    repo: str,
    question: str,
    findings: dict[str, list[VulnItem]],
) -> str:
    if not settings.gemini_api_key:
        return _fallback_answer(question, findings)
    top = _top_findings(findings, 6)
    lines = [
        "You are an expert security remediation agent.",
        "Answer the user's question with direct, practical guidance.",
        "Keep the response short, specific, and action oriented.",
        get_coral_assistant_context(),
        f"Repository: {repo}",
        f"Question: {question}",
        "Top findings:",
    ]
    for dep, v in top:
        lines.append(
            f"- {dep}: {v.cve_id or v.id} | severity={v.severity or 'unknown'} | kev={'yes' if v.kev else 'no'} | fix={v.fixed_in or 'unknown'} | {v.summary or ''}"
        )
    lines.append("Return plain text only. Prefer a concise answer with a short follow-up recommendation.")
    result = await _call_gemini("\n".join(lines))
    return result or _fallback_answer(question, findings)
