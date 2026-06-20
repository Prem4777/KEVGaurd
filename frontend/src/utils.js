// ── Metrics ───────────────────────────────────────────────────────────────────

export function computeMetrics(findings) {
  const deps = Object.keys(findings)
  let total = 0, kev = 0
  const rb = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }

  for (const vulns of Object.values(findings)) {
    for (const v of vulns) {
      total++
      if (v.kev) kev++
      const sev = (v.severity || '').toLowerCase()
      if (sev.includes('critical'))      rb.critical++
      else if (sev.includes('high'))     rb.high++
      else if (sev.includes('medium') || sev.includes('moderate')) rb.medium++
      else if (sev.includes('low'))      rb.low++
      else                               rb.unknown++
    }
  }

  const raw =
    10 * Math.log2(rb.critical * 2 + 1) +
    6  * Math.log2(rb.high     * 2 + 1) +
    3  * Math.log2(rb.medium   * 2 + 1) +
    1  * Math.log2(rb.low      * 2 + 1) +
    2  * Math.log2(rb.unknown  * 2 + 1)

  const kevPenalty = 5 * Math.log2(kev * 3 + 1)
  const securityScore = Math.round(100 * Math.exp(-(raw + kevPenalty) / 55))

  return { securityScore, totalVulnerabilities: total, activelyExploited: kev, dependencyCount: deps.length, riskBreakdown: rb }
}

export function initialChatAnswer(findings) {
  const m = computeMetrics(findings)
  if (m.totalVulnerabilities === 0)
    return 'No known dependency vulnerabilities found. Keep dependencies pinned and rescan regularly.'
  return `This repository has ${m.totalVulnerabilities} vulnerabilities, including ${m.activelyExploited} actively exploited KEV hits. Prioritize critical/high KEV issues first.`
}

export function sortFindings(findings) {
  const score = (v) => {
    const s = (v.severity || '').toLowerCase()
    return (s.includes('critical') ? 4 : s.includes('high') ? 3 : s.includes('medium') ? 2 : s.includes('low') ? 1 : 0) + (v.kev ? 2 : 0)
  }
  return Object.entries(findings)
    .flatMap(([dep, vulns]) => vulns.map((vuln) => ({ dep, vuln })))
    .sort((a, b) => score(b.vuln) - score(a.vuln))
}

export function repoDisplayName(url) {
  try {
    const parts = new URL(url).pathname.split('/').filter(Boolean)
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`
  } catch { /* ignore */ }
  return url
}

export function compareScanFindings(prev, curr) {
  const prevIds = new Set(Object.values(prev).flatMap((v) => v.map((x) => x.id)))
  const currIds = new Set(Object.values(curr).flatMap((v) => v.map((x) => x.id)))
  return {
    added: [...currIds].filter((id) => !prevIds.has(id)),
    fixed: [...prevIds].filter((id) => !currIds.has(id)),
    unchanged: [...currIds].filter((id) => prevIds.has(id)).length,
  }
}

export function scoreBreakdown(metrics) {
  const { riskBreakdown: r, activelyExploited, securityScore } = metrics
  const lines = ['Diminishing-returns model (score = 100 × e^−penalty/55):']
  if (r.critical > 0) lines.push(`  critical ×${r.critical} → −${(10 * Math.log2(r.critical * 2 + 1)).toFixed(1)}`)
  if (r.high > 0)     lines.push(`  high     ×${r.high} → −${(6  * Math.log2(r.high     * 2 + 1)).toFixed(1)}`)
  if (r.medium > 0)   lines.push(`  medium   ×${r.medium} → −${(3  * Math.log2(r.medium   * 2 + 1)).toFixed(1)}`)
  if (r.low > 0)      lines.push(`  low      ×${r.low} → −${(1  * Math.log2(r.low      * 2 + 1)).toFixed(1)}`)
  if (r.unknown > 0)  lines.push(`  unknown  ×${r.unknown} → −${(2  * Math.log2(r.unknown  * 2 + 1)).toFixed(1)}`)
  if (activelyExploited > 0) lines.push(`  KEV      ×${activelyExploited} → −${(5 * Math.log2(activelyExploited * 3 + 1)).toFixed(1)}`)
  lines.push(`  = ${securityScore} / 100`)
  return lines.join('\n')
}
