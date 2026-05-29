import type { DashboardMetrics, FindingsMap, VulnItem } from "./types";

function severityText(severity: VulnItem["severity"]) {
  if (!severity) return "unknown";
  if (typeof severity === "string") return severity.toLowerCase();
  if (typeof severity === "object" && severity.type)
    return String(severity.type).toLowerCase();
  return "unknown";
}

export function computeMetrics(findings: FindingsMap): DashboardMetrics {
  const deps = Object.keys(findings);
  let total = 0;
  let kev = 0;
  const riskBreakdown = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

  for (const vulns of Object.values(findings)) {
    for (const vuln of vulns) {
      total += 1;
      if (vuln.kev) kev += 1;
      const sev = severityText(vuln.severity);
      if (sev.includes("critical")) riskBreakdown.critical += 1;
      else if (sev.includes("high")) riskBreakdown.high += 1;
      else if (sev.includes("moderate") || sev.includes("medium")) riskBreakdown.medium += 1;
      else if (sev.includes("low")) riskBreakdown.low += 1;
      else riskBreakdown.unknown += 1;
    }
  }

  // Diminishing-returns penalty: each additional vuln of the same severity
  // hurts less than the first. Formula: weight × log2(count + 1)
  // This prevents a pile of medium findings from flooring the score.
  // KEV adds a flat multiplier on top (×1.5 on the critical+high subtotal).
  const r = riskBreakdown;
  const raw =
    10 * Math.log2(r.critical * 2 + 1) +   // 1 crit  → ~10,  5 crit  → ~25
    6  * Math.log2(r.high     * 2 + 1) +   // 1 high  → ~6,   6 high  → ~17
    3  * Math.log2(r.medium   * 2 + 1) +   // 1 med   → ~3,   6 med   → ~9
    1  * Math.log2(r.low      * 2 + 1) +   // 1 low   → ~1
    2  * Math.log2(r.unknown  * 2 + 1);    // unknown treated between low and medium

  // KEV bonus penalty: each KEV adds 5 points on top, also diminishing
  const kevPenalty = 5 * Math.log2(kev * 3 + 1);

  const totalPenalty = raw + kevPenalty;

  // Map penalty onto 0-100 scale using exponential decay
  // k=55 calibration: clean=100, 1 high=84, 3high+2med=65, lodash profile=34
  const securityScore = Math.round(100 * Math.exp(-totalPenalty / 55));

  return { securityScore, totalVulnerabilities: total, activelyExploited: kev, dependencyCount: deps.length, riskBreakdown };
}

/** Human-readable breakdown of how the score was calculated. */
export function scoreBreakdown(metrics: DashboardMetrics): string {
  const { riskBreakdown: r, activelyExploited, securityScore } = metrics;
  const lines: string[] = ["Diminishing-returns model (score = 100 × e^−penalty/22):"];
  if (r.critical > 0) lines.push(`  critical ×${r.critical} → −${(10 * Math.log2(r.critical * 2 + 1)).toFixed(1)}`);
  if (r.high > 0)     lines.push(`  high     ×${r.high} → −${(6  * Math.log2(r.high     * 2 + 1)).toFixed(1)}`);
  if (r.medium > 0)   lines.push(`  medium   ×${r.medium} → −${(3  * Math.log2(r.medium   * 2 + 1)).toFixed(1)}`);
  if (r.low > 0)      lines.push(`  low      ×${r.low} → −${(1  * Math.log2(r.low      * 2 + 1)).toFixed(1)}`);
  if (r.unknown > 0)  lines.push(`  unknown  ×${r.unknown} → −${(2  * Math.log2(r.unknown  * 2 + 1)).toFixed(1)}`);
  if (activelyExploited > 0) lines.push(`  KEV      ×${activelyExploited} → −${(5 * Math.log2(activelyExploited * 3 + 1)).toFixed(1)}`);
  lines.push(`  = ${securityScore} / 100`);
  return lines.join("\n");
}

export function topRiskDependency(findings: FindingsMap): string | null {
  let top: { dep: string; score: number } | null = null;
  for (const [dep, vulns] of Object.entries(findings)) {
    const score =
      vulns.reduce((acc, v) => {
        const sev = severityText(v.severity);
        if (sev.includes("critical")) return acc + 4;
        if (sev.includes("high")) return acc + 3;
        if (sev.includes("moderate") || sev.includes("medium")) return acc + 2;
        if (sev.includes("low")) return acc + 1;
        return acc + 1;
      }, 0) + vulns.filter((v) => v.kev).length * 4;
    if (!top || score > top.score) top = { dep, score };
  }
  return top?.dep ?? null;
}

export function initialChatAnswer(findings: FindingsMap): string {
  const metrics = computeMetrics(findings);
  if (metrics.totalVulnerabilities === 0) {
    return "No known dependency vulnerabilities were found. Keep dependencies pinned and continue regular scanning.";
  }
  return `This repository has ${metrics.totalVulnerabilities} vulnerabilities, including ${metrics.activelyExploited} actively exploited KEV hits. Prioritize critical/high issues with KEV status first.`;
}

/** Compare two scans and return a diff summary. */
export function compareScanFindings(
  prev: FindingsMap,
  curr: FindingsMap,
): { added: string[]; fixed: string[]; unchanged: number } {
  const prevIds = new Set(
    Object.values(prev).flatMap((vulns) => vulns.map((v) => v.id)),
  );
  const currIds = new Set(
    Object.values(curr).flatMap((vulns) => vulns.map((v) => v.id)),
  );

  const added = [...currIds].filter((id) => !prevIds.has(id));
  const fixed = [...prevIds].filter((id) => !currIds.has(id));
  const unchanged = [...currIds].filter((id) => prevIds.has(id)).length;

  return { added, fixed, unchanged };
}
