"use client";

import { useState } from "react";
import type { FindingsMap, DashboardMetrics } from "./types";

type Props = {
  repo: string;
  findings: FindingsMap;
  metrics: DashboardMetrics;
};

export function ExportButton({ repo, findings, metrics }: Props) {
  const [open, setOpen] = useState(false);

  function exportJson() {
    const payload = {
      repo,
      scannedAt: new Date().toISOString(),
      metrics,
      findings,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    download(blob, `kevguard-${repoSlug(repo)}.json`);
    setOpen(false);
  }

  function exportCsv() {
    const rows: string[][] = [
      ["Package", "Vuln ID", "CVE", "Severity", "EPSS", "KEV", "Direct", "Fix Version", "Summary"],
    ];
    for (const [dep, vulns] of Object.entries(findings)) {
      for (const v of vulns) {
        rows.push([
          dep,
          v.id,
          v.cveId ?? "",
          String(v.severity ?? "unknown"),
          v.epssScore != null ? (v.epssScore * 100).toFixed(2) + "%" : "",
          v.kev ? "yes" : "no",
          v.isDirect !== false ? "direct" : "transitive",
          v.fixed_in ?? "",
          (v.summary ?? "").replace(/,/g, ";"),
        ]);
      }
    }
    const csv = rows.map((r) => r.map((c) => `"${c}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    download(blob, `kevguard-${repoSlug(repo)}.csv`);
    setOpen(false);
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-[12px] text-white/50 transition-colors hover:border-white/20 hover:text-white/80"
        aria-label="Export report"
      >
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
        </svg>
        Export
      </button>

      {open && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full z-50 mt-1 w-36 overflow-hidden rounded-lg border border-white/10 bg-[#0d1f35] shadow-xl">
            <button
              onClick={exportJson}
              className="flex w-full items-center gap-2 px-4 py-2.5 text-left font-mono text-[12px] text-white/60 transition-colors hover:bg-white/5 hover:text-white"
            >
              <span className="text-[#45dfa4]">{ }</span> JSON
            </button>
            <button
              onClick={exportCsv}
              className="flex w-full items-center gap-2 px-4 py-2.5 text-left font-mono text-[12px] text-white/60 transition-colors hover:bg-white/5 hover:text-white"
            >
              <span className="text-amber-400">⊞</span> CSV
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function repoSlug(repo: string) {
  return repo.replace(/[^a-zA-Z0-9\-_]/g, "-").toLowerCase();
}

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
