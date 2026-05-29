"use client";

import { useCallback, useEffect, useState } from "react";

type SqlLogEntry = {
  id: string;
  label: string;
  sql: string;
  source: "coral" | "legacy" | "none";
  rowCount: number | null;
  durationMs: number;
  error: string | null;
  timestamp: string;
};

export function SqlLogPanel() {
  const [entries, setEntries] = useState<SqlLogEntry[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/sql-log");
      if (res.ok) {
        const data = await res.json();
        setEntries(data.entries ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function clearLog() {
    await fetch("/api/sql-log", { method: "DELETE" });
    setEntries([]);
    setExpanded(null);
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/6 px-6 py-4">
        <div>
          <h2 className="text-[18px] font-semibold text-white">SQL Log</h2>
          <p className="mt-0.5 font-mono text-[11px] text-white/30">
            Coral queries executed by the agent
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-[12px] text-white/50 transition-colors hover:border-white/20 hover:text-white/80 disabled:opacity-40"
          >
            <svg className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
            </svg>
            Refresh
          </button>
          {entries.length > 0 && (
            <button
              onClick={clearLog}
              className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-[12px] text-white/50 transition-colors hover:border-[#e13052]/30 hover:text-[#e13052]/70"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Entries */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {entries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <svg className="mb-3 h-8 w-8 text-white/10" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 2.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125m16.5 2.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
            </svg>
            <p className="text-[14px] text-white/30">No queries yet</p>
            <p className="mt-1 font-mono text-[11px] text-white/15">Run a scan to see Coral SQL queries here</p>
          </div>
        ) : (
          <div className="space-y-2">
            {entries.map((entry, i) => (
              <div
                key={entry.id}
                className={`rounded-xl border transition-colors ${
                  entry.error
                    ? "border-[#e13052]/20 bg-[#e13052]/5"
                    : "border-white/6 bg-[#0b1929]"
                }`}
              >
                {/* Row header */}
                <button
                  onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                  className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left"
                >
                  <div className="min-w-0 flex-1">
                    {/* Query number + source badge */}
                    <div className="mb-1.5 flex items-center gap-2">
                      <span className="font-mono text-[10px] text-white/20">#{entries.length - i}</span>
                      <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                        entry.source === "coral" ? "bg-[#45dfa4]/10 text-[#45dfa4]/70" : "bg-white/5 text-white/30"
                      }`}>
                        {entry.source}
                      </span>
                      {entry.error && (
                        <span className="rounded bg-[#e13052]/10 px-1.5 py-0.5 font-mono text-[10px] text-[#e13052]/80">
                          error
                        </span>
                      )}
                    </div>
                    {/* Label (human-readable query name) */}
                    <p className="text-[13px] font-medium text-white/80">{entry.label}</p>
                    {/* SQL first line as subtitle */}
                    <p className="mt-0.5 truncate font-mono text-[11px] text-white/30">
                      {entry.sql.trim().split("\n")[0].trim()}
                    </p>
                  </div>

                  {/* Meta */}
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="font-mono text-[11px] text-white/25">
                      {entry.durationMs}ms
                    </span>
                    {entry.rowCount !== null && (
                      <span className="font-mono text-[11px] text-white/25">
                        {entry.rowCount} row{entry.rowCount !== 1 ? "s" : ""}
                      </span>
                    )}
                    <svg
                      className={`h-3.5 w-3.5 text-white/20 transition-transform ${expanded === entry.id ? "rotate-180" : ""}`}
                      fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </button>

                {/* Expanded: full SQL */}
                {expanded === entry.id && (
                  <div className="border-t border-white/6 px-4 pb-4 pt-3">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="font-mono text-[10px] uppercase tracking-widest text-white/25">SQL</span>
                      <span className="font-mono text-[10px] text-white/20">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <pre className="overflow-x-auto rounded-lg bg-black/30 p-3 font-mono text-[12px] leading-relaxed text-[#45dfa4]/80 whitespace-pre-wrap break-all">
                      {entry.sql.trim()}
                    </pre>
                    {entry.error && (
                      <div className="mt-2 rounded-lg border border-[#e13052]/20 bg-[#e13052]/5 px-3 py-2">
                        <p className="font-mono text-[11px] text-[#e13052]/80">{entry.error}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
