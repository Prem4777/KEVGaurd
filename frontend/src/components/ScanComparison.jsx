import { useEffect, useState } from 'react'
import { compareScanFindings, computeMetrics } from '../utils.js'

export default function ScanComparison({ currentFindings, currentScanId }) {
  const [scans, setScans] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [prevFindings, setPrevFindings] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetch('/api/scans')
      .then(r => r.json())
      .then(d => setScans((d.scans ?? []).filter(s => s.id !== currentScanId)))
      .catch(() => {})
  }, [currentScanId])

  async function loadPrev(id) {
    if (!id) { setPrevFindings(null); return }
    setLoading(true)
    try {
      const res = await fetch(`/api/scans/${id}`)
      if (!res.ok) return
      const data = await res.json()
      const map = {}
      for (const f of data.findings ?? []) {
        const key = `${f.package_name}@${f.ecosystem}`
        map[key] = map[key] ?? []
        map[key].push({ id: f.vulnerability_id, cve_id: f.cve_id, summary: f.summary, severity: f.severity, fixed_in: f.fix, kev: f.kev_status })
      }
      setPrevFindings(map)
    } finally { setLoading(false) }
  }

  if (scans.length === 0) return null

  const diff = prevFindings ? compareScanFindings(prevFindings, currentFindings) : null
  const prevMetrics = prevFindings ? computeMetrics(prevFindings) : null
  const currMetrics = computeMetrics(currentFindings)

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#0b1929] p-5">
      <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.15em] text-white/30">Compare with previous scan</p>
      <select value={selectedId}
        onChange={e => { setSelectedId(e.target.value); loadPrev(e.target.value) }}
        className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[13px] text-white/70 outline-none focus:border-white/20">
        <option value="">Select a previous scan…</option>
        {scans.map(s => (
          <option key={s.id} value={s.id}>
            {s.owner}/{s.repo} — {new Date(s.created_at).toLocaleDateString()} ({s.findings_count} findings)
          </option>
        ))}
      </select>

      {loading && <p className="mt-3 font-mono text-[12px] text-white/30">Loading…</p>}

      {diff && prevMetrics && !loading && (
        <div className="mt-4 space-y-3">
          <div className="flex items-center justify-between rounded-lg border border-white/[0.06] px-4 py-3">
            <span className="font-mono text-[12px] text-white/40">Security score</span>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[13px] text-white/40">{prevMetrics.securityScore}</span>
              <svg className="h-3.5 w-3.5 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
              <span className={`font-mono text-[13px] font-semibold ${currMetrics.securityScore > prevMetrics.securityScore ? 'text-[#45dfa4]' : currMetrics.securityScore < prevMetrics.securityScore ? 'text-[#e13052]' : 'text-white/60'}`}>
                {currMetrics.securityScore}
              </span>
              {currMetrics.securityScore !== prevMetrics.securityScore && (
                <span className={`font-mono text-[11px] ${currMetrics.securityScore > prevMetrics.securityScore ? 'text-[#45dfa4]/60' : 'text-[#e13052]/60'}`}>
                  ({currMetrics.securityScore > prevMetrics.securityScore ? '+' : ''}{currMetrics.securityScore - prevMetrics.securityScore})
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'New',       val: diff.added.length,   color: diff.added.length > 0 ? 'text-[#e13052]' : 'text-white/40' },
              { label: 'Fixed',     val: diff.fixed.length,   color: diff.fixed.length > 0 ? 'text-[#45dfa4]' : 'text-white/40' },
              { label: 'Unchanged', val: diff.unchanged,      color: 'text-white/40' },
            ].map(({ label, val, color }) => (
              <div key={label} className="rounded-lg border border-white/[0.06] px-3 py-2 text-center">
                <p className={`text-[20px] font-semibold ${color}`}>{val}</p>
                <p className="font-mono text-[10px] uppercase tracking-widest text-white/25">{label}</p>
              </div>
            ))}
          </div>

          {diff.added.length > 0 && (
            <div className="rounded-lg border border-[#e13052]/20 bg-[#e13052]/5 px-3 py-2">
              <p className="font-mono text-[11px] text-[#e13052]/80">⚠ Regression — {diff.added.length} new {diff.added.length === 1 ? 'vulnerability' : 'vulnerabilities'} since last scan</p>
            </div>
          )}
          {diff.fixed.length > 0 && diff.added.length === 0 && (
            <div className="rounded-lg border border-[#45dfa4]/20 bg-[#45dfa4]/5 px-3 py-2">
              <p className="font-mono text-[11px] text-[#45dfa4]/80">✓ Improved — {diff.fixed.length} {diff.fixed.length === 1 ? 'vulnerability' : 'vulnerabilities'} resolved</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
