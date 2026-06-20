import { useEffect, useState } from 'react'

function sevColor(sev) {
  const v = (sev || '').toUpperCase()
  if (v.includes('CRITICAL')) return 'text-[#e13052]'
  if (v.includes('HIGH'))     return 'text-orange-400'
  if (v.includes('MEDIUM') || v.includes('MODERATE')) return 'text-amber-400'
  if (v.includes('LOW'))      return 'text-yellow-400'
  return 'text-white/30'
}

function sevRank(sev) {
  const v = (sev || '').toUpperCase()
  if (v.includes('CRITICAL')) return 4
  if (v.includes('HIGH'))     return 3
  if (v.includes('MEDIUM') || v.includes('MODERATE')) return 2
  if (v.includes('LOW'))      return 1
  return 0
}

// ── Scan detail modal ─────────────────────────────────────────────────────────

function ScanDetail({ scan, onClose }) {
  const { job, findings } = scan
  const grouped = findings.reduce((acc, f) => {
    const key = `${f.package_name}@${f.ecosystem}`
    acc[key] = acc[key] ?? []
    acc[key].push(f)
    return acc
  }, {})
  const kevCount = findings.filter(f => f.kev_status).length

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="mx-auto my-10 max-w-3xl rounded-2xl border border-white/[0.08] bg-[#060e18] p-8 shadow-2xl"
        onClick={e => e.stopPropagation()}>
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h2 className="text-[24px] font-semibold text-white">{job.owner}/{job.repo}</h2>
            <p className="mt-1 font-mono text-[12px] text-white/30">{new Date(job.created_at).toLocaleString()}</p>
          </div>
          <button onClick={onClose} className="rounded-lg border border-white/10 p-2 text-white/40 hover:text-white/80">
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="mb-6 flex gap-6 border-b border-white/5 pb-6">
          {[
            { label: 'Status',   val: job.status,           accent: job.status === 'completed' ? 'text-[#45dfa4]' : 'text-amber-400' },
            { label: 'Findings', val: String(findings.length), accent: null },
            { label: 'KEV Hits', val: String(kevCount),     accent: kevCount > 0 ? 'text-[#e13052]' : null },
          ].map(({ label, val, accent }) => (
            <div key={label}>
              <p className="font-mono text-[11px] uppercase tracking-widest text-white/25">{label}</p>
              <p className={`mt-0.5 text-[15px] font-semibold ${accent ?? 'text-white'}`}>{val}</p>
            </div>
          ))}
        </div>

        {Object.keys(grouped).length === 0
          ? <p className="py-8 text-center text-white/30">No findings stored for this scan.</p>
          : Object.entries(grouped).map(([dep, depFindings]) => {
              const highestSev = depFindings.map(f => f.severity).sort((a, b) => sevRank(b) - sevRank(a))[0] ?? 'UNKNOWN'
              const hasKev = depFindings.some(f => f.kev_status)
              return (
                <div key={dep} className="border-b border-white/5 py-5">
                  <div className="mb-3 flex flex-wrap items-center gap-3">
                    {hasKev && <span className="h-2 w-2 rounded-full bg-[#e13052]" />}
                    <span className="text-[16px] font-semibold text-white">{dep}</span>
                    <span className={`font-mono text-[11px] uppercase ${sevColor(highestSev)}`}>{highestSev}</span>
                    {hasKev && <span className="rounded border border-[#e13052]/40 px-2 py-0.5 font-mono text-[10px] text-[#e13052]">Actively exploited</span>}
                    <span className="ml-auto font-mono text-[11px] text-white/25">{depFindings.length} issue{depFindings.length !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="space-y-3 pl-4">
                    {depFindings.map(f => (
                      <div key={f.vulnerability_id}>
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span className="font-mono text-[12px] text-white/50">{f.vulnerability_id}</span>
                          <span className={`font-mono text-[11px] uppercase ${sevColor(f.severity)}`}>{f.severity}</span>
                          {f.kev_status && <span className="font-mono text-[11px] text-[#e13052]">KEV</span>}
                        </div>
                        <p className="text-[13px] leading-relaxed text-white/50">{f.summary}</p>
                        {f.fix && f.fix !== 'unknown' && (
                          <p className="mt-1 font-mono text-[12px] text-[#45dfa4]/60">Fix → {f.fix}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )
            })
        }
      </div>
    </div>
  )
}

// ── Main history page ─────────────────────────────────────────────────────────

export default function HistoryPage() {
  const [scans, setScans]             = useState([])
  const [loading, setLoading]         = useState(true)
  const [selected, setSelected]       = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)

  useEffect(() => {
    fetch('/api/scans')
      .then(r => r.json())
      .then(d => setScans(d.scans ?? []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  async function openDetail(id) {
    setDetailLoading(true)
    try {
      const res = await fetch(`/api/scans/${id}`)
      if (res.ok) setSelected(await res.json())
    } finally { setDetailLoading(false) }
  }

  const maxFindings = Math.max(1, ...scans.map(s => s.findings_count))

  return (
    <div className="ml-60 min-h-screen bg-[#060e18] px-8 py-10">
      <div className="mx-auto max-w-4xl">
        <p className="mb-1 font-mono text-[11px] uppercase tracking-[0.18em] text-white/30">Scan History</p>
        <h1 className="mb-8 text-[28px] font-semibold tracking-tight text-white">Previous Scans</h1>

        {loading && <p className="font-mono text-[13px] text-white/30">Loading…</p>}

        {!loading && scans.length === 0 && (
          <div className="rounded-xl border border-white/6 bg-[#0b1929] p-8 text-center">
            <p className="text-[15px] text-white/40">No scans yet. Run your first scan from the dashboard.</p>
          </div>
        )}

        {scans.length > 0 && (
          <>
            {/* Risk trend sparkline */}
            <div className="mb-6 flex h-14 items-end gap-1 overflow-hidden rounded-xl border border-white/6 bg-[#0b1929] px-4 py-3">
              {scans.slice(0, 20).map(s => (
                <div key={s.id}
                  className="flex-1 cursor-pointer rounded-sm bg-[#45dfa4]/40 transition-all hover:bg-[#45dfa4]/70"
                  style={{ height: `${Math.max(12, Math.round((s.findings_count / maxFindings) * 100))}%` }}
                  title={`${s.owner}/${s.repo}: ${s.findings_count} findings`}
                  onClick={() => openDetail(s.id)} />
              ))}
            </div>

            {/* Scan list */}
            <div className="divide-y divide-white/5 rounded-xl border border-white/6 bg-[#0b1929]">
              {scans.map(scan => (
                <button key={scan.id} onClick={() => openDetail(scan.id)}
                  className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left transition-colors hover:bg-white/[0.02]">
                  <div>
                    <span className="text-[15px] font-semibold text-white/80">{scan.owner}/{scan.repo}</span>
                    <div className="mt-0.5 flex items-center gap-3 font-mono text-[11px] text-[#c6c6cd]">
                      <span>Findings: {scan.findings_count}</span>
                      <span className="opacity-40">·</span>
                      <span className={scan.kev_count > 0 ? 'text-[#e13052]' : ''}>KEV: {scan.kev_count}</span>
                      <span className="opacity-40">·</span>
                      <span className={scan.status === 'completed' ? 'text-[#45dfa4]' : 'text-amber-400'}>{scan.status}</span>
                      <span className="opacity-40">·</span>
                      <span>{new Date(scan.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                  <svg className="h-4 w-4 shrink-0 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      {detailLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <p className="font-mono text-[13px] text-white/50">Loading scan…</p>
        </div>
      )}
      {selected && <ScanDetail scan={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
