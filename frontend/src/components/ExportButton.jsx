import { useState } from 'react'

function download(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

function slug(repo) { return repo.replace(/[^a-zA-Z0-9\-_]/g, '-').toLowerCase() }

export default function ExportButton({ repo, findings, metrics }) {
  const [open, setOpen] = useState(false)

  function exportJson() {
    download(
      new Blob([JSON.stringify({ repo, scannedAt: new Date().toISOString(), metrics, findings }, null, 2)], { type: 'application/json' }),
      `kevguard-${slug(repo)}.json`
    )
    setOpen(false)
  }

  function exportCsv() {
    const header = ['Package','Vuln ID','CVE','Severity','EPSS','KEV','Direct','Fix Version','Summary']
    const rows = [header]
    for (const [dep, vulns] of Object.entries(findings)) {
      for (const v of vulns) {
        rows.push([dep, v.id, v.cve_id ?? '', String(v.severity ?? 'unknown'),
          v.epss_score != null ? `${(v.epss_score * 100).toFixed(2)}%` : '',
          v.kev ? 'yes' : 'no', v.is_direct !== false ? 'direct' : 'transitive',
          v.fixed_in ?? '', (v.summary ?? '').replace(/,/g, ';')])
      }
    }
    download(
      new Blob([rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n')], { type: 'text/csv' }),
      `kevguard-${slug(repo)}.csv`
    )
    setOpen(false)
  }

  return (
    <div className="relative">
      <button onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-[12px] text-white/50 transition-colors hover:border-white/20 hover:text-white/80">
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
        </svg>
        Export
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full z-50 mt-1 w-36 overflow-hidden rounded-lg border border-white/10 bg-[#0d1f35] shadow-xl">
            <button onClick={exportJson} className="flex w-full items-center gap-2 px-4 py-2.5 font-mono text-[12px] text-white/60 hover:bg-white/5 hover:text-white">
              <span className="text-[#45dfa4]">{'{}'}</span> JSON
            </button>
            <button onClick={exportCsv} className="flex w-full items-center gap-2 px-4 py-2.5 font-mono text-[12px] text-white/60 hover:bg-white/5 hover:text-white">
              <span className="text-amber-400">⊞</span> CSV
            </button>
          </div>
        </>
      )}
    </div>
  )
}
