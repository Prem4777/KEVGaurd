import { useEffect, useRef, useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import VulnerabilityCard from './components/VulnerabilityCard.jsx'
import RiskBreakdown from './components/RiskBreakdown.jsx'
import ExportButton from './components/ExportButton.jsx'
import ChatPanel from './components/ChatPanel.jsx'
import ScanComparison from './components/ScanComparison.jsx'
import ScoreTooltip from './components/ScoreTooltip.jsx'
import SqlLogPanel from './components/SqlLogPanel.jsx'
import HistoryPage from './components/HistoryPage.jsx'
import { computeMetrics, initialChatAnswer, repoDisplayName, sortFindings } from './utils.js'

// ── Stat cards ────────────────────────────────────────────────────────────────
const TONE = {
  danger:  { card: 'border-[#e13052]/25 bg-[#e13052]/5',  val: 'text-[#e13052]',  icon: 'text-[#e13052]/50'  },
  warn:    { card: 'border-amber-500/25 bg-amber-500/5',   val: 'text-amber-400',  icon: 'text-amber-400/50'  },
  good:    { card: 'border-[#45dfa4]/25 bg-[#45dfa4]/5',  val: 'text-[#45dfa4]',  icon: 'text-[#45dfa4]/50'  },
  neutral: { card: 'border-white/6 bg-[#0b1929]',         val: 'text-white',       icon: 'text-white/20'      },
}
function StatCard({ label, value, sub, tone, icon, tooltip }) {
  const t = TONE[tone] ?? TONE.neutral
  return (
    <div className={`rounded-xl border p-5 ${t.card}`}>
      <div className={`mb-3 ${t.icon}`}>{icon}</div>
      <div className="flex items-baseline gap-1">
        <span className={`text-[32px] font-semibold leading-none tracking-tight ${t.val}`}>{value}</span>
        {sub && <span className="text-[14px] text-white/30">{sub}</span>}
      </div>
      <div className="mt-2 flex items-center gap-1">
        <p className="font-mono text-[11px] uppercase tracking-widest text-white/30">{label}</p>
        {tooltip}
      </div>
    </div>
  )
}
function MiniStat({ label, value, color }) {
  return (
    <div className="rounded-xl border border-white/6 bg-[#0b1929] px-4 py-3">
      <span className={`text-[22px] font-semibold leading-none ${color}`}>{value}</span>
      <p className="mt-1 font-mono text-[11px] uppercase tracking-widest text-white/25">{label}</p>
    </div>
  )
}

// ── Inline scanning state (real SSE progress) ─────────────────────────────────
const LOG_TYPES = { INF: 'text-[#c6c6cd]', KEV: 'text-[#45dfa4]', WRN: 'text-[#ffb2b7]', ERR: 'text-[#e13052]' }
const MSG_TYPE = (msg) => {
  if (msg.includes('KEV') || msg.includes('CISA')) return 'KEV'
  if (msg.includes('Error') || msg.includes('error')) return 'ERR'
  if (msg.includes('Missing')) return 'WRN'
  return 'INF'
}

function ScanningView({ repoName, logs, progress }) {
  const logRef = useRef(null)
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])
  const now = new Date()
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-8 py-12">
      <div className="w-full max-w-2xl">
        <div className="mb-10 w-full">
          <div className="mb-2 flex items-end justify-between">
            <div>
              <h2 className="text-[24px] font-semibold leading-tight tracking-tight text-[#d4e4fa]">
                {progress >= 100 ? 'Scan Complete' : 'Scanning Repository…'}
              </h2>
              <p className="mt-1 font-mono text-[13px] text-[#c6c6cd]">{repoName}</p>
            </div>
            <span className="font-mono text-[13px] text-[#45dfa4]">{progress}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#273647]">
            <div className="h-full rounded-full bg-[#45dfa4] transition-all duration-500"
              style={{ width: `${progress}%` }} />
          </div>
        </div>
        <div className="w-full rounded border border-[#46464c] bg-[#010f1f] p-5">
          <div className="mb-4 flex items-center justify-between border-b border-[#46464c]/50 pb-2">
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-[#45dfa4] animate-pulse" />
              <span className="font-mono text-[11px] font-medium uppercase tracking-wider text-[#d4e4fa]">PROCESS_LOG</span>
            </div>
            <span className="font-mono text-[10px] text-[#46464c]">KEVGuard</span>
          </div>
          <div ref={logRef} className="h-64 space-y-1.5 overflow-y-auto font-mono text-[11px] leading-relaxed">
            <div className="flex gap-3 text-[#45dfa4]/70">
              <span className="shrink-0 opacity-50">{ts}</span>
              <span>INF: System initializing...</span>
            </div>
            {logs.map((log, i) => (
              <div key={i} className={`flex gap-3 ${LOG_TYPES[log.type] ?? LOG_TYPES.INF}`}>
                <span className="shrink-0 opacity-40">{ts}</span>
                <span className="flex-1">{log.type}: {log.msg}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-8 flex w-full items-center gap-4 rounded border border-[#46464c]/40 bg-[#0d1c2d] p-4">
          <svg className="h-5 w-5 shrink-0 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
          </svg>
          <p className="text-[14px] text-[#c6c6cd]">
            <span className="font-semibold text-[#45dfa4]">Insight:</span>{' '}
            Cross-referencing dependency graph with{' '}
            <span className="rounded bg-[#273647] px-1 font-mono text-[12px] text-[#d4e4fa]">CISA-KEV</span> catalog.
          </p>
        </div>
      </div>
    </div>
  )
}

// ── SSE reader — real-time progress + final result ────────────────────────────
async function readSseStream(res, onProgress, onResult, onError) {
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    let value, done
    try { ;({ value, done } = await reader.read()) } catch { break }

    if (value) buffer += decoder.decode(value, { stream: !done })

    let norm = buffer.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    let idx = norm.indexOf('\n\n')
    while (idx >= 0) {
      const block = norm.slice(0, idx).trim()
      norm = norm.slice(idx + 2)
      idx = norm.indexOf('\n\n')
      if (!block) continue

      let etype = 'message', dline = ''
      for (const line of block.split('\n')) {
        if (line.startsWith('event:')) etype = line.slice(6).trim()
        else if (line.startsWith('data:')) dline = line.slice(5).trim()
      }
      if (!dline) continue

      try {
        const payload = JSON.parse(dline)
        if (etype === 'progress') { onProgress(payload); continue }
        if (etype === 'result')   { onResult(payload); return }
        if (etype === 'error')    { onError(payload.message || 'Scan failed'); return }
      } catch (e) {
        console.warn('[KEVGuard] SSE parse error:', e, dline.slice(0, 100))
      }
    }
    buffer = norm
    if (done) break
  }
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  // view: 'landing' | 'scanning' | 'result'
  const [view, setView]                 = useState('landing')
  const [repoUrl, setRepoUrl]           = useState('')
  const [result, setResult]             = useState(null)
  const [error, setError]               = useState(null)
  const [rateLimitWarning, setRateLimitWarning] = useState(null)
  const [recentScans, setRecentScans]   = useState([])
  const [activeTab, setActiveTab]       = useState('dashboard')
  // Real SSE progress
  const [scanLogs, setScanLogs]         = useState([])
  const [scanProgress, setScanProgress] = useState(0)

  // Poll recent scans every 3s while a scan is in flight so history updates live
  const pollRef = useRef(null)

  async function loadRecentScans() {
    try {
      const r = await fetch('/api/scans')
      if (r.ok) setRecentScans((await r.json()).scans ?? [])
    } catch { /* ignore */ }
  }

  useEffect(() => { loadRecentScans() }, [])

  // Progress event → update log + progress bar
  function handleProgress(payload) {
    const msg = payload.message || ''
    if (!msg) return
    const type = MSG_TYPE(msg)
    setScanLogs(prev => [...prev, { type, msg }])
    // Map stage to progress %
    const pMap = {
      started: 5, fetched: 20, parsed: 35,
      processing: 60, persisting: 80, summarizing: 90, done: 98,
    }
    const p = pMap[payload.type]
    if (p) setScanProgress(p)
  }

  async function runScan(e) {
    e?.preventDefault()
    if (!repoUrl.trim()) return

    // Switch to scanning view immediately
    setView('scanning')
    setResult(null)
    setError(null)
    setRateLimitWarning(null)
    setScanLogs([])
    setScanProgress(5)

    // Start polling so history panel stays live
    clearInterval(pollRef.current)
    pollRef.current = setInterval(loadRecentScans, 3000)

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl }),
      })

      if (!res.ok || !res.body) {
        setError(`Scan failed: ${res.status}`)
        setView('landing')
        return
      }

      await readSseStream(
        res,
        handleProgress,
        (data) => {
          // Scan complete — set progress to 100, wait one tick then show result
          setScanProgress(100)
          setScanLogs(prev => [...prev, { type: 'INF', msg: 'Report generated successfully.' }])
          if (data.rateLimitWarning) setRateLimitWarning(data.rateLimitWarning)
          // Small delay so user sees 100% before transitioning
          setTimeout(() => {
            setResult(data)
            setView('result')
            clearInterval(pollRef.current)
            loadRecentScans()
          }, 800)
        },
        (msg) => {
          setError(msg)
          setView('landing')
          clearInterval(pollRef.current)
          loadRecentScans()
        },
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setView('landing')
      clearInterval(pollRef.current)
    }
  }

  // Cleanup poll on unmount
  useEffect(() => () => clearInterval(pollRef.current), [])

  function resetToStart() {
    setView('landing')
    setResult(null)
    setError(null)
    setRateLimitWarning(null)
    setScanLogs([])
    setScanProgress(0)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const findings    = result?.findings ?? {}
  const metrics     = computeMetrics(findings)
  const sortedVulns = sortFindings(findings)
  const repoName    = result?.repo ? repoDisplayName(result.repo) : repoDisplayName(repoUrl)

  return (
    <div className="flex min-h-screen bg-[#060e18] text-[#d4e4fa]">
      <Sidebar active={activeTab} onTabChange={setActiveTab} onNewScan={resetToStart} />

      {activeTab === 'sql-log' && (
        <div className="ml-60 flex flex-1 flex-col min-h-screen"><SqlLogPanel /></div>
      )}
      {activeTab === 'history' && <HistoryPage />}

      {activeTab === 'dashboard' && (
        <div className="ml-60 flex flex-1 flex-col">

          {/* ════ SCANNING ════ */}
          {view === 'scanning' && (
            <ScanningView repoName={repoUrl} logs={scanLogs} progress={scanProgress} />
          )}

          {/* ════ LANDING ════ */}
          {view === 'landing' && (
            <>
              <section className="flex min-h-screen flex-col items-center justify-center px-6 text-center">
                <div className="mb-3 flex items-center gap-2">
                  <svg className="h-5 w-5 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                  <span className="font-mono text-[12px] uppercase tracking-[0.2em] text-[#45dfa4]">KEVGuard</span>
                </div>
                <h1 className="mb-4 max-w-2xl text-[42px] font-semibold leading-[1.1] tracking-[-0.03em] text-white sm:text-[52px]">
                  AI-powered dependency security
                </h1>
                <p className="mb-12 max-w-lg text-[17px] leading-relaxed text-white/40">
                  Paste a GitHub repository URL. We scan your dependencies against OSV and CISA KEV in seconds.
                </p>
                <form onSubmit={runScan} className="w-full max-w-xl">
                  <div className="flex overflow-hidden rounded-xl border border-white/10 bg-white/4 focus-within:border-[#45dfa4]/50 transition-all">
                    <input value={repoUrl} onChange={e => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/owner/repo"
                      className="flex-1 bg-transparent px-5 py-4 text-[15px] text-white outline-none placeholder:text-white/20" />
                    <button type="submit" disabled={!repoUrl.trim()}
                      className="m-1.5 rounded-lg bg-[#45dfa4] px-6 py-2.5 text-[13px] font-semibold text-[#002d1e] transition-all hover:brightness-110 disabled:opacity-40">
                      Analyze
                    </button>
                  </div>
                  {error && <p className="mt-3 text-[13px] text-red-400">{error}</p>}
                </form>
                <button onClick={() => document.getElementById('about')?.scrollIntoView({ behavior: 'smooth' })}
                  className="mt-20 flex flex-col items-center gap-2 text-white/20 hover:text-white/40">
                  <span className="font-mono text-[11px] uppercase tracking-widest">Learn more</span>
                  <svg className="h-4 w-4 animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              </section>

              <section id="about" className="border-t border-white/5 px-8 py-24">
                <div className="mx-auto max-w-4xl">
                  <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.2em] text-[#45dfa4]">What is KEVGuard</p>
                  <h2 className="mb-6 text-[32px] font-semibold leading-tight tracking-tight text-white">
                    Know which vulnerabilities are being actively exploited — before attackers reach you.
                  </h2>
                  <p className="mb-16 max-w-2xl text-[16px] leading-relaxed text-white/40">
                    KEVGuard combines OSV vulnerability intelligence with the CISA Known Exploited Vulnerabilities catalog to give you a prioritised, AI-summarised security report for any public GitHub repository.
                  </p>
                  <div className="divide-y divide-white/5">
                    {[
                      { num: '01', title: 'GitHub dependency parsing', desc: 'We fetch your package.json, requirements.txt, and other manifests directly from GitHub and extract every declared dependency.' },
                      { num: '02', title: 'OSV vulnerability lookup', desc: 'Each dependency is cross-referenced against the Open Source Vulnerabilities database — covering npm, PyPI, Go, Maven, and more.' },
                      { num: '03', title: 'CISA KEV correlation', desc: 'CVEs are matched against the CISA Known Exploited Vulnerabilities catalog so you know which issues are actively being weaponised.' },
                      { num: '04', title: 'AI-generated summary', desc: 'Gemini synthesises the findings into a plain-English summary with a prioritised fix list — no security expertise required.' },
                    ].map(f => (
                      <div key={f.num} className="flex gap-8 py-8">
                        <span className="shrink-0 font-mono text-[13px] text-white/20 pt-0.5">{f.num}</span>
                        <div>
                          <h3 className="mb-2 text-[17px] font-semibold text-white">{f.title}</h3>
                          <p className="text-[15px] leading-relaxed text-white/40">{f.desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-16 grid grid-cols-2 gap-8 border-t border-white/5 pt-16 md:grid-cols-4">
                    {[{ value: '< 2s', label: 'Scan time' }, { value: '1M+', label: 'CVEs indexed' }, { value: '24/7', label: 'CISA sync' }, { value: '99.9%', label: 'Accuracy' }].map(s => (
                      <div key={s.label}>
                        <div className="text-[28px] font-semibold tracking-tight text-white">{s.value}</div>
                        <div className="mt-1 font-mono text-[11px] uppercase tracking-widest text-white/30">{s.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              {recentScans.length > 0 && (
                <section className="border-t border-white/5 px-8 py-16">
                  <div className="mx-auto max-w-4xl">
                    <h3 className="mb-6 text-[18px] font-semibold text-white">Recent scans</h3>
                    <div className="divide-y divide-white/5">
                      {recentScans.map(scan => (
                        <button key={scan.id}
                          onClick={() => { setRepoUrl(`https://github.com/${scan.owner}/${scan.repo}`) }}
                          className="flex w-full items-center justify-between gap-4 py-4 text-left hover:text-white transition-colors">
                          <div>
                            <span className="text-[15px] font-medium text-white/80">{scan.owner}/{scan.repo}</span>
                            <div className="mt-0.5 flex items-center gap-3 font-mono text-[11px] text-white/30">
                              <span>{scan.findings_count} findings</span>
                              {scan.kev_count > 0 && <span className="text-[#e13052]/70">{scan.kev_count} KEV</span>}
                              <span className={scan.status === 'completed' ? 'text-[#45dfa4]/60' : 'text-amber-400/60'}>{scan.status}</span>
                              <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                            </div>
                          </div>
                          <svg className="h-4 w-4 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                          </svg>
                        </button>
                      ))}
                    </div>
                  </div>
                </section>
              )}

              <footer className="mt-auto border-t border-white/5 px-8 py-5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] text-white/20">KEVGuard · OSV + CISA KEV</span>
                  <span className="font-mono text-[11px] text-white/20">FastAPI + React</span>
                </div>
              </footer>
            </>
          )}

          {/* ════ RESULT ════ */}
          {view === 'result' && result && (
            <div className="flex flex-col min-h-screen">
              <div className="sticky top-0 z-40 border-b border-white/6 bg-[#060e18]/95 px-8 py-3 backdrop-blur">
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <button onClick={resetToStart}
                      className="flex items-center gap-1.5 font-mono text-[12px] text-white/30 hover:text-white/60 transition-colors">
                      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
                      </svg>
                      New scan
                    </button>
                    <span className="text-white/10">/</span>
                    <span className="text-[14px] font-medium text-white/60">{repoName}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="h-1.5 w-1.5 rounded-full bg-[#45dfa4]" />
                    <span className="font-mono text-[11px] text-white/30">Scan complete</span>
                    <ExportButton repo={repoName} findings={findings} metrics={metrics} />
                  </div>
                </div>
              </div>

              <div className="px-8 py-8">
                {result.cachedSha && (
                  <div className="mb-6 flex items-center gap-2 rounded-lg border border-[#45dfa4]/20 bg-[#45dfa4]/5 px-4 py-2.5">
                    <svg className="h-4 w-4 shrink-0 text-[#45dfa4]/60" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <p className="font-mono text-[12px] text-[#45dfa4]/80">Cached result — this commit was already scanned.</p>
                  </div>
                )}
                {rateLimitWarning && (
                  <div className="mb-6 flex items-center gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-2.5">
                    <svg className="h-4 w-4 shrink-0 text-amber-400/60" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                    <p className="font-mono text-[12px] text-amber-400/80">{rateLimitWarning}</p>
                  </div>
                )}

                <div className="mb-8">
                  <p className="mb-1 font-mono text-[11px] uppercase tracking-[0.18em] text-white/30">Security Report</p>
                  <h2 className="text-[28px] font-semibold leading-tight tracking-tight text-white">{repoName}</h2>
                  <p className="mt-1 font-mono text-[12px] text-white/25">{new Date().toLocaleString()} · OSV + CISA KEV</p>

                  <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    <StatCard label="Security Score" value={String(metrics.securityScore)} sub="/ 100"
                      tone={metrics.securityScore < 60 ? 'danger' : metrics.securityScore < 80 ? 'warn' : 'good'}
                      tooltip={<ScoreTooltip metrics={metrics} />}
                      icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg>} />
                    <StatCard label="Critical" value={String(metrics.riskBreakdown.critical)}
                      tone={metrics.riskBreakdown.critical > 0 ? 'danger' : 'neutral'}
                      icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" /></svg>} />
                    <StatCard label="Actively Exploited" value={String(metrics.activelyExploited)}
                      tone={metrics.activelyExploited > 0 ? 'danger' : 'neutral'}
                      icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" /></svg>} />
                    <StatCard label="Total Findings" value={String(metrics.totalVulnerabilities)} tone="neutral"
                      icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0112 12.75zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 01-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 002.248-2.354M12 12.75a2.25 2.25 0 01-2.248-2.354M12 8.25c.995 0 1.971-.08 2.922-.236.403-.066.74-.358.795-.762a3.778 3.778 0 00-.399-2.25M12 8.25c-.995 0-1.97-.08-2.922-.236-.402-.066-.74-.358-.795-.762a3.734 3.734 0 01.4-2.253M12 8.25a2.25 2.25 0 00-2.248 2.146M12 8.25a2.25 2.25 0 012.248 2.146" /></svg>} />
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    <MiniStat label="High"                value={metrics.riskBreakdown.high}   color="text-orange-400" />
                    <MiniStat label="Medium"              value={metrics.riskBreakdown.medium} color="text-amber-400"  />
                    <MiniStat label="Low"                 value={metrics.riskBreakdown.low}    color="text-yellow-400" />
                    <MiniStat label="Vulnerable Packages" value={metrics.dependencyCount}      color="text-white/60"   />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_340px]">
                  <div>
                    <div className="mb-4 flex items-center justify-between">
                      <h3 className="text-[16px] font-semibold text-white">
                        Vulnerabilities
                        <span className="ml-2 font-mono text-[13px] font-normal text-white/30">{sortedVulns.length}</span>
                      </h3>
                      {metrics.activelyExploited > 0 && (
                        <span className="rounded-md border border-[#e13052]/40 bg-[#e13052]/10 px-2.5 py-1 font-mono text-[11px] text-[#e13052]">
                          {metrics.activelyExploited} KEV
                        </span>
                      )}
                    </div>
                    {sortedVulns.length === 0 ? (
                      <div className="rounded-xl border border-white/6 bg-[#0b1929] p-8 text-center">
                        <svg className="mx-auto mb-3 h-8 w-8 text-[#45dfa4]/40" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <p className="text-[15px] font-medium text-white/50">No vulnerabilities found</p>
                        <p className="mt-1 text-[13px] text-white/25">This repository looks clean.</p>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {sortedVulns.map(({ dep, vuln }, idx) => (
                          <VulnerabilityCard key={`${dep}-${vuln.id}-${idx}`} dependency={dep} vuln={vuln} />
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="space-y-4">
                    <div className="rounded-xl border border-white/6 bg-[#0b1929] p-5">
                      <div className="mb-3 flex items-center gap-2">
                        <svg className="h-4 w-4 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                        </svg>
                        <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-[#45dfa4]">AI Summary</span>
                      </div>
                      <p className="text-[14px] leading-relaxed text-white/65">
                        {result.summary ?? initialChatAnswer(findings)}
                      </p>
                    </div>
                    <div className="rounded-xl border border-white/6 bg-[#0b1929] p-5">
                      <p className="mb-4 font-mono text-[11px] uppercase tracking-[0.15em] text-white/30">Risk Breakdown</p>
                      <RiskBreakdown breakdown={metrics.riskBreakdown} />
                    </div>
                    <ChatPanel findings={findings} repo={result.repo ?? repoName} />
                    <ScanComparison currentFindings={findings} currentScanId={result.scanId} />
                  </div>
                </div>
              </div>

              <footer className="mt-auto border-t border-white/5 px-8 py-4">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] text-white/20">KEVGuard · OSV + CISA KEV</span>
                  <span className="font-mono text-[11px] text-white/20">FastAPI + React</span>
                </div>
              </footer>
            </div>
          )}

        </div>
      )}
    </div>
  )
}
