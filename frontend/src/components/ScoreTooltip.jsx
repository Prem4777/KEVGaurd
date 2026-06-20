import { useState } from 'react'
import { scoreBreakdown } from '../utils.js'

export default function ScoreTooltip({ metrics }) {
  const [show, setShow] = useState(false)
  const text = scoreBreakdown(metrics)

  return (
    <div className="relative inline-flex items-center">
      <button
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onFocus={() => setShow(true)}
        onBlur={() => setShow(false)}
        className="ml-1 flex h-4 w-4 items-center justify-center rounded-full border border-white/15 font-mono text-[10px] text-white/30 transition-colors hover:border-white/30 hover:text-white/60"
        aria-label="Score breakdown"
      >
        ?
      </button>
      {show && (
        <div className="absolute bottom-full left-1/2 z-50 mb-2 w-64 -translate-x-1/2 rounded-lg border border-white/10 bg-[#0d1f35] p-3 shadow-xl">
          <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-white/30">How the score is calculated</p>
          <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-white/60">{text}</pre>
          <div className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-[#0d1f35]" />
        </div>
      )}
    </div>
  )
}
