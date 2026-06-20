import { useEffect, useRef, useState } from 'react'

const QUICK = [
  { label: 'Prioritize Fixes', q: 'What should I fix first?' },
  { label: 'Risk Profile',     q: 'Summarize repo risk' },
  { label: 'Most Dangerous',   q: 'Which dependency is most dangerous?' },
]

export default function ChatPanel({ findings, repo }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', text: 'Analysis complete. Ask me what to fix first, which dependency is most dangerous, or for a short risk summary.' },
  ])
  const [prompt, setPrompt] = useState('')
  const scrollRef = useRef(null)

  async function send(question) {
    const q = question.trim()
    if (!q) return
    setMessages(prev => [...prev, { role: 'user', text: q }])
    setPrompt('')
    setMessages(prev => [...prev, { role: 'assistant', text: 'Thinking…' }])
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo, question: q, findings }),
      })
      const data = await res.json()
      const answer = res.ok ? (data.answer ?? 'No answer.') : (data.error ?? data.detail ?? 'Chat failed.')
      setMessages(prev => [...prev.filter(m => m.text !== 'Thinking…'), { role: 'assistant', text: answer }])
    } catch {
      setMessages(prev => [...prev.filter(m => m.text !== 'Thinking…'), { role: 'assistant', text: 'Chat failed. Try again.' }])
    }
  }

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages])

  return (
    <div className="flex h-[420px] flex-col overflow-hidden rounded-xl border border-white/[0.06] bg-[#0b1929]">
      <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
        <svg className="h-4 w-4 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 01-2.555-.337A5.972 5.972 0 015.41 20.97a5.969 5.969 0 01-.474-.065 4.48 4.48 0 00.978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25z" />
        </svg>
        <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-[#45dfa4]">AI Chat</span>
      </div>

      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[85%] rounded-xl border px-4 py-2.5 text-[13px] leading-relaxed ${
              m.role === 'user' ? 'border-white/10 bg-white/[0.08] text-white' : 'border-white/[0.06] bg-[#060e18] text-white/70'
            }`}>
              {m.text}
            </div>
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-2 border-t border-white/[0.06] p-3">
        <div className="flex flex-wrap gap-1.5">
          {QUICK.map(a => (
            <button key={a.label} onClick={() => send(a.q)}
              className="rounded-full border border-white/10 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-white/40 transition-colors hover:border-white/20 hover:text-white/70">
              {a.label}
            </button>
          ))}
        </div>
        <form onSubmit={e => { e.preventDefault(); send(prompt) }} className="relative flex">
          <input value={prompt} onChange={e => setPrompt(e.target.value)}
            placeholder="Ask about this repo…"
            className="w-full rounded-lg border border-white/10 bg-white/[0.04] py-2.5 pl-3 pr-10 font-mono text-[13px] text-white outline-none placeholder:text-white/20 focus:border-white/20" />
          <button type="submit" className="absolute right-2.5 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/70">
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5" />
            </svg>
          </button>
        </form>
      </div>
    </div>
  )
}
