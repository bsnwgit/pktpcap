/**
 * AI Assistant panel — floating button + slide-in chat drawer.
 * Accessible from any page. Sends current view's capture/analysis context
 * to whichever AI provider is configured (Anthropic or OpenAI).
 */
import { useState, useRef, useEffect } from 'react'
import { api } from '../api/client'

interface Message {
  role: 'user' | 'assistant'
  text: string
  error?: boolean
}

interface AiAssistantProps {
  /** Optional context from the current view (capture summary, flows, threats, etc.) */
  context?: Record<string, unknown>
}

export default function AiAssistant({ context = {} }: AiAssistantProps) {
  const [open, setOpen]           = useState(false)
  const [messages, setMessages]   = useState<Message[]>([])
  const [input, setInput]         = useState('')
  const [loading, setLoading]     = useState(false)
  const [configured, setConfigured] = useState<boolean | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  // Check if a provider API key is configured
  useEffect(() => {
    if (!open || configured !== null) return
    api.getSettings().then(s => {
      const provider = (s['provider'] as string) || 'anthropic'
      const key = provider === 'openai' ? (s['openai_key'] as string) : (s['anthropic_key'] as string)
      setConfigured(Boolean(key && key !== '••••••••'))
    }).catch(() => setConfigured(false))
  }, [open])

  // Scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async () => {
    const q = input.trim()
    if (!q || loading) return

    setInput('')
    setMessages(m => [...m, { role: 'user', text: q }])
    setLoading(true)

    try {
      const data = await api.aiChat(q, context)
      setMessages(m => [...m, { role: 'assistant', text: data.answer }])
    } catch (e: any) {
      setMessages(m => [...m, { role: 'assistant', text: e.message || 'Network error — could not reach AI service.', error: true }])
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
  }

  return (
    <>
      {/* Floating button */}
      <button
        onClick={() => setOpen(o => !o)}
        title="AI Assistant"
        className={`fixed bottom-6 right-6 z-40 w-12 h-12 rounded-full shadow-lg flex items-center justify-center transition-all ${
          open ? 'bg-gray-700 text-white' : 'bg-sky-600 hover:bg-sky-500 text-white'
        }`}
      >
        {open ? '✕' : '✦'}
      </button>

      {/* Slide-in panel */}
      {open && (
        <div className="fixed bottom-20 right-6 z-40 w-96 max-w-[calc(100vw-3rem)] bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl flex flex-col"
          style={{ height: '28rem' }}>

          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
            <div className="flex items-center gap-2">
              <span className="text-sky-400 text-sm">✦</span>
              <span className="text-sm font-semibold text-white">AI Assistant</span>
            </div>
            {messages.length > 0 && (
              <button
                onClick={() => setMessages([])}
                className="text-xs text-white hover:text-white transition-colors"
              >
                Clear
              </button>
            )}
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3 text-sm">
            {configured === false && (
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 text-yellow-400 text-xs">
                AI assistant not configured. Add an API key in{' '}
                <strong>Settings → AI Assistant</strong>.
              </div>
            )}
            {messages.length === 0 && configured !== false && (
              <div className="text-white text-xs space-y-2">
                <p>Ask about the current capture:</p>
                {[
                  'What stands out in this packet capture?',
                  'Why are there so many DNS queries in this flow?',
                  'Could this traffic pattern indicate a scan?',
                ].map(q => (
                  <button
                    key={q}
                    onClick={() => { setInput(q); }}
                    className="block text-left text-white hover:text-white bg-gray-800 hover:bg-gray-700 rounded-lg px-3 py-2 w-full transition-colors text-xs"
                  >
                    {q}
                  </button>
                ))}
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-sky-600 text-white'
                    : m.error
                      ? 'bg-red-900/40 text-red-300 border border-red-700/40'
                      : 'bg-gray-800 text-gray-200'
                }`}>
                  {m.text}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="bg-gray-800 rounded-xl px-3 py-2 text-xs text-white animate-pulse">
                  Thinking…
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="px-4 py-3 border-t border-gray-800 flex gap-2">
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              disabled={loading || configured === false}
              placeholder={configured === false ? 'Configure API key first' : 'Ask about this capture…'}
              rows={1}
              className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500 resize-none disabled:opacity-50"
            />
            <button
              onClick={send}
              disabled={loading || !input.trim() || configured === false}
              className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg px-3 py-2 text-sm transition-colors"
            >
              →
            </button>
          </div>
        </div>
      )}
    </>
  )
}
