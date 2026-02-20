import { useState, useRef, useEffect, useCallback } from 'react'
import { Send, Loader2, Shield, User, Trash2, Cpu, Cog, Wrench, CheckCircle2, XCircle } from 'lucide-react'
import { copilotApi } from '../../api/endpoints'
import ReactMarkdown from 'react-markdown'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  timestamp?: string
  actions?: string[]
  source?: 'llm' | 'rule_based'
  model?: string
  pendingAction?: PendingAction | null
}

interface PendingAction {
  tool: string
  args: Record<string, any>
  description: string
  status: 'pending' | 'approved' | 'denied' | 'executed'
  result?: string
}

interface LLMStatus {
  llm_available: boolean
  provider: string
  model: string
  base_url: string
  reputation: Record<string, { score: number; tier: string; allowed: boolean }>
}

interface AgentChatProps {
  context?: Record<string, any>
}

const INITIAL_QUICK_ACTIONS = [
  "How's my security?",
  'Show critical findings',
  'Triage findings',
  'What are my top risks?',
  'List my assets',
  'MITRE mappings',
]

export default function AgentChat({ context }: AgentChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content:
        "I'm your **AI Security Specialist** — a senior IT security analyst with expertise in " +
        "network security, vulnerability management, threat modeling (C4/STRIDE), risk assessment " +
        "(ISO 27005), and incident response.\n\n" +
        "I have full access to your assessment data and can perform actions with your authorization.\n\n" +
        "Try asking me:\n" +
        '- "How\'s my security posture?"\n' +
        '- "Show me critical findings"\n' +
        '- "Triage my findings"\n' +
        '- "What threats affect my network?"\n' +
        '- "How do I secure my router?"',
      timestamp: new Date().toISOString(),
    },
  ])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamingContent, setStreamingContent] = useState('')
  const [activeTools, setActiveTools] = useState<string[]>([])
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [llmStatus, setLlmStatus] = useState<LLMStatus | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamingContent])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 60000)
    return () => clearInterval(interval)
  }, [])

  async function fetchStatus() {
    try {
      const res = await copilotApi.status()
      setLlmStatus(res.data)
    } catch {
      setLlmStatus(null)
    }
  }

  const sendMessage = useCallback(async (overrideText?: string) => {
    const trimmed = (overrideText || input).trim()
    if (!trimmed || isStreaming) return

    const userMsg: ChatMessage = { role: 'user', content: trimmed, timestamp: new Date().toISOString() }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setIsStreaming(true)
    setStreamingContent('')
    setActiveTools([])
    setSuggestions([])

    const conversation = messages.map((m) => ({ role: m.role, content: m.content }))

    try {
      const controller = new AbortController()
      abortRef.current = controller

      const apiBase = import.meta.env.VITE_API_URL || ''
      const resp = await fetch(`${apiBase}/api/copilot/chat/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: trimmed, conversation, context }),
        signal: controller.signal,
      })

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${resp.statusText}`)
      }

      const reader = resp.body?.getReader()
      if (!reader) throw new Error('No response body')

      const decoder = new TextDecoder()
      let buffer = ''
      let collectedContent = ''
      let source: 'llm' | 'rule_based' = 'llm'
      let model: string | undefined
      let doneSuggestions: string[] = []

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const data = line.slice(6).trim()
          if (data === '[DONE]') continue

          try {
            const event = JSON.parse(data)

            switch (event.type) {
              case 'status':
                setActiveTools((prev) => [...prev, event.message])
                break
              case 'tool_result':
                setActiveTools((prev) =>
                  prev.map((t) =>
                    t === `Calling ${event.tool}...` ? `${event.tool}: ${event.summary}` : t
                  )
                )
                break
              case 'token':
                collectedContent += event.content
                setStreamingContent(collectedContent)
                break
              case 'pending_action':
                // Will be handled in Phase 4
                break
              case 'done':
                source = event.source || 'llm'
                model = event.model
                doneSuggestions = event.suggestions || []
                break
              case 'error':
                collectedContent += `\n\nError: ${event.message}`
                setStreamingContent(collectedContent)
                break
            }
          } catch {
            // Not JSON, might be raw text
            if (data && data !== '[DONE]') {
              collectedContent += data
              setStreamingContent(collectedContent)
            }
          }
        }
      }

      // Finalize the message
      const finalContent = collectedContent || 'No response generated.'
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: finalContent,
          timestamp: new Date().toISOString(),
          source,
          model,
        },
      ])
      setSuggestions(doneSuggestions)
    } catch (err: any) {
      if (err.name === 'AbortError') return
      // Fallback to non-streaming
      try {
        const conversation2 = messages.map((m) => ({ role: m.role, content: m.content }))
        const res = await copilotApi.chat(trimmed, conversation2)
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: res.data.content || 'No response generated.',
            timestamp: res.data.timestamp,
            source: res.data.source,
            model: res.data.model,
          },
        ])
      } catch (fallbackErr: any) {
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: `Error: ${fallbackErr.response?.data?.detail || fallbackErr.message || 'Failed to get response'}`,
            timestamp: new Date().toISOString(),
          },
        ])
      }
    } finally {
      setIsStreaming(false)
      setStreamingContent('')
      setActiveTools([])
      abortRef.current = null
      inputRef.current?.focus()
    }
  }, [input, isStreaming, messages, context])

  const handleExecuteTool = async (msgIndex: number, approved: boolean) => {
    setMessages((prev) => {
      const updated = [...prev]
      const msg = updated[msgIndex]
      if (msg?.pendingAction) {
        msg.pendingAction.status = approved ? 'approved' : 'denied'
      }
      return updated
    })

    if (!approved) {
      setMessages((prev) => {
        const updated = [...prev]
        const msg = updated[msgIndex]
        if (msg?.pendingAction) {
          msg.pendingAction.status = 'denied'
          msg.pendingAction.result = 'Action cancelled by user.'
        }
        return updated
      })
      return
    }

    const msg = messages[msgIndex]
    if (!msg?.pendingAction) return

    try {
      const res = await copilotApi.executeTool({
        tool: msg.pendingAction.tool,
        args: msg.pendingAction.args,
      })
      setMessages((prev) => {
        const updated = [...prev]
        if (updated[msgIndex]?.pendingAction) {
          updated[msgIndex].pendingAction!.status = 'executed'
          updated[msgIndex].pendingAction!.result = res.data.result || 'Action completed.'
        }
        return updated
      })
    } catch (err: any) {
      setMessages((prev) => {
        const updated = [...prev]
        if (updated[msgIndex]?.pendingAction) {
          updated[msgIndex].pendingAction!.status = 'denied'
          updated[msgIndex].pendingAction!.result = `Error: ${err.response?.data?.detail || err.message}`
        }
        return updated
      })
    }
  }

  const clearChat = () => {
    abortRef.current?.abort()
    setMessages([
      {
        role: 'assistant',
        content: 'Chat cleared. How can I help you with your security assessment?',
        timestamp: new Date().toISOString(),
      },
    ])
    setSuggestions([])
    setStreamingContent('')
    setActiveTools([])
  }

  const isLlmOnline = llmStatus?.llm_available === true
  const showInitialActions = messages.length <= 2 && suggestions.length === 0
  const displaySuggestions = suggestions.length > 0 ? suggestions : (showInitialActions ? INITIAL_QUICK_ACTIONS : [])

  return (
    <div className="flex flex-col h-[calc(100vh-220px)]">
      {/* Chat Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b bg-gradient-to-r from-brand-50 to-purple-50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-brand-600 flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="font-semibold text-sm">Security Specialist Agent</h3>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isLlmOnline ? 'bg-green-500' : 'bg-gray-400'}`} />
              <p className="text-xs text-gray-500">
                {isLlmOnline ? (
                  <>
                    <Cpu className="w-3 h-3 inline mr-0.5 -mt-0.5" />
                    AI ({llmStatus?.model})
                  </>
                ) : (
                  <>
                    <Cog className="w-3 h-3 inline mr-0.5 -mt-0.5" />
                    Rule-based
                  </>
                )}
              </p>
            </div>
          </div>
        </div>
        <button
          onClick={clearChat}
          className="text-gray-400 hover:text-gray-600 p-2 rounded-lg hover:bg-gray-100 transition-colors"
          title="Clear chat"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, i) => (
          <div key={i}>
            <div className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              {msg.role === 'assistant' && (
                <div className="w-8 h-8 rounded-full bg-brand-100 flex items-center justify-center shrink-0 mt-1">
                  <Shield className="w-4 h-4 text-brand-600" />
                </div>
              )}
              <div
                className={`max-w-[85%] rounded-2xl px-4 py-3 text-sm ${
                  msg.role === 'user'
                    ? 'bg-brand-600 text-white rounded-br-md'
                    : 'bg-gray-100 text-gray-800 rounded-bl-md'
                }`}
              >
                {msg.role === 'assistant' ? (
                  <div className="prose prose-sm max-w-none prose-headings:text-gray-800 prose-headings:mt-3 prose-headings:mb-2 prose-p:my-1 prose-li:my-0.5 prose-code:text-brand-700 prose-code:bg-brand-50 prose-code:px-1 prose-code:rounded prose-strong:text-gray-800">
                    <ReactMarkdown>{msg.content}</ReactMarkdown>
                  </div>
                ) : (
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                )}
                <div className="flex items-center gap-2 mt-2">
                  {msg.timestamp && (
                    <p className={`text-xs ${msg.role === 'user' ? 'text-brand-200' : 'text-gray-400'}`}>
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </p>
                  )}
                  {msg.role === 'assistant' && msg.source && (
                    <span
                      className={`text-xs px-1.5 py-0.5 rounded-full font-medium ${
                        msg.source === 'llm'
                          ? 'bg-purple-100 text-purple-700'
                          : 'bg-gray-200 text-gray-600'
                      }`}
                    >
                      {msg.source === 'llm' ? 'AI' : 'Rule-based'}
                    </span>
                  )}
                </div>
              </div>
              {msg.role === 'user' && (
                <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center shrink-0 mt-1">
                  <User className="w-4 h-4 text-gray-600" />
                </div>
              )}
            </div>

            {/* Pending Action Confirmation Card */}
            {msg.pendingAction && (
              <div className="ml-11 mt-2">
                <ActionConfirmationCard
                  action={msg.pendingAction}
                  onApprove={() => handleExecuteTool(i, true)}
                  onDeny={() => handleExecuteTool(i, false)}
                />
              </div>
            )}
          </div>
        ))}

        {/* Streaming indicator */}
        {isStreaming && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-full bg-brand-100 flex items-center justify-center shrink-0">
              <Shield className="w-4 h-4 text-brand-600" />
            </div>
            <div className="max-w-[85%]">
              {/* Tool activity */}
              {activeTools.length > 0 && (
                <div className="mb-2 space-y-1">
                  {activeTools.map((tool, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs text-gray-500 bg-purple-50 px-3 py-1.5 rounded-lg">
                      <Wrench className="w-3 h-3 text-purple-500" />
                      <span>{tool}</span>
                    </div>
                  ))}
                </div>
              )}
              {/* Streaming content */}
              {streamingContent ? (
                <div className="bg-gray-100 rounded-2xl rounded-bl-md px-4 py-3 text-sm">
                  <div className="prose prose-sm max-w-none prose-headings:text-gray-800 prose-headings:mt-3 prose-headings:mb-2 prose-p:my-1 prose-li:my-0.5 prose-code:text-brand-700 prose-code:bg-brand-50 prose-code:px-1 prose-code:rounded prose-strong:text-gray-800">
                    <ReactMarkdown>{streamingContent}</ReactMarkdown>
                  </div>
                  <span className="inline-block w-1.5 h-4 bg-brand-500 animate-pulse ml-0.5 -mb-0.5" />
                </div>
              ) : (
                <div className="bg-gray-100 rounded-2xl rounded-bl-md px-4 py-3">
                  <div className="flex items-center gap-2 text-sm text-gray-500">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>{activeTools.length > 0 ? 'Working...' : (isLlmOnline ? 'Thinking...' : 'Analyzing...')}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggestion Chips */}
      {displaySuggestions.length > 0 && !isStreaming && (
        <div className="px-4 pb-2">
          <div className="flex flex-wrap gap-2">
            {displaySuggestions.map((action) => (
              <button
                key={action}
                onClick={() => sendMessage(action)}
                className="text-xs px-3 py-1.5 rounded-full border border-brand-200 text-brand-600 hover:bg-brand-50 transition-colors"
              >
                {action}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <form
        id="chat-form"
        onSubmit={(e) => {
          e.preventDefault()
          sendMessage()
        }}
        className="border-t px-4 py-3 flex gap-2"
      >
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about your security posture, findings, risks..."
          className="flex-1 px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          disabled={isStreaming}
        />
        <button
          type="submit"
          disabled={!input.trim() || isStreaming}
          className="px-4 py-2.5 bg-brand-600 text-white rounded-xl hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  )
}

/* ── Action Confirmation Card ── */

function ActionConfirmationCard({
  action,
  onApprove,
  onDeny,
}: {
  action: PendingAction
  onApprove: () => void
  onDeny: () => void
}) {
  if (action.status === 'executed') {
    return (
      <div className="bg-green-50 border border-green-200 rounded-lg px-4 py-3 text-sm">
        <div className="flex items-center gap-2 text-green-700 font-medium">
          <CheckCircle2 className="w-4 h-4" />
          Action Executed
        </div>
        {action.result && <p className="text-green-600 mt-1 text-xs">{action.result}</p>}
      </div>
    )
  }

  if (action.status === 'denied') {
    return (
      <div className="bg-gray-50 border border-gray-200 rounded-lg px-4 py-3 text-sm">
        <div className="flex items-center gap-2 text-gray-500">
          <XCircle className="w-4 h-4" />
          Action Cancelled
        </div>
      </div>
    )
  }

  return (
    <div className="bg-amber-50 border-2 border-amber-200 rounded-lg px-4 py-3">
      <div className="flex items-center gap-2 mb-2">
        <Wrench className="w-4 h-4 text-amber-600" />
        <span className="text-sm font-medium text-amber-800">Action Requires Approval</span>
      </div>
      <p className="text-sm text-amber-700 mb-1">{action.description}</p>
      <p className="text-xs text-amber-600 mb-3 font-mono">
        {action.tool}({JSON.stringify(action.args).slice(0, 80)})
      </p>
      <div className="flex gap-2">
        <button
          onClick={onApprove}
          className="px-3 py-1.5 bg-amber-600 text-white rounded-lg text-xs font-medium hover:bg-amber-700"
        >
          Approve
        </button>
        <button
          onClick={onDeny}
          className="px-3 py-1.5 bg-white border border-gray-300 text-gray-600 rounded-lg text-xs font-medium hover:bg-gray-50"
        >
          Deny
        </button>
      </div>
    </div>
  )
}
