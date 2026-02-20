import { useState, useRef, useEffect } from 'react'
import { Send, Loader2, Shield, User, Trash2 } from 'lucide-react'
import { copilotApi } from '../../api/endpoints'
import ReactMarkdown from 'react-markdown'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  timestamp?: string
  actions?: string[]
}

export default function AgentChat() {
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
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const sendMessage = async () => {
    const trimmed = input.trim()
    if (!trimmed || loading) return

    const userMsg: ChatMessage = { role: 'user', content: trimmed, timestamp: new Date().toISOString() }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const conversation = messages.map((m) => ({ role: m.role, content: m.content }))
      const res = await copilotApi.chat(trimmed, conversation)
      const assistantMsg: ChatMessage = {
        role: 'assistant',
        content: res.data.content || 'No response generated.',
        timestamp: res.data.timestamp,
        actions: res.data.actions,
      }
      setMessages((prev) => [...prev, assistantMsg])
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `Error: ${err.response?.data?.detail || err.message || 'Failed to get response'}`,
          timestamp: new Date().toISOString(),
        },
      ])
    }
    setLoading(false)
    inputRef.current?.focus()
  }

  const clearChat = () => {
    setMessages([
      {
        role: 'assistant',
        content: 'Chat cleared. How can I help you with your security assessment?',
        timestamp: new Date().toISOString(),
      },
    ])
  }

  const quickActions = [
    'How\'s my security?',
    'Show critical findings',
    'Triage findings',
    'What are my top risks?',
    'List my assets',
    'MITRE mappings',
  ]

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
            <p className="text-xs text-gray-500">Senior IT Security Analyst</p>
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
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
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
              {msg.timestamp && (
                <p className={`text-xs mt-2 ${msg.role === 'user' ? 'text-brand-200' : 'text-gray-400'}`}>
                  {new Date(msg.timestamp).toLocaleTimeString()}
                </p>
              )}
            </div>
            {msg.role === 'user' && (
              <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center shrink-0 mt-1">
                <User className="w-4 h-4 text-gray-600" />
              </div>
            )}
          </div>
        ))}
        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-full bg-brand-100 flex items-center justify-center shrink-0">
              <Shield className="w-4 h-4 text-brand-600" />
            </div>
            <div className="bg-gray-100 rounded-2xl rounded-bl-md px-4 py-3">
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions */}
      {messages.length <= 2 && (
        <div className="px-4 pb-2">
          <div className="flex flex-wrap gap-2">
            {quickActions.map((action) => (
              <button
                key={action}
                onClick={() => {
                  setInput(action)
                  setTimeout(() => {
                    const form = document.getElementById('chat-form')
                    if (form) form.dispatchEvent(new Event('submit', { bubbles: true }))
                  }, 50)
                }}
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
          disabled={loading}
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="px-4 py-2.5 bg-brand-600 text-white rounded-xl hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  )
}
