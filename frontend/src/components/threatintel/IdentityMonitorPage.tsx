import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useIdentityMonitorStore } from '../../stores/identityMonitorStore'
import type { MonitoredIdentity, BreachHit } from '../../stores/identityMonitorStore'
import Badge from '../common/Badge'
import {
  ChevronLeft, Plus, Trash2, RefreshCw, Search, Shield,
  AlertTriangle, Eye, EyeOff, Key, Loader2, CheckCircle2,
  XCircle, Mail, Clock, ChevronDown, ChevronUp, Lock,
  Copy, ExternalLink,
} from 'lucide-react'

function timeAgo(ts: string | null): string {
  if (!ts) return 'Never'
  const diff = Date.now() - new Date(ts).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

async function sha1(input: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(input)
  const hashBuffer = await crypto.subtle.digest('SHA-1', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

export default function IdentityMonitorPage() {
  const {
    identities, selectedBreaches, summary, passwordResult,
    loading, checking, error,
    fetchIdentities, addIdentity, deleteIdentity, fetchBreaches,
    checkAll, checkSingle, fetchSummary, checkPassword, clearPasswordResult,
  } = useIdentityMonitorStore()

  const [newEmail, setNewEmail] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [passwordInput, setPasswordInput] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [passwordChecking, setPasswordChecking] = useState(false)

  useEffect(() => { fetchIdentities(); fetchSummary() }, [])

  const handleAddIdentity = async () => {
    if (!newEmail.trim()) return
    await addIdentity(newEmail.trim(), newLabel.trim() || undefined)
    setNewEmail('')
    setNewLabel('')
  }

  const handleExpand = async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null)
      return
    }
    setExpandedId(id)
    await fetchBreaches(id)
  }

  const handlePasswordCheck = async () => {
    if (!passwordInput) return
    setPasswordChecking(true)
    const hash = await sha1(passwordInput)
    await checkPassword(hash)
    setPasswordInput('')
    setShowPassword(false)
    setPasswordChecking(false)
  }

  const copyBreachList = (identity: MonitoredIdentity) => {
    const breachNames = selectedBreaches.map(b => b.breach_name).join(', ')
    navigator.clipboard.writeText(`${identity.email}: ${breachNames}`)
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/intel" className="text-gray-400 hover:text-gray-600"><ChevronLeft className="w-5 h-5" /></Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Identity Monitor</h1>
            <p className="text-sm text-gray-500">Breach exposure monitoring for email addresses via HIBP</p>
          </div>
        </div>
        <button
          onClick={checkAll}
          disabled={checking || identities.length === 0}
          className="btn-primary flex items-center gap-2 text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} />
          {checking ? 'Checking...' : 'Check All'}
        </button>
      </div>

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <SummaryCard label="Monitored" value={summary.total_identities} color="blue" icon={<Mail className="w-4 h-4" />} />
          <SummaryCard label="Exposed" value={summary.exposed_identities} color={summary.exposed_identities > 0 ? 'red' : 'green'} icon={<AlertTriangle className="w-4 h-4" />} />
          <SummaryCard label="Total Breaches" value={summary.total_breaches} color="gray" icon={<Shield className="w-4 h-4" />} />
          <SummaryCard label="Critical" value={summary.critical_breaches} color={summary.critical_breaches > 0 ? 'red' : 'gray'} icon={<XCircle className="w-4 h-4" />} />
          <SummaryCard label="High" value={summary.high_breaches} color={summary.high_breaches > 0 ? 'orange' : 'gray'} icon={<AlertTriangle className="w-4 h-4" />} />
        </div>
      )}

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* LEFT: Identity list (2/3 width) */}
        <div className="lg:col-span-2 space-y-4">
          {/* Add identity form */}
          <div className="bg-white border border-gray-200 rounded-xl p-4">
            <div className="flex items-end gap-3">
              <div className="flex-1">
                <label className="block text-xs font-medium text-gray-500 mb-1">Email address</label>
                <input
                  type="email"
                  value={newEmail}
                  onChange={e => setNewEmail(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleAddIdentity()}
                  placeholder="user@company.de"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                />
              </div>
              <div className="w-40">
                <label className="block text-xs font-medium text-gray-500 mb-1">Label (optional)</label>
                <input
                  type="text"
                  value={newLabel}
                  onChange={e => setNewLabel(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleAddIdentity()}
                  placeholder="e.g. CTO, Admin"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                />
              </div>
              <button
                onClick={handleAddIdentity}
                disabled={!newEmail.trim()}
                className="btn-primary flex items-center gap-1.5 text-sm py-2"
              >
                <Plus className="w-4 h-4" /> Add
              </button>
            </div>
          </div>

          {/* Identity list */}
          <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
            {loading && identities.length === 0 ? (
              <div className="flex items-center justify-center py-16 text-gray-400">
                <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading...
              </div>
            ) : identities.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-gray-400">
                <Mail className="w-10 h-10 mb-2" />
                <p className="text-sm font-medium">No emails monitored yet</p>
                <p className="text-xs mt-1">Add email addresses above to start monitoring</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-100">
                {identities.map(identity => (
                  <div key={identity.id}>
                    {/* Identity row */}
                    <div className="flex items-center gap-4 px-5 py-3 hover:bg-gray-50">
                      <button onClick={() => handleExpand(identity.id)} className="shrink-0">
                        {expandedId === identity.id
                          ? <ChevronUp className="w-4 h-4 text-gray-400" />
                          : <ChevronDown className="w-4 h-4 text-gray-400" />}
                      </button>
                      {/* Status icon */}
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                        identity.breach_count === 0 ? 'bg-green-100' : 'bg-red-100'
                      }`}>
                        {identity.breach_count === 0
                          ? <CheckCircle2 className="w-4 h-4 text-green-600" />
                          : <AlertTriangle className="w-4 h-4 text-red-600" />}
                      </div>
                      {/* Email */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-gray-800">{identity.email}</span>
                          {identity.label && (
                            <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-gray-100 text-gray-500">{identity.label}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-xs text-gray-400 mt-0.5">
                          <span>Checked: {timeAgo(identity.last_checked)}</span>
                          {identity.breach_count > 0 && (
                            <span className="text-red-500 font-medium">{identity.breach_count} breach{identity.breach_count !== 1 ? 'es' : ''}</span>
                          )}
                        </div>
                      </div>
                      {/* Actions */}
                      <button
                        onClick={() => checkSingle(identity.id)}
                        disabled={checking}
                        className="btn-secondary text-xs py-1 px-2 flex items-center gap-1"
                        title="Check now"
                      >
                        <RefreshCw className={`w-3 h-3 ${checking ? 'animate-spin' : ''}`} />
                      </button>
                      <button
                        onClick={() => deleteIdentity(identity.id)}
                        className="text-gray-400 hover:text-red-500 p-1"
                        title="Remove"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>

                    {/* Expanded breach list */}
                    {expandedId === identity.id && (
                      <div className="bg-gray-50/70 border-t border-gray-100 px-5 py-3">
                        {selectedBreaches.length === 0 ? (
                          <div className="text-center py-6 text-xs text-gray-400">
                            {identity.breach_count === 0
                              ? 'No breaches found for this email'
                              : 'Loading breaches...'}
                          </div>
                        ) : (
                          <div className="space-y-2">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                                Breaches ({selectedBreaches.length})
                              </span>
                              <button
                                onClick={() => copyBreachList(identity)}
                                className="text-xs text-gray-400 hover:text-gray-600 flex items-center gap-1"
                              >
                                <Copy className="w-3 h-3" /> Copy
                              </button>
                            </div>
                            {selectedBreaches.map(breach => (
                              <BreachCard key={breach.id} breach={breach} />
                            ))}
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

        {/* RIGHT: Password check (1/3 width) */}
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-5">
            <h3 className="text-base font-semibold flex items-center gap-2 mb-4">
              <Key className="w-4 h-4 text-amber-500" /> Password Check
            </h3>
            <p className="text-xs text-gray-500 mb-4">
              Check if a password appears in known breaches.
              The password is SHA-1 hashed <strong>in your browser</strong> — only the first 5 characters of the hash are sent to HIBP (k-anonymity).
              The actual password never leaves your device.
            </p>
            <div className="space-y-3">
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={passwordInput}
                  onChange={e => { setPasswordInput(e.target.value); clearPasswordResult() }}
                  onKeyDown={e => e.key === 'Enter' && handlePasswordCheck()}
                  placeholder="Enter password to check..."
                  className="w-full pl-9 pr-10 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                />
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <button
                onClick={handlePasswordCheck}
                disabled={!passwordInput || passwordChecking}
                className="btn-primary w-full flex items-center justify-center gap-2 text-sm"
              >
                {passwordChecking ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                {passwordChecking ? 'Checking...' : 'Check Password'}
              </button>
            </div>

            {passwordResult && (
              <div className={`mt-4 p-4 rounded-lg border ${
                passwordResult.is_compromised
                  ? 'bg-red-50 border-red-200'
                  : 'bg-green-50 border-green-200'
              }`}>
                {passwordResult.is_compromised ? (
                  <>
                    <div className="flex items-center gap-2 mb-1">
                      <XCircle className="w-5 h-5 text-red-500" />
                      <span className="text-sm font-bold text-red-700">Compromised!</span>
                    </div>
                    <p className="text-xs text-red-600">
                      This password has been seen <strong>{passwordResult.occurrence_count.toLocaleString()}</strong> times
                      in data breaches. Do NOT use this password.
                    </p>
                  </>
                ) : (
                  <>
                    <div className="flex items-center gap-2 mb-1">
                      <CheckCircle2 className="w-5 h-5 text-green-500" />
                      <span className="text-sm font-bold text-green-700">Not found</span>
                    </div>
                    <p className="text-xs text-green-600">
                      This password has not been found in any known breach database.
                    </p>
                  </>
                )}
              </div>
            )}

            <div className="mt-4 pt-3 border-t border-gray-100">
              <p className="text-[10px] text-gray-400 leading-relaxed">
                <strong>Privacy:</strong> Uses HIBP k-anonymity protocol.
                Your password is SHA-1 hashed locally in the browser.
                Only the first 5 characters of the 40-character hash are sent to the API.
                The full password or hash is never transmitted.
                <a href="https://haveibeenpwned.com/API/v3#PwnedPasswords" target="_blank" rel="noopener noreferrer" className="text-brand-500 hover:text-brand-600 ml-1 inline-flex items-center gap-0.5">
                  Learn more <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </p>
            </div>
          </div>

          {/* Provenance panel */}
          <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-5">
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Data Source</h3>
            <div className="space-y-2 text-xs text-gray-500">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-purple-100 text-purple-700">HIBP</span>
                <span>Have I Been Pwned by Troy Hunt</span>
              </div>
              <p>Covers 700+ verified data breaches and 900M+ compromised passwords.</p>
              <a href="https://haveibeenpwned.com/" target="_blank" rel="noopener noreferrer" className="text-brand-500 hover:text-brand-600 flex items-center gap-1">
                haveibeenpwned.com <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Breach card subcomponent ── */
function BreachCard({ breach }: { breach: BreachHit }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-3">
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-2">
          <Badge variant={
            breach.severity === 'critical' ? 'critical' :
            breach.severity === 'high' ? 'high' :
            breach.severity === 'medium' ? 'medium' : 'low'
          }>
            {breach.severity}
          </Badge>
          <span className="text-sm font-semibold text-gray-800">{breach.breach_title || breach.breach_name}</span>
          {breach.is_verified && (
            <span className="text-[10px] font-medium px-1 py-0.5 rounded bg-blue-50 text-blue-600">Verified</span>
          )}
          {breach.is_sensitive && (
            <span className="text-[10px] font-medium px-1 py-0.5 rounded bg-red-50 text-red-600">Sensitive</span>
          )}
        </div>
        <span className="text-xs text-gray-400">
          {breach.breach_date ? new Date(breach.breach_date).toLocaleDateString() : '—'}
        </span>
      </div>
      {/* Data classes */}
      {breach.data_classes && breach.data_classes.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {breach.data_classes.map(dc => {
            const isDangerous = ['Passwords', 'Credit cards', 'Bank account numbers', 'Social security numbers'].includes(dc)
            const isWarning = ['Password hints', 'Security questions and answers', 'Auth tokens'].includes(dc)
            return (
              <span
                key={dc}
                className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                  isDangerous ? 'bg-red-100 text-red-700' :
                  isWarning ? 'bg-orange-100 text-orange-700' :
                  'bg-gray-100 text-gray-600'
                }`}
              >
                {dc}
              </span>
            )
          })}
        </div>
      )}
      <div className="flex items-center gap-3 mt-2 text-xs text-gray-400">
        {breach.breach_domain && <span>{breach.breach_domain}</span>}
        <span className="text-[10px] font-bold px-1 py-0.5 rounded bg-purple-50 text-purple-600">{breach.source}</span>
      </div>
    </div>
  )
}

/* ── Summary card subcomponent ── */
function SummaryCard({ label, value, color, icon }: {
  label: string; value: number; color: string; icon: React.ReactNode
}) {
  const colorMap: Record<string, string> = {
    red: 'bg-red-50 text-red-600 border-red-100',
    orange: 'bg-orange-50 text-orange-600 border-orange-100',
    blue: 'bg-blue-50 text-blue-600 border-blue-100',
    green: 'bg-green-50 text-green-600 border-green-100',
    gray: 'bg-gray-50 text-gray-600 border-gray-100',
  }
  return (
    <div className={`flex flex-col items-center p-3 rounded-xl border ${colorMap[color] || colorMap.gray}`}>
      <div className="opacity-70 mb-1">{icon}</div>
      <span className="text-2xl font-bold">{value}</span>
      <span className="text-[10px] font-medium opacity-70 mt-0.5">{label}</span>
    </div>
  )
}
