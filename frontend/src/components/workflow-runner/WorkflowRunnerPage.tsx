import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Badge from '../common/Badge'
import { useRunStore } from '../../stores/runStore'
import type { AuditEvent } from '../../types'
import {
  Play, Pause, Square, CheckCircle2, Circle, Loader2,
  AlertTriangle, FileText, Clock, XCircle, ChevronRight,
  Activity, Terminal, Zap
} from 'lucide-react'

/* ── Pipeline step definitions ── */

const STEPS = [
  { key: 'discovery', label: 'Asset Discovery', desc: 'Scan network for devices' },
  { key: 'fingerprinting', label: 'Fingerprinting', desc: 'Identify services & OS' },
  { key: 'threat_modeling', label: 'Threat Modeling', desc: 'Identify potential threats' },
  { key: 'vuln_scanning', label: 'Vuln Scanning', desc: 'Check for vulnerabilities' },
  { key: 'exploit_analysis', label: 'Exploit Analysis', desc: 'Assess exploitability' },
  { key: 'mitre_mapping', label: 'MITRE Mapping', desc: 'Map to ATT&CK techniques' },
  { key: 'risk_analysis', label: 'Risk Analysis', desc: 'Calculate risk levels' },
  { key: 'baseline', label: 'Baseline Snapshot', desc: 'Create drift baseline' },
]

const LABELS: Record<string, string> = {
  pipeline: 'Pipeline',
  discovery: 'Asset Discovery',
  fingerprinting: 'Fingerprinting',
  threat_modeling: 'Threat Modeling',
  vuln_scanning: 'Vuln Scanning',
  exploit_analysis: 'Exploit Analysis',
  mitre_mapping: 'MITRE Mapping',
  risk_analysis: 'Risk Analysis',
  baseline: 'Baseline Snapshot',
}

/* ── Event summary helper ── */

function summarize(ev: AuditEvent): string | null {
  const v = ev.new_value
  if (!v) return null
  const s = v.step as string
  if (ev.action === 'started' && s === 'pipeline') return `Scanning ${v.subnet || 'network'}`
  if (ev.action === 'started') return 'In progress...'
  if (ev.action === 'failed') return `Error: ${v.error || 'unknown'}`
  if (ev.action !== 'completed') return null
  const m: Record<string, string> = {
    pipeline: `All ${v.total_steps} steps done`,
    discovery: `${v.assets_found ?? '?'} assets found`,
    fingerprinting: `${v.assets_fingerprinted ?? '?'} fingerprinted`,
    threat_modeling: `${v.threats_identified ?? '?'} threats`,
    vuln_scanning: `${v.findings_found ?? '?'} findings`,
    exploit_analysis: `${v.findings_enriched ?? '?'} enriched`,
    mitre_mapping: `${v.techniques_mapped ?? '?'} techniques`,
    risk_analysis: `${v.risks_assessed ?? '?'} risks`,
    baseline: 'Snapshot created',
  }
  return m[s] || null
}

/* ── Main page component ── */

export default function WorkflowRunnerPage() {
  const {
    runs, activeRun, actionLog, loading, polling, error,
    fetchRuns, createRun, pauseRun, resumeRun, cancelRun, stopPolling,
  } = useRunStore()
  const [subnet, setSubnet] = useState('192.168.178.0/24')
  const navigate = useNavigate()
  const logEnd = useRef<HTMLDivElement>(null)

  useEffect(() => { fetchRuns(); return () => { stopPolling() } }, [])
  useEffect(() => { logEnd.current?.scrollIntoView({ behavior: 'smooth' }) }, [actionLog.length])

  const isRunning = activeRun && ['running', 'pending'].includes(activeRun.status)
  const done = activeRun?.steps_completed?.length || 0
  const pct = Math.round((done / STEPS.length) * 100)

  const stepStatus = (key: string) => {
    if (!activeRun) return 'pending'
    if (activeRun.steps_completed?.includes(key)) return 'done'
    if (activeRun.current_step === key && activeRun.status === 'running') return 'active'
    if (activeRun.current_step === key && activeRun.status === 'failed') return 'failed'
    return 'pending'
  }

  return (
    <div className="space-y-6">
      {/* ── Page header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Workflow Runner</h1>
          <p className="mt-1 text-sm text-gray-500">Execute and monitor assessment pipelines</p>
        </div>
        <div className="flex items-center gap-3">
          <input
            type="text"
            value={subnet}
            onChange={e => setSubnet(e.target.value)}
            placeholder="192.168.178.0/24"
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm w-44 focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
            disabled={!!isRunning}
          />
          <button
            onClick={() => createRun({ scope: { subnets: [subnet] } })}
            disabled={loading || !!isRunning}
            className="btn-primary flex items-center gap-2"
          >
            <Play className="w-4 h-4" />
            {loading ? 'Starting...' : 'New Run'}
          </button>
        </div>
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {/* ── Active run status bar ── */}
      {activeRun && (
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-5">
              <div className="flex items-center gap-2 text-sm">
                <Zap className="w-4 h-4 text-brand-500" />
                <span className="text-gray-500">Run</span>
                <code className="font-mono font-bold text-gray-800">{activeRun.id.slice(0, 8)}</code>
              </div>
              <Badge variant={
                activeRun.status === 'completed' ? 'success' :
                activeRun.status === 'failed' ? 'critical' : 'info'
              }>
                {activeRun.status === 'running' && (
                  <Loader2 className="w-3 h-3 animate-spin inline mr-1" />
                )}
                {activeRun.status}
              </Badge>
              {done > 0 && (
                <div className="flex items-center gap-2">
                  <div className="w-28 bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-brand-500 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-500 font-medium">{done}/{STEPS.length}</span>
                </div>
              )}
              {polling && (
                <span className="inline-flex items-center gap-1.5 text-xs text-green-700 bg-green-50 border border-green-200 px-2 py-0.5 rounded-full">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                  Live
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {activeRun.status === 'running' && (
                <button onClick={() => pauseRun(activeRun.id)} className="btn-secondary text-sm py-1.5 px-3 flex items-center gap-1">
                  <Pause className="w-3.5 h-3.5" /> Pause
                </button>
              )}
              {activeRun.status === 'paused' && (
                <button onClick={() => resumeRun(activeRun.id)} className="btn-primary text-sm py-1.5 px-3 flex items-center gap-1">
                  <Play className="w-3.5 h-3.5" /> Resume
                </button>
              )}
              {['running', 'paused'].includes(activeRun.status) && (
                <button onClick={() => cancelRun(activeRun.id)} className="btn-danger text-sm py-1.5 px-3 flex items-center gap-1">
                  <Square className="w-3.5 h-3.5" /> Cancel
                </button>
              )}
              {activeRun.status === 'completed' && (
                <button onClick={() => navigate('/reports')} className="btn-primary text-sm py-1.5 px-4 flex items-center gap-2">
                  <FileText className="w-4 h-4" /> Generate Report
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ══════ Two-column layout ══════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ minHeight: 520 }}>

        {/* ── LEFT: Pipeline Steps ── */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6">
          <h3 className="text-base font-semibold mb-5 flex items-center gap-2">
            <Zap className="w-4 h-4 text-brand-500" />
            Pipeline Steps
          </h3>
          <ol className="space-y-0">
            {STEPS.map((step, i) => {
              const st = stepStatus(step.key)
              return (
                <li key={step.key} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-bold shrink-0 ${
                      st === 'done' ? 'bg-green-500' :
                      st === 'active' ? 'bg-brand-500 animate-pulse' :
                      st === 'failed' ? 'bg-red-500' :
                      'bg-gray-300'
                    }`}>
                      {st === 'done' ? <CheckCircle2 className="w-4 h-4" /> :
                       st === 'active' ? <Loader2 className="w-4 h-4 animate-spin" /> :
                       st === 'failed' ? <XCircle className="w-4 h-4" /> :
                       <span>{i + 1}</span>}
                    </div>
                    {i < STEPS.length - 1 && (
                      <div className={`w-0.5 flex-1 my-1 ${st === 'done' ? 'bg-green-400' : 'bg-gray-200'}`} />
                    )}
                  </div>
                  <div className="pt-1 pb-4 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-medium ${st === 'pending' ? 'text-gray-400' : 'text-gray-900'}`}>
                        {step.label}
                      </span>
                      {st === 'active' && <Badge variant="info">Running</Badge>}
                      {st === 'done' && <Badge variant="success">Done</Badge>}
                      {st === 'failed' && <Badge variant="critical">Failed</Badge>}
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">{step.desc}</p>
                  </div>
                </li>
              )
            })}
          </ol>

          {/* Run history */}
          {runs.length > 0 && (
            <div className="mt-5 pt-4 border-t border-gray-100">
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Run History</h4>
              <div className="space-y-1.5">
                {runs.slice(0, 5).map(r => (
                  <div key={r.id} className="flex items-center justify-between py-1.5 px-2 rounded-lg hover:bg-gray-50">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-mono text-gray-500">{r.id.slice(0, 8)}</code>
                      <span className="text-xs text-gray-400">{r.triggered_by}</span>
                    </div>
                    <Badge variant={r.status === 'completed' ? 'success' : r.status === 'failed' ? 'critical' : 'info'}>
                      {r.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── RIGHT: Action Log ── */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm flex flex-col">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between shrink-0">
            <h3 className="text-base font-semibold flex items-center gap-2">
              <Terminal className="w-4 h-4 text-gray-500" />
              Action Log
            </h3>
            {polling && (
              <span className="inline-flex items-center gap-1.5 text-xs text-green-700 bg-green-50 border border-green-200 px-2 py-0.5 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                Live
              </span>
            )}
          </div>

          <div className="flex-1 overflow-y-auto p-4 bg-gray-50/50" style={{ maxHeight: 520 }}>
            {actionLog.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-gray-300 py-20">
                <Activity className="w-12 h-12 mb-3" />
                <p className="text-sm font-medium text-gray-400">
                  {isRunning ? 'Waiting for events...' : 'No activity yet'}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  {activeRun ? 'Events stream here in real-time' : 'Start an assessment run to see the action log'}
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                {actionLog.map((ev, i) => {
                  const name = LABELS[ev.new_value?.step as string] || (ev.new_value?.step as string) || '?'
                  const info = summarize(ev)
                  const t = new Date(ev.timestamp).toLocaleTimeString()
                  const actionColors: Record<string, string> = {
                    completed: 'bg-green-100 text-green-700',
                    started: 'bg-blue-100 text-blue-700',
                    failed: 'bg-red-100 text-red-700',
                  }
                  const actionIcons: Record<string, React.ReactNode> = {
                    completed: <CheckCircle2 className="w-4 h-4 text-green-500" />,
                    started: <ChevronRight className="w-4 h-4 text-blue-500" />,
                    failed: <XCircle className="w-4 h-4 text-red-500" />,
                  }
                  return (
                    <div key={ev.id} className={`flex items-start gap-3 p-2.5 rounded-lg ${i % 2 === 0 ? 'bg-white' : ''}`}>
                      <div className="mt-0.5 shrink-0">
                        {actionIcons[ev.action] || <Circle className="w-4 h-4 text-gray-300" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium text-gray-800">{name}</span>
                          <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${actionColors[ev.action] || 'bg-gray-100 text-gray-500'}`}>
                            {ev.action}
                          </span>
                        </div>
                        {info && <p className="text-xs text-gray-500 mt-0.5">{info}</p>}
                      </div>
                      <span className="text-xs text-gray-400 whitespace-nowrap shrink-0 flex items-center gap-1 mt-0.5">
                        <Clock className="w-3 h-3" />{t}
                      </span>
                    </div>
                  )
                })}
                <div ref={logEnd} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
