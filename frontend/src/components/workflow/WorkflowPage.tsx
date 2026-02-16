import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { useRunStore } from '../../stores/runStore'
import type { AuditEvent } from '../../types'
import {
  Play, Pause, Square, CheckCircle2, Circle, Loader2,
  AlertTriangle, FileText, Clock, XCircle, ArrowRight,
  Activity, Terminal, ChevronRight
} from 'lucide-react'

/* ─── constants ─── */

const STEPS = [
  { key: 'discovery', label: 'Asset Discovery', description: 'Scan network for devices' },
  { key: 'fingerprinting', label: 'Fingerprinting', description: 'Identify services and OS' },
  { key: 'threat_modeling', label: 'Threat Modeling', description: 'Identify potential threats' },
  { key: 'vuln_scanning', label: 'Vulnerability Scanning', description: 'Check for vulnerabilities' },
  { key: 'exploit_analysis', label: 'Exploit Analysis', description: 'Assess exploitability' },
  { key: 'mitre_mapping', label: 'MITRE Mapping', description: 'Map to ATT&CK techniques' },
  { key: 'risk_analysis', label: 'Risk Analysis', description: 'Calculate risk levels' },
  { key: 'baseline', label: 'Baseline Snapshot', description: 'Create drift detection baseline' },
]

const STEP_LABELS: Record<string, string> = Object.fromEntries([
  ['pipeline', 'Pipeline'],
  ...STEPS.map(s => [s.key, s.label]),
])

/* ─── helpers ─── */

function formatSummary(event: AuditEvent): string | null {
  const v = event.new_value
  if (!v) return null
  const step = v.step as string
  const action = event.action

  if (action === 'started' && step === 'pipeline') return `Scanning ${v.subnet || 'network'}`
  if (action === 'started') return 'Running...'
  if (action === 'failed') return `Error: ${v.error || 'unknown'}`
  if (action !== 'completed') return null

  if (step === 'pipeline') return `All ${v.total_steps} steps completed successfully`
  if (step === 'discovery') return `Found ${v.assets_found ?? '?'} assets on ${v.subnet || 'network'}`
  if (step === 'fingerprinting') return `Fingerprinted ${v.assets_fingerprinted ?? '?'} assets`
  if (step === 'threat_modeling') return `Identified ${v.threats_identified ?? '?'} threats`
  if (step === 'vuln_scanning') return `Discovered ${v.findings_found ?? '?'} findings`
  if (step === 'exploit_analysis') return `Enriched ${v.findings_enriched ?? '?'} findings`
  if (step === 'mitre_mapping') return `Mapped ${v.techniques_mapped ?? '?'} ATT&CK techniques`
  if (step === 'risk_analysis') return `Assessed ${v.risks_assessed ?? '?'} risks`
  if (step === 'baseline') return 'Baseline snapshot created'
  return null
}

function LogIcon({ action }: { action: string }) {
  if (action === 'completed') return <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0" />
  if (action === 'started') return <ChevronRight className="w-4 h-4 text-blue-500 shrink-0" />
  if (action === 'failed') return <XCircle className="w-4 h-4 text-red-500 shrink-0" />
  return <Circle className="w-4 h-4 text-gray-400 shrink-0" />
}

/* ─── main component ─── */

export default function WorkflowPage() {
  const {
    runs, activeRun, actionLog, loading, polling, error,
    fetchRuns, createRun, pauseRun, resumeRun, cancelRun, stopPolling,
  } = useRunStore()
  const [subnet, setSubnet] = useState('192.168.178.0/24')
  const navigate = useNavigate()
  const logEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchRuns()
    return () => { stopPolling() }
  }, [])

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [actionLog.length])

  const handleNewRun = async () => {
    await createRun({ scope: { subnets: [subnet] } })
  }

  const getStepStatus = (stepKey: string) => {
    if (!activeRun) return 'pending'
    if (activeRun.steps_completed?.includes(stepKey)) return 'completed'
    if (activeRun.current_step === stepKey && activeRun.status === 'running') return 'active'
    if (activeRun.current_step === stepKey && activeRun.status === 'failed') return 'failed'
    return 'pending'
  }

  const isRunning = activeRun && ['running', 'pending'].includes(activeRun.status)
  const completedCount = activeRun?.steps_completed?.length || 0
  const progressPct = (completedCount / STEPS.length) * 100

  return (
    <div>
      <PageHeader
        title="Workflow Runner"
        description="Execute and monitor assessment workflows"
        actions={
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={subnet}
              onChange={(e) => setSubnet(e.target.value)}
              placeholder="192.168.178.0/24"
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm w-44"
              disabled={!!isRunning}
            />
            <button
              onClick={handleNewRun}
              disabled={loading || !!isRunning}
              className="btn-primary flex items-center gap-2"
            >
              <Play className="w-4 h-4" />
              {loading ? 'Starting...' : 'New Assessment Run'}
            </button>
          </div>
        }
      />

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {/* ── Status bar ── */}
      {activeRun && (
        <div className="card p-4 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-500">Run</span>
                <span className="font-mono text-sm font-medium">{activeRun.id.slice(0, 8)}</span>
              </div>
              <Badge variant={
                activeRun.status === 'completed' ? 'success' :
                activeRun.status === 'failed' ? 'critical' :
                activeRun.status === 'running' ? 'info' : 'info'
              }>
                {activeRun.status === 'running' && <Loader2 className="w-3 h-3 animate-spin mr-1 inline" />}
                {activeRun.status}
              </Badge>
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-500">{completedCount}/{STEPS.length} steps</span>
                <div className="w-32 bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-brand-500 h-2 rounded-full transition-all duration-500"
                    style={{ width: `${progressPct}%` }}
                  />
                </div>
              </div>
              {polling && (
                <span className="text-xs text-brand-500 flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" /> Live
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {activeRun.status === 'running' && (
                <button onClick={() => pauseRun(activeRun.id)} className="btn-secondary flex items-center gap-1 text-sm py-1.5 px-3">
                  <Pause className="w-3.5 h-3.5" /> Pause
                </button>
              )}
              {activeRun.status === 'paused' && (
                <button onClick={() => resumeRun(activeRun.id)} className="btn-primary flex items-center gap-1 text-sm py-1.5 px-3">
                  <Play className="w-3.5 h-3.5" /> Resume
                </button>
              )}
              {['running', 'paused'].includes(activeRun.status) && (
                <button onClick={() => cancelRun(activeRun.id)} className="btn-danger flex items-center gap-1 text-sm py-1.5 px-3">
                  <Square className="w-3.5 h-3.5" /> Cancel
                </button>
              )}
              {activeRun.status === 'completed' && (
                <button
                  onClick={() => navigate('/reports')}
                  className="btn-primary flex items-center gap-2 text-sm py-1.5 px-4"
                >
                  <FileText className="w-4 h-4" /> Generate Report
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Main two-panel layout ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* ── Left: Workflow Steps ── */}
        <div className="card p-6">
          <h3 className="font-semibold mb-6">Workflow Steps</h3>
          <div className="space-y-1">
            {STEPS.map((step, idx) => {
              const status = getStepStatus(step.key)
              return (
                <div key={step.key} className="flex items-start gap-3">
                  <div className="flex flex-col items-center">
                    {status === 'completed' ? (
                      <CheckCircle2 className="w-7 h-7 text-green-500" />
                    ) : status === 'active' ? (
                      <Loader2 className="w-7 h-7 text-brand-500 animate-spin" />
                    ) : status === 'failed' ? (
                      <AlertTriangle className="w-7 h-7 text-red-500" />
                    ) : (
                      <Circle className="w-7 h-7 text-gray-300" />
                    )}
                    {idx < STEPS.length - 1 && (
                      <div className={`w-0.5 h-6 mt-1 ${status === 'completed' ? 'bg-green-300' : 'bg-gray-200'}`} />
                    )}
                  </div>
                  <div className="flex-1 pt-0.5 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{step.label}</span>
                      {status === 'active' && <Badge variant="info">Running</Badge>}
                      {status === 'completed' && <Badge variant="success">Done</Badge>}
                      {status === 'failed' && <Badge variant="critical">Failed</Badge>}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5">{step.description}</p>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Recent Runs */}
          {runs.length > 0 && (
            <div className="mt-6 pt-4 border-t border-gray-200">
              <h4 className="text-sm font-semibold text-gray-600 mb-3">Recent Runs</h4>
              <div className="space-y-2">
                {runs.slice(0, 4).map((run) => (
                  <div key={run.id} className="flex items-center justify-between py-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-gray-500">{run.id.slice(0, 8)}</span>
                      <span className="text-xs text-gray-400">{run.triggered_by}</span>
                    </div>
                    <Badge variant={run.status === 'completed' ? 'success' : run.status === 'failed' ? 'critical' : 'info'}>
                      {run.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Right: Action Log ── */}
        <div className="card p-6 flex flex-col" style={{ minHeight: '500px' }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <Terminal className="w-4 h-4" /> Action Log
            </h3>
            {polling && (
              <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> Live
              </span>
            )}
          </div>

          <div className="flex-1 overflow-y-auto bg-gray-50 rounded-lg border border-gray-200 p-3">
            {actionLog.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-400 py-16">
                <Activity className="w-10 h-10 mb-3 opacity-40" />
                <p className="text-sm font-medium">
                  {isRunning ? 'Waiting for step events...' : 'No activity yet'}
                </p>
                <p className="text-xs mt-1">
                  {activeRun ? 'Events will appear here as steps execute' : 'Start an assessment run to see the action log'}
                </p>
              </div>
            ) : (
              <div className="space-y-0">
                {actionLog.map((event, idx) => {
                  const stepName = event.new_value?.step as string || 'unknown'
                  const label = STEP_LABELS[stepName] || stepName
                  const summary = formatSummary(event)
                  const time = new Date(event.timestamp).toLocaleTimeString()

                  return (
                    <div
                      key={event.id}
                      className={`flex gap-3 items-start py-2.5 px-2 rounded ${
                        idx % 2 === 0 ? 'bg-white' : ''
                      }`}
                    >
                      <LogIcon action={event.action} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium">{label}</span>
                          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                            event.action === 'completed' ? 'bg-green-100 text-green-700' :
                            event.action === 'started' ? 'bg-blue-100 text-blue-700' :
                            event.action === 'failed' ? 'bg-red-100 text-red-700' :
                            'bg-gray-100 text-gray-600'
                          }`}>
                            {event.action}
                          </span>
                        </div>
                        {summary && (
                          <p className="text-xs text-gray-600 mt-0.5">{summary}</p>
                        )}
                      </div>
                      <span className="text-xs text-gray-400 whitespace-nowrap flex items-center gap-1 shrink-0">
                        <Clock className="w-3 h-3" /> {time}
                      </span>
                    </div>
                  )
                })}
                <div ref={logEndRef} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
