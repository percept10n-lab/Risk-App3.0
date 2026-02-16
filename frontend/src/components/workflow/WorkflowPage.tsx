import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { useRunStore } from '../../stores/runStore'
import type { AuditEvent } from '../../types'
import { Play, Pause, Square, CheckCircle2, Circle, Loader2, AlertTriangle, FileText, Clock, XCircle, ArrowRight, Activity } from 'lucide-react'

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

const STEP_LABELS: Record<string, string> = {
  pipeline: 'Pipeline',
  discovery: 'Asset Discovery',
  fingerprinting: 'Fingerprinting',
  threat_modeling: 'Threat Modeling',
  vuln_scanning: 'Vulnerability Scanning',
  exploit_analysis: 'Exploit Analysis',
  mitre_mapping: 'MITRE Mapping',
  risk_analysis: 'Risk Analysis',
  baseline: 'Baseline Snapshot',
}

function formatSummary(event: AuditEvent): string | null {
  const v = event.new_value
  if (!v) return null
  const step = v.step as string
  const action = event.action

  if (action === 'started') {
    if (step === 'pipeline') return `Target: ${v.subnet || 'network'}`
    return null
  }
  if (action === 'failed') return `Error: ${v.error || 'unknown'}`
  if (action !== 'completed') return null

  if (step === 'pipeline') return `${v.total_steps} steps completed`
  if (step === 'discovery') return `${v.assets_found ?? '?'} assets found on ${v.subnet || 'network'}`
  if (step === 'fingerprinting') return `${v.assets_fingerprinted ?? '?'} assets fingerprinted`
  if (step === 'threat_modeling') return `${v.threats_identified ?? '?'} threats identified`
  if (step === 'vuln_scanning') return `${v.findings_found ?? '?'} findings discovered`
  if (step === 'exploit_analysis') return `${v.findings_enriched ?? '?'} findings enriched`
  if (step === 'mitre_mapping') return `${v.techniques_mapped ?? '?'} techniques mapped`
  if (step === 'risk_analysis') return `${v.risks_assessed ?? '?'} risks assessed`
  if (step === 'baseline') return 'Baseline snapshot created'
  return null
}

function LogIcon({ action }: { action: string }) {
  if (action === 'completed') return <CheckCircle2 className="w-3.5 h-3.5 text-green-500 shrink-0 mt-0.5" />
  if (action === 'started') return <ArrowRight className="w-3.5 h-3.5 text-blue-500 shrink-0 mt-0.5" />
  if (action === 'failed') return <XCircle className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
  return <Circle className="w-3.5 h-3.5 text-gray-400 shrink-0 mt-0.5" />
}

export default function WorkflowPage() {
  const { runs, activeRun, actionLog, loading, polling, error, fetchRuns, createRun, pauseRun, resumeRun, cancelRun, stopPolling } = useRunStore()
  const [subnet, setSubnet] = useState('192.168.178.0/24')
  const navigate = useNavigate()
  const logEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchRuns()
    return () => { stopPolling() }
  }, [])

  // Auto-scroll action log to bottom on new entries
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
              <Play className="w-4 h-4" /> New Assessment Run
            </button>
          </div>
        }
      />

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Workflow Steps */}
        <div className="lg:col-span-2">
          <div className="card p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-semibold">Workflow Steps</h3>
              {polling && (
                <span className="text-xs text-brand-500 flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" /> Live updating
                </span>
              )}
            </div>
            <div className="space-y-4">
              {STEPS.map((step, idx) => {
                const status = getStepStatus(step.key)
                return (
                  <div key={step.key} className="flex items-start gap-4">
                    <div className="flex flex-col items-center">
                      {status === 'completed' ? (
                        <CheckCircle2 className="w-8 h-8 text-green-500" />
                      ) : status === 'active' ? (
                        <Loader2 className="w-8 h-8 text-brand-500 animate-spin" />
                      ) : status === 'failed' ? (
                        <AlertTriangle className="w-8 h-8 text-red-500" />
                      ) : (
                        <Circle className="w-8 h-8 text-gray-300" />
                      )}
                      {idx < STEPS.length - 1 && (
                        <div className={`w-0.5 h-8 mt-1 ${status === 'completed' ? 'bg-green-300' : 'bg-gray-200'}`} />
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{step.label}</p>
                        {status === 'active' && <Badge variant="info">Running</Badge>}
                        {status === 'completed' && <Badge variant="success">Completed</Badge>}
                        {status === 'failed' && <Badge variant="critical">Failed</Badge>}
                      </div>
                      <p className="text-sm text-gray-500 mt-0.5">{step.description}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Right: Run Controls + Action Log */}
        <div className="space-y-4">
          {/* Run Controls */}
          <div className="card p-6">
            <h3 className="font-semibold mb-4">Run Controls</h3>
            {activeRun ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500">Run ID</span>
                  <span className="font-mono text-sm">{activeRun.id.slice(0, 8)}...</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500">Status</span>
                  <Badge variant={
                    activeRun.status === 'completed' ? 'success' :
                    activeRun.status === 'failed' ? 'critical' :
                    activeRun.status === 'running' ? 'info' : 'info'
                  }>
                    {activeRun.status}
                  </Badge>
                </div>
                {activeRun.steps_completed && activeRun.steps_completed.length > 0 && (
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm text-gray-500">Progress</span>
                      <span className="text-sm font-medium">{activeRun.steps_completed.length} / {STEPS.length}</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-brand-500 h-2 rounded-full transition-all duration-500"
                        style={{ width: `${(activeRun.steps_completed.length / STEPS.length) * 100}%` }}
                      />
                    </div>
                  </div>
                )}
                {['running', 'paused'].includes(activeRun.status) && (
                  <div className="flex gap-2 pt-1">
                    {activeRun.status === 'running' && (
                      <button onClick={() => pauseRun(activeRun.id)} className="btn-secondary flex items-center gap-1 text-sm">
                        <Pause className="w-3.5 h-3.5" /> Pause
                      </button>
                    )}
                    {activeRun.status === 'paused' && (
                      <button onClick={() => resumeRun(activeRun.id)} className="btn-primary flex items-center gap-1 text-sm">
                        <Play className="w-3.5 h-3.5" /> Resume
                      </button>
                    )}
                    <button onClick={() => cancelRun(activeRun.id)} className="btn-danger flex items-center gap-1 text-sm">
                      <Square className="w-3.5 h-3.5" /> Cancel
                    </button>
                  </div>
                )}
                {activeRun.status === 'completed' && (
                  <button
                    onClick={() => navigate('/reports')}
                    className="btn-primary w-full flex items-center justify-center gap-2 text-sm mt-1"
                  >
                    <FileText className="w-4 h-4" /> Generate Report
                  </button>
                )}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No active run. Enter your subnet and start a new assessment.</p>
            )}
          </div>

          {/* Action Log */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <Activity className="w-4 h-4" /> Action Log
              </h3>
              {polling && (
                <span className="text-xs text-brand-500 flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" /> Live
                </span>
              )}
            </div>
            <div className="max-h-[480px] overflow-y-auto space-y-0">
              {actionLog.length === 0 ? (
                <div className="text-center py-8">
                  <Activity className="w-8 h-8 text-gray-300 mx-auto mb-2" />
                  <p className="text-sm text-gray-500">
                    {activeRun ? 'Waiting for step events...' : 'Start a run to see the action log'}
                  </p>
                </div>
              ) : (
                actionLog.map((event, idx) => {
                  const stepName = event.new_value?.step as string || 'unknown'
                  const label = STEP_LABELS[stepName] || stepName
                  const summary = formatSummary(event)
                  const time = new Date(event.timestamp).toLocaleTimeString()
                  const isLast = idx === actionLog.length - 1

                  return (
                    <div key={event.id} className={`flex gap-3 py-2 ${idx > 0 ? 'border-t border-gray-100' : ''}`}>
                      <LogIcon action={event.action} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate">{label}</span>
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            event.action === 'completed' ? 'bg-green-100 text-green-700' :
                            event.action === 'started' ? 'bg-blue-100 text-blue-700' :
                            event.action === 'failed' ? 'bg-red-100 text-red-700' :
                            'bg-gray-100 text-gray-600'
                          }`}>
                            {event.action}
                          </span>
                        </div>
                        {summary && (
                          <p className="text-xs text-gray-500 mt-0.5">{summary}</p>
                        )}
                        <p className="text-xs text-gray-400 mt-0.5 flex items-center gap-1">
                          <Clock className="w-3 h-3" /> {time}
                        </p>
                      </div>
                    </div>
                  )
                })
              )}
              <div ref={logEndRef} />
            </div>
          </div>

          {/* Recent Runs */}
          <div className="card p-6">
            <h3 className="font-semibold mb-4">Recent Runs</h3>
            {runs.length === 0 ? (
              <p className="text-sm text-gray-500">No previous runs</p>
            ) : (
              <div className="space-y-2">
                {runs.slice(0, 5).map((run) => (
                  <div key={run.id} className="flex items-center justify-between p-2 rounded-lg hover:bg-gray-50">
                    <div>
                      <p className="text-sm font-mono">{run.id.slice(0, 8)}</p>
                      <p className="text-xs text-gray-500">{run.triggered_by}</p>
                    </div>
                    <Badge variant={run.status === 'completed' ? 'success' : run.status === 'failed' ? 'critical' : 'info'}>
                      {run.status}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
