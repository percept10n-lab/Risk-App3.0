import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import Modal from '../common/Modal'
import { useRunStore } from '../../stores/runStore'
import type { StepDetail } from '../../types'
import { Play, Pause, Square, CheckCircle2, Circle, Loader2, AlertTriangle, FileText, ChevronDown, ChevronRight } from 'lucide-react'

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

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-700 bg-red-50',
  high: 'text-orange-700 bg-orange-50',
  medium: 'text-yellow-700 bg-yellow-50',
  low: 'text-blue-700 bg-blue-50',
  info: 'text-gray-600 bg-gray-50',
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`
  const mins = Math.floor(seconds / 60)
  const secs = Math.round(seconds % 60)
  return `${mins}m ${secs}s`
}

function StepReportCard({ step }: { step: StepDetail }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 hover:bg-gray-50 text-left"
      >
        <div className="flex items-center gap-3">
          {step.status === 'completed' ? (
            <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0" />
          ) : step.status === 'failed' ? (
            <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0" />
          ) : (
            <Circle className="w-5 h-5 text-gray-300 flex-shrink-0" />
          )}
          <div>
            <p className="font-medium text-sm">{step.label}</p>
            <p className="text-xs text-gray-500">
              {step.status === 'completed'
                ? `${step.items_count} item${step.items_count !== 1 ? 's' : ''} produced`
                : step.status === 'failed' ? 'Step failed' : 'Skipped'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={step.status === 'completed' ? 'success' : step.status === 'failed' ? 'critical' : 'info'}>
            {step.status}
          </Badge>
          {step.details.length > 0 && (
            expanded ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />
          )}
        </div>
      </button>

      {expanded && step.details.length > 0 && (
        <div className="border-t bg-gray-50 p-3">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-500">
                  {Object.keys(step.details[0]).map((key) => (
                    <th key={key} className="pb-2 pr-3 font-medium capitalize">
                      {key.replace(/_/g, ' ')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {step.details.map((row, idx) => (
                  <tr key={idx} className="border-t border-gray-200">
                    {Object.entries(row).map(([key, value]) => (
                      <td key={key} className="py-1.5 pr-3">
                        {key === 'severity' || key === 'risk_level' ? (
                          <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium ${SEVERITY_COLORS[String(value)] || ''}`}>
                            {String(value)}
                          </span>
                        ) : typeof value === 'number' ? (
                          Number.isInteger(value) ? String(value) : (value as number).toFixed(2)
                        ) : (
                          String(value)
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {step.items_count > step.details.length && (
            <p className="text-xs text-gray-400 mt-2">
              Showing {step.details.length} of {step.items_count} items
            </p>
          )}
        </div>
      )}
    </div>
  )
}

export default function WorkflowPage() {
  const {
    runs, activeRun, loading, polling, error,
    report, reportLoading,
    fetchRuns, createRun, pauseRun, resumeRun, cancelRun, stopPolling,
    fetchReport, clearReport,
  } = useRunStore()
  const [subnet, setSubnet] = useState('192.168.178.0/24')
  const [reportOpen, setReportOpen] = useState(false)

  useEffect(() => {
    fetchRuns()
    return () => { stopPolling() }
  }, [])

  const handleNewRun = async () => {
    await createRun({ scope: { subnets: [subnet] } })
  }

  const handleViewReport = (runId: string) => {
    fetchReport(runId)
    setReportOpen(true)
  }

  const handleCloseReport = () => {
    setReportOpen(false)
    clearReport()
  }

  const getStepStatus = (stepKey: string) => {
    if (!activeRun) return 'pending'
    if (activeRun.steps_completed?.includes(stepKey)) return 'completed'
    if (activeRun.current_step === stepKey && activeRun.status === 'running') return 'active'
    if (activeRun.current_step === stepKey && activeRun.status === 'failed') return 'failed'
    return 'pending'
  }

  const isRunning = activeRun && ['running', 'pending'].includes(activeRun.status)
  const isFinished = activeRun && ['completed', 'failed', 'cancelled'].includes(activeRun.status)

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

            {isFinished && (
              <div className="mt-6 pt-4 border-t">
                <button
                  onClick={() => handleViewReport(activeRun.id)}
                  className="btn-primary flex items-center gap-2"
                >
                  <FileText className="w-4 h-4" /> View Completion Report
                </button>
              </div>
            )}
          </div>
        </div>

        <div>
          <div className="card p-6">
            <h3 className="font-semibold mb-4">Run Controls</h3>
            {activeRun ? (
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-500">Run ID</p>
                  <p className="font-mono text-sm">{activeRun.id.slice(0, 8)}...</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Status</p>
                  <p className="font-medium capitalize">{activeRun.status}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Current Step</p>
                  <p className="font-medium">
                    {activeRun.status === 'completed' ? 'All steps completed' :
                     activeRun.current_step || 'Initializing...'}
                  </p>
                </div>
                {activeRun.steps_completed && activeRun.steps_completed.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-500">Progress</p>
                    <p className="font-medium">{activeRun.steps_completed.length} / {STEPS.length} steps</p>
                    <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                      <div
                        className="bg-brand-500 h-2 rounded-full transition-all duration-500"
                        style={{ width: `${(activeRun.steps_completed.length / STEPS.length) * 100}%` }}
                      />
                    </div>
                  </div>
                )}
                <div className="flex gap-2 pt-2">
                  {activeRun.status === 'running' && (
                    <button onClick={() => pauseRun(activeRun.id)} className="btn-secondary flex items-center gap-1">
                      <Pause className="w-4 h-4" /> Pause
                    </button>
                  )}
                  {activeRun.status === 'paused' && (
                    <button onClick={() => resumeRun(activeRun.id)} className="btn-primary flex items-center gap-1">
                      <Play className="w-4 h-4" /> Resume
                    </button>
                  )}
                  {['running', 'paused'].includes(activeRun.status) && (
                    <button onClick={() => cancelRun(activeRun.id)} className="btn-danger flex items-center gap-1">
                      <Square className="w-4 h-4" /> Cancel
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-500">No active run. Enter your subnet and start a new assessment.</p>
            )}
          </div>

          <div className="card p-6 mt-4">
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
                    <div className="flex items-center gap-2">
                      {['completed', 'failed'].includes(run.status) && (
                        <button
                          onClick={() => handleViewReport(run.id)}
                          className="text-gray-400 hover:text-brand-500"
                          title="View report"
                        >
                          <FileText className="w-4 h-4" />
                        </button>
                      )}
                      <Badge variant={run.status === 'completed' ? 'success' : run.status === 'failed' ? 'critical' : 'info'}>
                        {run.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Workflow Completion Report Modal */}
      <Modal
        open={reportOpen}
        onClose={handleCloseReport}
        title="Workflow Completion Report"
        footer={
          <button onClick={handleCloseReport} className="btn-secondary">
            Close
          </button>
        }
      >
        {reportLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
            <span className="ml-2 text-sm text-gray-500">Loading report...</span>
          </div>
        ) : report ? (
          <div className="space-y-6">
            {/* Run overview */}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-gray-500">Run ID</p>
                <p className="font-mono">{report.run_id.slice(0, 12)}...</p>
              </div>
              <div>
                <p className="text-gray-500">Status</p>
                <Badge variant={report.status === 'completed' ? 'success' : report.status === 'failed' ? 'critical' : 'info'}>
                  {report.status}
                </Badge>
              </div>
              <div>
                <p className="text-gray-500">Scope</p>
                <p className="font-mono text-xs">{report.scope?.subnets?.join(', ') || '—'}</p>
              </div>
              <div>
                <p className="text-gray-500">Duration</p>
                <p>{report.duration_seconds != null ? formatDuration(report.duration_seconds) : '—'}</p>
              </div>
              {report.started_at && (
                <div>
                  <p className="text-gray-500">Started</p>
                  <p className="text-xs">{new Date(report.started_at).toLocaleString()}</p>
                </div>
              )}
              {report.completed_at && (
                <div>
                  <p className="text-gray-500">Completed</p>
                  <p className="text-xs">{new Date(report.completed_at).toLocaleString()}</p>
                </div>
              )}
            </div>

            {/* Summary counters */}
            <div>
              <h4 className="text-sm font-semibold mb-2">Summary</h4>
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-blue-50 rounded-lg p-2 text-center">
                  <p className="text-lg font-bold text-blue-700">{report.summary.total_assets}</p>
                  <p className="text-xs text-blue-600">Assets</p>
                </div>
                <div className="bg-orange-50 rounded-lg p-2 text-center">
                  <p className="text-lg font-bold text-orange-700">{report.summary.total_findings}</p>
                  <p className="text-xs text-orange-600">Findings</p>
                </div>
                <div className="bg-purple-50 rounded-lg p-2 text-center">
                  <p className="text-lg font-bold text-purple-700">{report.summary.total_threats}</p>
                  <p className="text-xs text-purple-600">Threats</p>
                </div>
                <div className="bg-red-50 rounded-lg p-2 text-center">
                  <p className="text-lg font-bold text-red-700">{report.summary.total_risks}</p>
                  <p className="text-xs text-red-600">Risks</p>
                </div>
                <div className="bg-indigo-50 rounded-lg p-2 text-center">
                  <p className="text-lg font-bold text-indigo-700">{report.summary.total_mitre_mappings}</p>
                  <p className="text-xs text-indigo-600">MITRE Maps</p>
                </div>
                <div className="bg-green-50 rounded-lg p-2 text-center">
                  <p className="text-lg font-bold text-green-700">{report.summary.total_baselines}</p>
                  <p className="text-xs text-green-600">Baselines</p>
                </div>
              </div>
            </div>

            {/* Findings by severity */}
            {Object.keys(report.summary.findings_by_severity).length > 0 && (
              <div>
                <h4 className="text-sm font-semibold mb-2">Findings by Severity</h4>
                <div className="flex gap-2 flex-wrap">
                  {['critical', 'high', 'medium', 'low', 'info'].map((sev) =>
                    report.summary.findings_by_severity[sev] ? (
                      <span key={sev} className={`px-2 py-1 rounded text-xs font-medium ${SEVERITY_COLORS[sev] || ''}`}>
                        {sev}: {report.summary.findings_by_severity[sev]}
                      </span>
                    ) : null
                  )}
                </div>
              </div>
            )}

            {/* Risks by level */}
            {Object.keys(report.summary.risks_by_level).length > 0 && (
              <div>
                <h4 className="text-sm font-semibold mb-2">Risks by Level</h4>
                <div className="flex gap-2 flex-wrap">
                  {['critical', 'high', 'medium', 'low'].map((lvl) =>
                    report.summary.risks_by_level[lvl] ? (
                      <span key={lvl} className={`px-2 py-1 rounded text-xs font-medium ${SEVERITY_COLORS[lvl] || ''}`}>
                        {lvl}: {report.summary.risks_by_level[lvl]}
                      </span>
                    ) : null
                  )}
                </div>
              </div>
            )}

            {/* Step-by-step details */}
            <div>
              <h4 className="text-sm font-semibold mb-2">Step Details</h4>
              <div className="space-y-2">
                {report.steps.map((step) => (
                  <StepReportCard key={step.step} step={step} />
                ))}
              </div>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-500 py-8 text-center">No report data available.</p>
        )}
      </Modal>
    </div>
  )
}
