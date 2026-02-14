import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { Bot, Lightbulb, Wrench, FileText, Loader2, ChevronDown, ChevronUp, Play, CheckCircle2, XCircle, RotateCcw, ArrowRight } from 'lucide-react'
import api from '../../api/client'

interface TriageItem {
  finding_id: string
  title: string
  severity: string
  category: string
  priority_score: number
  recommended_action: string
  effort_estimate: string
}

type WorkflowStep = 'IDLE' | 'INVESTIGATE' | 'PLAN' | 'CONFIRM' | 'EXECUTE' | 'VERIFY' | 'REPORT'

const STEP_ORDER: WorkflowStep[] = ['INVESTIGATE', 'PLAN', 'CONFIRM', 'EXECUTE', 'VERIFY', 'REPORT']
const STEP_LABELS: Record<string, string> = {
  INVESTIGATE: 'Investigate', PLAN: 'Plan', CONFIRM: 'Confirm',
  EXECUTE: 'Execute', VERIFY: 'Verify', REPORT: 'Report',
}

interface InvestigateData {
  finding: any
  asset: any
  mitre_mappings: any[]
  risks: any[]
  analysis: { what: string; why_relevant: string[]; attack_context: string[]; risk_context: string[]; asset_context: string }
  plan: { steps: Array<{ step: number; action: string; detail: string }>; risk_notes: string[]; estimated_effort: string; verification: string }
}

export default function CopilotPage() {
  const [triageResults, setTriageResults] = useState<TriageItem[]>([])
  const [loading, setLoading] = useState<Record<string, boolean>>({})
  const navigate = useNavigate()

  // Workflow state
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null)
  const [currentStep, setCurrentStep] = useState<WorkflowStep>('IDLE')
  const [investigateData, setInvestigateData] = useState<InvestigateData | null>(null)
  const [executeResult, setExecuteResult] = useState<any>(null)
  const [verifyResult, setVerifyResult] = useState<any>(null)

  useEffect(() => {
    runTriage()
  }, [])

  async function runTriage() {
    setLoading((p) => ({ ...p, triage: true }))
    try {
      const res = await api.post('/copilot/triage', {})
      setTriageResults(res.data.findings || [])
    } catch { /* empty */ }
    setLoading((p) => ({ ...p, triage: false }))
  }

  async function startInvestigation(findingId: string) {
    setSelectedFindingId(findingId)
    setCurrentStep('INVESTIGATE')
    setInvestigateData(null)
    setExecuteResult(null)
    setVerifyResult(null)
    setLoading((p) => ({ ...p, investigate: true }))
    try {
      const res = await api.post('/copilot/investigate', { finding_id: findingId })
      setInvestigateData(res.data)
      setCurrentStep('PLAN')
    } catch { /* empty */ }
    setLoading((p) => ({ ...p, investigate: false }))
  }

  async function executeRemediation() {
    if (!selectedFindingId) return
    setCurrentStep('EXECUTE')
    setLoading((p) => ({ ...p, execute: true }))
    try {
      const res = await api.post('/copilot/execute-remediation', {
        finding_id: selectedFindingId,
        action: 'set_in_progress',
      })
      setExecuteResult(res.data)
    } catch { /* empty */ }
    setLoading((p) => ({ ...p, execute: false }))
  }

  async function runVerification() {
    if (!selectedFindingId) return
    setCurrentStep('VERIFY')
    setLoading((p) => ({ ...p, verify: true }))
    try {
      const res = await api.post('/copilot/verify', {
        finding_id: selectedFindingId,
        action_id: 'port_verify',
        target: investigateData?.asset?.ip_address || null,
      })
      setVerifyResult(res.data)
      setCurrentStep('REPORT')
    } catch { /* empty */ }
    setLoading((p) => ({ ...p, verify: false }))
  }

  async function markAsFixed() {
    if (!selectedFindingId) return
    try {
      await api.post('/copilot/execute-remediation', {
        finding_id: selectedFindingId,
        action: 'set_fixed',
      })
      // Refresh triage
      runTriage()
      resetWorkflow()
    } catch { /* empty */ }
  }

  function resetWorkflow() {
    setSelectedFindingId(null)
    setCurrentStep('IDLE')
    setInvestigateData(null)
    setExecuteResult(null)
    setVerifyResult(null)
  }

  const priorityColor = (score: number) => {
    if (score >= 70) return 'text-red-600 bg-red-50'
    if (score >= 40) return 'text-yellow-600 bg-yellow-50'
    return 'text-green-600 bg-green-50'
  }

  const stepIndex = currentStep === 'IDLE' ? -1 : STEP_ORDER.indexOf(currentStep)

  return (
    <div>
      <PageHeader
        title="AI Defense Copilot"
        description="AI-assisted security analysis and remediation workflow"
        actions={
          <div className="flex gap-2">
            <button onClick={runTriage} disabled={loading.triage} className="btn-secondary flex items-center gap-2">
              <Lightbulb className="w-4 h-4" /> {loading.triage ? 'Analyzing...' : 'Run Triage'}
            </button>
            {currentStep !== 'IDLE' && (
              <button onClick={resetWorkflow} className="btn-secondary flex items-center gap-2">
                <RotateCcw className="w-4 h-4" /> Reset Workflow
              </button>
            )}
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: Triage List */}
        <div className="lg:col-span-2">
          <div className="card">
            <div className="px-6 py-4 border-b flex items-center gap-2">
              <Lightbulb className="w-5 h-5 text-yellow-500" />
              <h3 className="font-semibold">Finding Triage ({triageResults.length})</h3>
            </div>
            <div className="divide-y max-h-[700px] overflow-y-auto">
              {loading.triage ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                  <span className="ml-2 text-sm text-gray-500">Analyzing findings...</span>
                </div>
              ) : triageResults.length === 0 ? (
                <div className="p-6 text-center text-gray-500 text-sm">
                  No findings to triage. Run an assessment workflow first.
                </div>
              ) : (
                triageResults.map((item) => (
                  <div
                    key={item.finding_id}
                    className={`p-4 cursor-pointer transition-colors ${
                      selectedFindingId === item.finding_id ? 'bg-brand-50 border-l-4 border-brand-500' : 'hover:bg-gray-50'
                    }`}
                    onClick={() => startInvestigation(item.finding_id)}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`px-2 py-1 rounded text-xs font-bold ${priorityColor(item.priority_score)}`}>
                        {item.priority_score}
                      </div>
                      <Badge variant={item.severity as any}>{item.severity}</Badge>
                      <span className="text-sm font-medium flex-1 truncate">{item.title}</span>
                    </div>
                    <div className="mt-1 ml-12 text-xs text-gray-500">
                      {item.category} | Effort: {item.effort_estimate}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right: Workflow Panel */}
        <div className="lg:col-span-3">
          {currentStep === 'IDLE' ? (
            <div className="card p-12 text-center">
              <Bot className="w-16 h-16 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-gray-700 mb-2">Select a Finding to Begin</h3>
              <p className="text-sm text-gray-500">Click on a finding in the triage list to start the 6-step remediation workflow.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Step Indicator */}
              <div className="card p-4">
                <div className="flex items-center justify-between">
                  {STEP_ORDER.map((step, i) => {
                    const isCompleted = i < stepIndex
                    const isActive = i === stepIndex
                    const isPending = i > stepIndex
                    return (
                      <div key={step} className="flex items-center flex-1">
                        <div className="flex flex-col items-center">
                          <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
                            isCompleted ? 'bg-green-500 text-white' :
                            isActive ? 'bg-brand-600 text-white' :
                            'bg-gray-200 text-gray-500'
                          }`}>
                            {isCompleted ? <CheckCircle2 className="w-4 h-4" /> : i + 1}
                          </div>
                          <span className={`text-xs mt-1 ${isActive ? 'text-brand-600 font-medium' : 'text-gray-400'}`}>
                            {STEP_LABELS[step]}
                          </span>
                        </div>
                        {i < STEP_ORDER.length - 1 && (
                          <div className={`flex-1 h-0.5 mx-2 ${isCompleted ? 'bg-green-500' : 'bg-gray-200'}`} />
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Workflow Content */}
              <div className="card">
                {/* INVESTIGATE / PLAN */}
                {(currentStep === 'INVESTIGATE' || currentStep === 'PLAN') && (
                  <div>
                    <div className="px-6 py-4 border-b flex items-center gap-2">
                      <Lightbulb className="w-5 h-5 text-yellow-500" />
                      <h3 className="font-semibold">{currentStep === 'INVESTIGATE' ? 'Investigating...' : 'Investigation & Plan'}</h3>
                    </div>
                    <div className="p-6">
                      {loading.investigate ? (
                        <div className="flex items-center gap-3 py-8 justify-center">
                          <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                          <span className="text-gray-500">Gathering context and building analysis...</span>
                        </div>
                      ) : investigateData ? (
                        <div className="space-y-5">
                          {/* Analysis */}
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2">Analysis</h4>
                            <div className="space-y-2 text-sm">
                              <div>
                                <span className="text-gray-500 font-medium">What: </span>
                                <span className="text-gray-700">{investigateData.analysis.what}</span>
                              </div>
                              <div>
                                <span className="text-gray-500 font-medium">Why relevant: </span>
                                <span className="text-gray-700">{investigateData.analysis.why_relevant.join('; ')}</span>
                              </div>
                              <div>
                                <span className="text-gray-500 font-medium">Asset: </span>
                                <span className="text-gray-700">{investigateData.analysis.asset_context}</span>
                              </div>
                            </div>
                          </div>

                          {/* Asset Box */}
                          {investigateData.asset && (
                            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                              <div className="flex items-center gap-2 text-sm">
                                <span className="font-medium text-blue-800">
                                  {investigateData.asset.hostname || investigateData.asset.ip_address}
                                </span>
                                <span className="text-blue-600 font-mono text-xs">{investigateData.asset.ip_address}</span>
                                <Badge variant="info">{investigateData.asset.zone}</Badge>
                                <Badge variant={investigateData.asset.criticality as any}>{investigateData.asset.criticality}</Badge>
                              </div>
                            </div>
                          )}

                          {/* Attack Context (MITRE) */}
                          {investigateData.mitre_mappings.length > 0 && (
                            <div>
                              <h4 className="text-sm font-semibold text-gray-700 mb-2">MITRE ATT&CK</h4>
                              <div className="flex flex-wrap gap-1">
                                {investigateData.mitre_mappings.map((m: any) => (
                                  <span key={m.technique_id} className="bg-brand-50 text-brand-700 px-2 py-1 rounded text-xs font-mono">
                                    {m.technique_id} ({m.tactic})
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Risk Context */}
                          {investigateData.risks.length > 0 && (
                            <div>
                              <h4 className="text-sm font-semibold text-gray-700 mb-2">Risk Scenarios</h4>
                              <div className="space-y-1">
                                {investigateData.risks.map((r: any) => (
                                  <div key={r.id} className="flex items-start gap-2">
                                    <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                                    <p className="text-xs text-gray-600">{r.scenario}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Remediation Plan */}
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2">Remediation Plan</h4>
                            <ol className="space-y-2">
                              {investigateData.plan.steps.map((step: any) => (
                                <li key={step.step} className="flex gap-2 text-sm">
                                  <span className="font-bold text-brand-600 shrink-0">{step.step}.</span>
                                  <div>
                                    <p className="font-medium">{step.action}</p>
                                    <p className="text-gray-500 text-xs">{step.detail}</p>
                                  </div>
                                </li>
                              ))}
                            </ol>
                            {investigateData.plan.risk_notes?.length > 0 && (
                              <div className="mt-2 text-xs text-amber-600 bg-amber-50 p-2 rounded">
                                {investigateData.plan.risk_notes.join('. ')}
                              </div>
                            )}
                          </div>

                          {/* Approve Plan Button */}
                          <button
                            onClick={() => setCurrentStep('CONFIRM')}
                            className="btn-primary flex items-center gap-2"
                          >
                            <ArrowRight className="w-4 h-4" /> Approve Plan
                          </button>
                        </div>
                      ) : null}
                    </div>
                  </div>
                )}

                {/* CONFIRM */}
                {currentStep === 'CONFIRM' && investigateData && (
                  <div>
                    <div className="px-6 py-4 border-b flex items-center gap-2">
                      <CheckCircle2 className="w-5 h-5 text-blue-500" />
                      <h3 className="font-semibold">Confirm Execution</h3>
                    </div>
                    <div className="p-6 space-y-4">
                      <div className="bg-gray-50 p-4 rounded-lg">
                        <p className="text-sm font-medium mb-2">Plan Summary</p>
                        <p className="text-sm text-gray-700">
                          <Badge variant={investigateData.finding.severity as any}>{investigateData.finding.severity}</Badge>
                          {' '}{investigateData.finding.title}
                        </p>
                        <p className="text-xs text-gray-500 mt-1">
                          {investigateData.plan.steps.length} steps | Effort: {investigateData.plan.estimated_effort}
                        </p>
                      </div>
                      <p className="text-sm text-gray-600">
                        This will set the finding status to "in_progress" and log the action. Continue?
                      </p>
                      <div className="flex gap-3">
                        <button onClick={executeRemediation} className="btn-primary flex items-center gap-2">
                          <Play className="w-4 h-4" /> Execute
                        </button>
                        <button onClick={() => setCurrentStep('PLAN')} className="btn-secondary">
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* EXECUTE */}
                {currentStep === 'EXECUTE' && (
                  <div>
                    <div className="px-6 py-4 border-b flex items-center gap-2">
                      <Wrench className="w-5 h-5 text-green-500" />
                      <h3 className="font-semibold">Executing Remediation</h3>
                    </div>
                    <div className="p-6">
                      {loading.execute ? (
                        <div className="flex items-center gap-3 py-4">
                          <Loader2 className="w-5 h-5 animate-spin text-brand-500" />
                          <span className="text-gray-500">Setting status and logging action...</span>
                        </div>
                      ) : executeResult ? (
                        <div className="space-y-4">
                          <div className="bg-green-50 border border-green-200 p-4 rounded-lg">
                            <div className="flex items-center gap-2 text-green-700 font-medium">
                              <CheckCircle2 className="w-5 h-5" />
                              Remediation Initiated
                            </div>
                            <p className="text-sm text-green-600 mt-1">
                              Status changed: {executeResult.old_status} → {executeResult.new_status}
                            </p>
                          </div>
                          <button onClick={() => setCurrentStep('VERIFY')} className="btn-primary flex items-center gap-2">
                            <ArrowRight className="w-4 h-4" /> Proceed to Verification
                          </button>
                        </div>
                      ) : null}
                    </div>
                  </div>
                )}

                {/* VERIFY */}
                {currentStep === 'VERIFY' && !verifyResult && (
                  <div>
                    <div className="px-6 py-4 border-b flex items-center gap-2">
                      <Bot className="w-5 h-5 text-purple-500" />
                      <h3 className="font-semibold">Verification Scan</h3>
                    </div>
                    <div className="p-6 space-y-4">
                      {loading.verify ? (
                        <div className="flex items-center gap-3 py-4">
                          <Loader2 className="w-5 h-5 animate-spin text-brand-500" />
                          <span className="text-gray-500">Running verification scan against {investigateData?.asset?.ip_address || 'target'}...</span>
                        </div>
                      ) : (
                        <>
                          <p className="text-sm text-gray-600">
                            Run a verification scan to check if the finding is still reproducible.
                          </p>
                          {investigateData?.asset && (
                            <div className="bg-gray-50 p-3 rounded-lg text-sm">
                              Target: <span className="font-mono font-medium">{investigateData.asset.ip_address}</span>
                            </div>
                          )}
                          <button onClick={runVerification} className="btn-primary flex items-center gap-2">
                            <Play className="w-4 h-4" /> Run Verification Scan
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* REPORT */}
                {currentStep === 'REPORT' && verifyResult && (
                  <div>
                    <div className="px-6 py-4 border-b flex items-center gap-2">
                      <FileText className="w-5 h-5 text-blue-500" />
                      <h3 className="font-semibold">Verification Report</h3>
                    </div>
                    <div className="p-6 space-y-4">
                      {/* Verdict */}
                      <div className={`p-4 rounded-lg border-2 ${
                        verifyResult.verdict === 'LIKELY_FIXED'
                          ? 'bg-green-50 border-green-300'
                          : 'bg-red-50 border-red-300'
                      }`}>
                        <div className="flex items-center gap-3">
                          {verifyResult.verdict === 'LIKELY_FIXED' ? (
                            <CheckCircle2 className="w-8 h-8 text-green-500" />
                          ) : (
                            <XCircle className="w-8 h-8 text-red-500" />
                          )}
                          <div>
                            <p className={`text-lg font-bold ${
                              verifyResult.verdict === 'LIKELY_FIXED' ? 'text-green-700' : 'text-red-700'
                            }`}>
                              {verifyResult.verdict === 'LIKELY_FIXED' ? 'Likely Fixed' : 'Still Vulnerable'}
                            </p>
                            <p className="text-sm text-gray-600">
                              Scan found {verifyResult.scan_findings_count} finding(s) on {verifyResult.target}
                            </p>
                          </div>
                        </div>
                      </div>

                      {/* Scan Results */}
                      {verifyResult.scan_result?.findings?.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-700 mb-2">Scan Findings</h4>
                          <div className="space-y-1">
                            {verifyResult.scan_result.findings.map((f: any, i: number) => (
                              <div key={i} className="flex items-center gap-2 text-xs p-2 bg-gray-50 rounded">
                                <Badge variant={f.severity as any}>{f.severity}</Badge>
                                <span>{f.title}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Actions */}
                      <div className="flex gap-3 pt-2">
                        {verifyResult.verdict === 'LIKELY_FIXED' ? (
                          <button onClick={markAsFixed} className="btn-primary flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4" /> Mark as Fixed
                          </button>
                        ) : (
                          <button onClick={() => startInvestigation(selectedFindingId!)} className="btn-primary flex items-center gap-2">
                            <RotateCcw className="w-4 h-4" /> Investigate Again
                          </button>
                        )}
                        <button onClick={resetWorkflow} className="btn-secondary">
                          Back to Triage
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
