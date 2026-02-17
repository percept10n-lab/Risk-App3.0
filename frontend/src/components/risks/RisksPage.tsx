import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Pagination from '../common/Pagination'
import Badge from '../common/Badge'
import { useRiskStore } from '../../stores/riskStore'
import { risksApi } from '../../api/endpoints'
import { formatRelativeTime } from '../../utils/format'
import { getContextualOptions } from '../../data/treatmentOptions'
import type { TreatmentOption } from '../../data/treatmentOptions'
import type { Risk } from '../../types'
import {
  ChevronDown, ChevronRight, Loader2, Play, Shield,
  AlertTriangle, Eye, Clock, CheckSquare,
} from 'lucide-react'

type TabKey = 'register' | 'matrix' | 'analysis' | 'treatment'

// --- CIA color helper ---
const ciaColor: Record<string, string> = {
  none: 'bg-gray-200',
  low: 'bg-yellow-400',
  medium: 'bg-orange-500',
  high: 'bg-red-600',
}

// --- Status step order ---
const STATUS_STEPS = ['identified', 'analyzed', 'evaluated', 'treated', 'monitoring']

// --- SLA days ---
const SLA_DAYS: Record<string, number | null> = { critical: 7, high: 30, medium: 90, low: null }

// --- Risk level colors for matrix ---
const RISK_LEVEL_BG: Record<string, string> = {
  low: 'bg-green-100 border-green-300 text-green-800',
  medium: 'bg-yellow-100 border-yellow-300 text-yellow-800',
  high: 'bg-orange-100 border-orange-300 text-orange-800',
  critical: 'bg-red-100 border-red-300 text-red-800',
}

const LIKELIHOOD_LABELS = ['very_high', 'high', 'medium', 'low', 'very_low']
const IMPACT_LABELS = ['negligible', 'low', 'medium', 'high', 'critical']

export default function RisksPage() {
  const { risks, total, page, pageSize, loading, filters, fetchRisks, setFilters, setPage } = useRiskStore()
  const [activeTab, setActiveTab] = useState<TabKey>('register')
  const [expandedRisks, setExpandedRisks] = useState<Record<string, any>>({})
  const [expandedLoading, setExpandedLoading] = useState<Record<string, boolean>>({})
  const [expandedAssets, setExpandedAssets] = useState<Record<string, boolean>>({})

  // Matrix state
  const [matrixData, setMatrixData] = useState<any>(null)
  const [matrixLoading, setMatrixLoading] = useState(false)
  const [selectedCell, setSelectedCell] = useState<string | null>(null)

  // Analysis state
  const [analysisRunning, setAnalysisRunning] = useState(false)
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analysisExpanded, setAnalysisExpanded] = useState<Record<string, any>>({})
  const [analysisExpandLoading, setAnalysisExpandLoading] = useState<Record<string, boolean>>({})

  // Treatment state
  const [treatmentModal, setTreatmentModal] = useState<{ riskId: string; risk: Risk } | null>(null)
  const [treatmentForm, setTreatmentForm] = useState({ treatment: 'mitigate', treatment_plan: '', treatment_measures: [] as string[], treatment_owner: '', treatment_due_date: '', residual_risk_level: '' })
  const [treatmentSaving, setTreatmentSaving] = useState(false)
  const [treatmentContext, setTreatmentContext] = useState<any>(null)
  const [treatmentContextLoading, setTreatmentContextLoading] = useState(false)

  // Error state for user feedback
  const [actionError, setActionError] = useState<string | null>(null)

  // Asset cache for register grouping
  const [assetCache, setAssetCache] = useState<Record<string, { hostname: string | null; ip_address: string }>>({})

  const navigate = useNavigate()

  useEffect(() => {
    fetchRisks({ include_asset: true })
  }, [])

  // Build asset cache from enriched risk data
  useEffect(() => {
    const cache: Record<string, { hostname: string | null; ip_address: string }> = {}
    risks.forEach((r: any) => {
      if (r.asset && r.asset_id) {
        cache[r.asset_id] = { hostname: r.asset.hostname, ip_address: r.asset.ip_address }
      }
    })
    if (Object.keys(cache).length > 0) {
      setAssetCache((prev) => ({ ...prev, ...cache }))
    }
  }, [risks])

  // Group risks by asset
  const risksByAsset: Record<string, Risk[]> = {}
  risks.forEach((r) => {
    const key = r.asset_id || 'unknown'
    if (!risksByAsset[key]) risksByAsset[key] = []
    risksByAsset[key].push(r)
  })

  // --- Register Tab: expandable rows ---
  const toggleExpand = useCallback(async (riskId: string) => {
    if (expandedRisks[riskId]) {
      setExpandedRisks((prev) => { const n = { ...prev }; delete n[riskId]; return n })
      return
    }
    setExpandedLoading((prev) => ({ ...prev, [riskId]: true }))
    try {
      const res = await risksApi.getFullContext(riskId)
      setExpandedRisks((prev) => ({ ...prev, [riskId]: res.data }))
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to load risk details')
    }
    setExpandedLoading((prev) => ({ ...prev, [riskId]: false }))
  }, [expandedRisks])

  // --- Matrix ---
  const loadMatrix = useCallback(async () => {
    setMatrixLoading(true)
    try {
      const res = await risksApi.matrix()
      setMatrixData(res.data)
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to load risk matrix')
    }
    setMatrixLoading(false)
  }, [])

  // --- Analysis ---
  const runAnalysis = async () => {
    setAnalysisRunning(true)
    setAnalysisResult(null)
    try {
      const res = await risksApi.analyze()
      setAnalysisResult(res.data)
      fetchRisks({ include_asset: true })
    } catch (err: any) {
      setAnalysisResult({ status: 'error', error: err.message })
    }
    setAnalysisRunning(false)
  }

  const toggleAnalysisExpand = useCallback(async (riskId: string) => {
    if (analysisExpanded[riskId]) {
      setAnalysisExpanded((prev) => { const n = { ...prev }; delete n[riskId]; return n })
      return
    }
    setAnalysisExpandLoading((prev) => ({ ...prev, [riskId]: true }))
    try {
      const res = await risksApi.getFullContext(riskId)
      setAnalysisExpanded((prev) => ({ ...prev, [riskId]: res.data }))
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to load risk details')
    }
    setAnalysisExpandLoading((prev) => ({ ...prev, [riskId]: false }))
  }, [analysisExpanded])

  // --- Treatment ---
  const saveTreatment = async () => {
    if (!treatmentModal) return
    setTreatmentSaving(true)
    try {
      await risksApi.treat(treatmentModal.riskId, {
        treatment: treatmentForm.treatment,
        treatment_plan: treatmentForm.treatment_plan || null,
        treatment_measures: treatmentForm.treatment_measures.length > 0 ? treatmentForm.treatment_measures : null,
        treatment_owner: treatmentForm.treatment_owner || null,
        treatment_due_date: treatmentForm.treatment_due_date || null,
        residual_risk_level: treatmentForm.residual_risk_level || null,
      })
      setTreatmentModal(null)
      fetchRisks({ include_asset: true })
      // Refresh matrix if loaded
      if (matrixData) loadMatrix()
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to save treatment')
    }
    setTreatmentSaving(false)
  }

  // --- Summary cards ---
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  risks.forEach((r) => { if (r.risk_level in riskCounts) riskCounts[r.risk_level as keyof typeof riskCounts]++ })

  // --- Treatment buckets ---
  const untreated = risks.filter((r) => ['identified', 'analyzed', 'evaluated'].includes(r.status))
  const treated = risks.filter((r) => r.status === 'treated')
  const monitoring = risks.filter((r) => r.status === 'monitoring')

  const tabs: Array<{ key: TabKey; label: string }> = [
    { key: 'register', label: 'Register' },
    { key: 'matrix', label: 'Matrix' },
    { key: 'analysis', label: 'Analysis' },
    { key: 'treatment', label: 'Treatment' },
  ]

  return (
    <div>
      <PageHeader
        title="Risk Register — ISO 27005"
        description="Risk assessment, analysis, and treatment management"
        actions={
          <button onClick={runAnalysis} disabled={analysisRunning} className="btn-primary flex items-center gap-2">
            {analysisRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Run Analysis
          </button>
        }
      />

      {/* Error banner */}
      {actionError && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-center justify-between">
          <span className="text-sm text-red-700">{actionError}</span>
          <button onClick={() => setActionError(null)} className="text-red-400 hover:text-red-600 text-sm ml-4">Dismiss</button>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {(['critical', 'high', 'medium', 'low'] as const).map((level) => {
          const colors: Record<string, string> = {
            critical: 'border-red-200 bg-red-50 text-red-700',
            high: 'border-orange-200 bg-orange-50 text-orange-700',
            medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
            low: 'border-green-200 bg-green-50 text-green-700',
          }
          return (
            <div key={level} className={`card p-4 border-2 ${colors[level]} cursor-pointer hover:shadow-md transition-shadow`}
              onClick={() => setFilters({ risk_level: filters.risk_level === level ? undefined : level })}
            >
              <p className="text-2xl font-bold">{riskCounts[level]}</p>
              <p className="text-sm capitalize">{level} Risk</p>
            </div>
          )
        })}
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-4">
        <select value={filters.risk_level || ''} onChange={(e) => setFilters({ risk_level: e.target.value || undefined })} className="btn-secondary text-sm">
          <option value="">All Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={filters.status || ''} onChange={(e) => setFilters({ status: e.target.value || undefined })} className="btn-secondary text-sm">
          <option value="">All Status</option>
          <option value="identified">Identified</option>
          <option value="analyzed">Analyzed</option>
          <option value="evaluated">Evaluated</option>
          <option value="treated">Treated</option>
          <option value="monitoring">Monitoring</option>
        </select>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => {
              setActiveTab(tab.key)
              if (tab.key === 'matrix' && !matrixData) loadMatrix()
            }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? 'border-brand-600 text-brand-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ====== REGISTER TAB ====== */}
      {activeTab === 'register' && (
        <div>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
            </div>
          ) : Object.keys(risksByAsset).length === 0 ? (
            <div className="card p-8 text-center text-gray-500 text-sm">
              No risks identified yet. Run a full assessment workflow.
            </div>
          ) : (
            <div className="space-y-4">
              {Object.entries(risksByAsset).map(([assetId, assetRisks]) => {
                const asset = assetCache[assetId]
                const isCollapsed = !expandedAssets[assetId]
                const assetLabel = asset
                  ? `${asset.ip_address}${asset.hostname ? ` (${asset.hostname})` : ''}`
                  : assetId.slice(0, 12)
                const critCount = assetRisks.filter((r) => r.risk_level === 'critical').length
                const highCount = assetRisks.filter((r) => r.risk_level === 'high').length

                return (
                  <div key={assetId} className="card">
                    {/* Asset Group Header */}
                    <button
                      onClick={() => setExpandedAssets((prev) => ({ ...prev, [assetId]: !prev[assetId] }))}
                      className="w-full px-4 py-3 flex items-center gap-3 hover:bg-gray-50 text-left border-b bg-gray-50"
                    >
                      {isCollapsed ? <ChevronRight className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
                      <span className="font-medium text-sm">{assetLabel}</span>
                      <span className="text-xs text-gray-400">{assetRisks.length} risks</span>
                      {critCount > 0 && <Badge variant="critical">{critCount} critical</Badge>}
                      {highCount > 0 && <Badge variant="high">{highCount} high</Badge>}
                    </button>

                    {/* Risk rows */}
                    {!isCollapsed && (
                      <div className="divide-y">
                        {assetRisks.map((r) => {
                          const ctx = expandedRisks[r.id]
                          return (
                            <div key={r.id}>
                              <div className="flex items-center gap-2 px-4 py-2 hover:bg-gray-50">
                                <button onClick={() => toggleExpand(r.id)} className="p-1 hover:bg-gray-100 rounded shrink-0">
                                  {expandedLoading[r.id] ? (
                                    <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
                                  ) : ctx ? (
                                    <ChevronDown className="w-4 h-4 text-gray-500" />
                                  ) : (
                                    <ChevronRight className="w-4 h-4 text-gray-500" />
                                  )}
                                </button>
                                <div className="w-20 shrink-0">
                                  <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                                </div>
                                <p className="text-sm line-clamp-2 flex-1 min-w-0" title={r.scenario}>{r.scenario}</p>
                                <span className="capitalize text-xs text-gray-400 w-16 shrink-0">{r.likelihood.replace('_', ' ')}</span>
                                <span className="capitalize text-xs text-gray-400 w-16 shrink-0">{r.impact}</span>
                                {r.treatment ? <Badge variant="info">{r.treatment}</Badge> : <span className="text-gray-300 text-xs w-16">—</span>}
                                <span className="capitalize text-xs text-gray-400 w-16 shrink-0">{r.status}</span>
                                <span className="text-xs text-gray-300 w-20 shrink-0">{formatRelativeTime(r.created_at)}</span>
                              </div>

                              {/* Expanded detail */}
                              {ctx && (
                                <div className="px-4 pb-3 ml-10 border-l-4 border-brand-400 bg-gray-50">
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3">
                                    {/* Threat */}
                                    {ctx.threat && (
                                      <div>
                                        <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Threat</h4>
                                        <p className="text-sm font-medium">{ctx.threat.title}</p>
                                        <div className="flex items-center gap-2 mt-1">
                                          <Badge variant="info">{ctx.threat.threat_type}</Badge>
                                          <div className="flex items-center gap-1">
                                            <span className="text-xs text-gray-500">Confidence:</span>
                                            <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                                              <div className="h-full bg-brand-500 rounded-full" style={{ width: `${(ctx.threat.confidence || 0) * 100}%` }} />
                                            </div>
                                            <span className="text-xs text-gray-500">{Math.round((ctx.threat.confidence || 0) * 100)}%</span>
                                          </div>
                                        </div>
                                      </div>
                                    )}

                                    {/* Finding */}
                                    {ctx.finding && (
                                      <div>
                                        <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Vulnerability</h4>
                                        <p className="text-sm font-medium">{ctx.finding.title}</p>
                                        <div className="flex items-center gap-2 mt-1">
                                          <Badge variant={ctx.finding.severity as any}>{ctx.finding.severity}</Badge>
                                          <span className="text-xs text-gray-500">{ctx.finding.status}</span>
                                          {ctx.finding.cwe_id && <span className="text-xs text-gray-400">{ctx.finding.cwe_id}</span>}
                                        </div>
                                        {ctx.finding.exploitability_score != null && (
                                          <div className="mt-1">
                                            <span className="text-xs text-gray-500">Exploitability: </span>
                                            <div className="inline-flex items-center gap-1">
                                              <div className="w-20 h-1.5 bg-gray-200 rounded-full overflow-hidden inline-block align-middle">
                                                <div className="h-full bg-red-500 rounded-full" style={{ width: `${(ctx.finding.exploitability_score / 10) * 100}%` }} />
                                              </div>
                                              <span className="text-xs font-medium">{ctx.finding.exploitability_score}/10</span>
                                            </div>
                                          </div>
                                        )}
                                        <button onClick={() => navigate(`/findings/${ctx.finding.id}`)} className="text-xs text-brand-600 hover:underline mt-1 inline-block">
                                          View Finding &rarr;
                                        </button>
                                      </div>
                                    )}

                                    {/* MITRE Techniques */}
                                    {ctx.mitre_mappings && ctx.mitre_mappings.length > 0 && (
                                      <div>
                                        <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">MITRE ATT&CK</h4>
                                        <div className="flex flex-wrap gap-1">
                                          {ctx.mitre_mappings.map((m: any) => (
                                            <span key={m.id} className="inline-flex items-center gap-1 px-2 py-0.5 bg-purple-50 text-purple-700 rounded text-xs">
                                              <span className="font-mono font-medium">{m.technique_id}</span>
                                              <span className="text-purple-500">{m.technique_name}</span>
                                              <span className="text-purple-400">({m.tactic})</span>
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* CIA Impact */}
                                    <div>
                                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">CIA Impact</h4>
                                      <div className="flex items-center gap-4">
                                        {['confidentiality', 'integrity', 'availability'].map((dim) => {
                                          const val = ctx[`${dim}_impact`] || 'none'
                                          return (
                                            <div key={dim} className="flex items-center gap-1">
                                              <div className={`w-3 h-3 rounded-full ${ciaColor[val] || ciaColor.none}`} />
                                              <span className="text-xs capitalize">{dim[0].toUpperCase()}: {val}</span>
                                            </div>
                                          )
                                        })}
                                      </div>
                                    </div>

                                    {/* Status Workflow */}
                                    <div>
                                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Status</h4>
                                      <div className="flex items-center gap-1">
                                        {STATUS_STEPS.map((step, i) => {
                                          const stepIdx = STATUS_STEPS.indexOf(ctx.status)
                                          const active = i <= stepIdx
                                          return (
                                            <span key={step} className={`px-2 py-0.5 rounded text-xs ${active ? 'bg-brand-100 text-brand-700 font-medium' : 'bg-gray-100 text-gray-400'}`}>
                                              {step}
                                            </span>
                                          )
                                        })}
                                      </div>
                                    </div>

                                    {/* Treatment info */}
                                    {ctx.treatment && (
                                      <div>
                                        <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Treatment</h4>
                                        <p className="text-xs"><span className="font-medium">Type:</span> {ctx.treatment}</p>
                                        {ctx.treatment_plan && <p className="text-xs"><span className="font-medium">Plan:</span> {ctx.treatment_plan}</p>}
                                        {ctx.treatment_owner && <p className="text-xs"><span className="font-medium">Owner:</span> {ctx.treatment_owner}</p>}
                                        {ctx.treatment_due_date && <p className="text-xs"><span className="font-medium">Due:</span> {ctx.treatment_due_date}</p>}
                                        {ctx.residual_risk_level && <p className="text-xs"><span className="font-medium">Residual:</span> <Badge variant={ctx.residual_risk_level as any}>{ctx.residual_risk_level}</Badge></p>}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} />
        </div>
      )}

      {/* ====== MATRIX TAB ====== */}
      {activeTab === 'matrix' && (
        <div>
          {matrixLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
            </div>
          ) : matrixData ? (
            <div>
              {/* 5x5 Matrix Grid */}
              <div className="card p-6 mb-4">
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-xs font-semibold text-gray-500 uppercase">Likelihood &uarr;</span>
                  <span className="ml-auto text-xs font-semibold text-gray-500 uppercase">Impact &rarr;</span>
                </div>
                <div className="grid gap-1" style={{ gridTemplateColumns: 'auto repeat(5, 1fr)', gridTemplateRows: 'auto repeat(5, 1fr)' }}>
                  {/* Header: empty corner */}
                  <div />
                  {IMPACT_LABELS.map((imp) => (
                    <div key={imp} className="text-center text-xs font-medium text-gray-500 capitalize py-1">
                      {imp.replace('_', ' ')}
                    </div>
                  ))}

                  {/* Rows */}
                  {LIKELIHOOD_LABELS.map((lik) => (
                    <>
                      <div key={`label-${lik}`} className="text-right text-xs font-medium text-gray-500 capitalize pr-2 flex items-center justify-end">
                        {lik.replace('_', ' ')}
                      </div>
                      {IMPACT_LABELS.map((imp) => {
                        const cellKey = `${lik}_${imp}`
                        const cellRisks: any[] = matrixData.cell_risks?.[cellKey] || []
                        const untreatedInCell = cellRisks.filter((r: any) => !r.treated)
                        const treatedInCell = cellRisks.filter((r: any) => r.treated)
                        // Determine cell risk level from matrix
                        const matrixLevels = matrixData.matrix?.levels || {}
                        const level = matrixLevels[`${lik},${imp}`] || matrixLevels[cellKey] || 'low'
                        const bg = RISK_LEVEL_BG[level] || RISK_LEVEL_BG.low

                        return (
                          <button
                            key={cellKey}
                            onClick={() => setSelectedCell(selectedCell === cellKey ? null : cellKey)}
                            className={`border rounded-lg p-2 min-h-[48px] flex items-center justify-center text-sm font-semibold transition-all hover:shadow-md ${bg} ${selectedCell === cellKey ? 'ring-2 ring-brand-500' : ''}`}
                          >
                            {untreatedInCell.length > 0 || treatedInCell.length > 0 ? (
                              <span>
                                {untreatedInCell.length > 0 && untreatedInCell.length}
                                {treatedInCell.length > 0 && (
                                  <span className="text-xs opacity-60 ml-0.5">({treatedInCell.length})</span>
                                )}
                              </span>
                            ) : ''}
                          </button>
                        )
                      })}
                    </>
                  ))}
                </div>

                {/* Legend */}
                <div className="flex items-center gap-4 mt-4 pt-3 border-t">
                  <span className="text-xs text-gray-500">Legend:</span>
                  {Object.entries(RISK_LEVEL_BG).map(([level, cls]) => (
                    <div key={level} className="flex items-center gap-1">
                      <div className={`w-4 h-4 rounded ${cls} border`} />
                      <span className="text-xs capitalize">{level}</span>
                    </div>
                  ))}
                  <span className="text-xs text-gray-400 ml-2">(n) = treated risks</span>
                </div>
              </div>

              {/* Selected Cell Drill-Down */}
              {selectedCell && matrixData.cell_risks?.[selectedCell] && (
                <div className="card mb-4">
                  <div className="px-4 py-3 border-b bg-gray-50">
                    <h3 className="text-sm font-semibold">
                      Risks in cell: {selectedCell.replace('_', ' \u2192 ').replace('_', ' / ')}
                      <span className="ml-2 text-gray-500">({matrixData.cell_risks[selectedCell].length})</span>
                    </h3>
                  </div>
                  <div className="divide-y">
                    {matrixData.cell_risks[selectedCell].map((r: any) => (
                      <div key={r.id} className="px-4 py-2 flex items-center gap-3">
                        <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                        <span className="text-sm flex-1 line-clamp-2" title={r.scenario}>{r.scenario}</span>
                        <span className="text-xs capitalize text-gray-400">{r.status}</span>
                        {r.treated && (
                          <span className="text-xs text-green-600 font-medium">
                            treated (was {r.original_risk_level})
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Thresholds */}
              <div className="card p-4">
                <h3 className="text-sm font-semibold mb-3">Treatment Thresholds</h3>
                <div className="grid grid-cols-4 gap-3">
                  {matrixData.thresholds && Object.entries(matrixData.thresholds).map(([level, t]: [string, any]) => (
                    <div key={level} className={`p-3 rounded-lg border ${RISK_LEVEL_BG[level]}`}>
                      <p className="text-sm font-semibold capitalize">{level}</p>
                      <p className="text-xs mt-1">{t.acceptable ? 'Acceptable' : 'Not acceptable'}</p>
                      {t.max_days && <p className="text-xs">SLA: {t.max_days} days</p>}
                      {t.requires_escalation && <p className="text-xs font-medium">Requires escalation</p>}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="card p-8 text-center text-gray-500 text-sm">
              Failed to load matrix data. <button onClick={loadMatrix} className="text-brand-600 hover:underline">Retry</button>
            </div>
          )}
        </div>
      )}

      {/* ====== ANALYSIS TAB ====== */}
      {activeTab === 'analysis' && (
        <div>
          <div className="flex items-center gap-3 mb-4">
            <button onClick={runAnalysis} disabled={analysisRunning} className="btn-primary flex items-center gap-2 text-sm">
              {analysisRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run New Analysis
            </button>
            {analysisRunning && (
              <div className="flex-1">
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div className="bg-brand-500 h-2 rounded-full animate-pulse" style={{ width: '60%' }} />
                </div>
              </div>
            )}
          </div>

          {analysisResult && (
            <div className={`card p-4 mb-4 ${analysisResult.status === 'error' ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
              {analysisResult.status === 'error' ? (
                <p className="text-sm text-red-700">{analysisResult.error}</p>
              ) : (
                <div className="text-sm text-green-700">
                  <p className="font-medium">Analysis Complete</p>
                  <p>Created: {analysisResult.risks_created} | Updated: {analysisResult.risks_updated} | Assets analyzed: {analysisResult.total_assets}</p>
                </div>
              )}
            </div>
          )}

          {/* Per-risk expandable analysis blocks */}
          <div className="space-y-2">
            {risks.map((r) => {
              const ctx = analysisExpanded[r.id]
              return (
                <div key={r.id} className="card">
                  <button
                    onClick={() => toggleAnalysisExpand(r.id)}
                    className="w-full px-4 py-3 flex items-center gap-3 hover:bg-gray-50 text-left"
                  >
                    {analysisExpandLoading[r.id] ? (
                      <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
                    ) : ctx ? (
                      <ChevronDown className="w-4 h-4 text-gray-500" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-500" />
                    )}
                    <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                    <span className="text-sm flex-1 line-clamp-2" title={r.scenario}>{r.scenario}</span>
                    <span className="text-xs text-gray-400 capitalize">{r.status}</span>
                  </button>

                  {ctx && (
                    <div className="px-4 pb-4 border-t bg-gray-50">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                        {/* Likelihood Factors */}
                        <div>
                          <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Likelihood Factors</h4>
                          {ctx.likelihood_factors ? (
                            <div className="space-y-2">
                              {Object.entries(ctx.likelihood_factors).map(([key, val]: [string, any]) => (
                                <div key={key}>
                                  <div className="flex items-center justify-between text-xs mb-0.5">
                                    <span className="capitalize">{key.replace(/_/g, ' ')}</span>
                                    <span className="text-gray-500">{typeof val === 'number' ? `${Math.round(val * 100)}%` : val}</span>
                                  </div>
                                  <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
                                    <div className="h-full bg-blue-500 rounded-full" style={{ width: `${typeof val === 'number' ? val * 100 : 50}%` }} />
                                  </div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-xs text-gray-400 italic">
                              {ctx.likelihood_rationale || 'No detailed factors available'}
                            </p>
                          )}
                        </div>

                        {/* Impact Factors */}
                        <div>
                          <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Impact Factors</h4>
                          {ctx.impact_factors ? (
                            <div className="space-y-2">
                              {Object.entries(ctx.impact_factors).map(([key, val]: [string, any]) => (
                                <div key={key}>
                                  <div className="flex items-center justify-between text-xs mb-0.5">
                                    <span className="capitalize">{key.replace(/_/g, ' ')}</span>
                                    <span className="text-gray-500">{typeof val === 'number' ? `${Math.round(val * 100)}%` : val}</span>
                                  </div>
                                  <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
                                    <div className="h-full bg-orange-500 rounded-full" style={{ width: `${typeof val === 'number' ? val * 100 : 50}%` }} />
                                  </div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-xs text-gray-400 italic">
                              {ctx.impact_rationale || 'No detailed factors available'}
                            </p>
                          )}
                        </div>

                        {/* Linked entities */}
                        {ctx.threat && (
                          <div>
                            <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Linked Threat</h4>
                            <p className="text-sm">{ctx.threat.title}</p>
                            <Badge variant="info">{ctx.threat.threat_type}</Badge>
                          </div>
                        )}
                        {ctx.finding && (
                          <div>
                            <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Linked Finding</h4>
                            <p className="text-sm">{ctx.finding.title}</p>
                            <Badge variant={ctx.finding.severity as any}>{ctx.finding.severity}</Badge>
                          </div>
                        )}
                        {ctx.mitre_mappings && ctx.mitre_mappings.length > 0 && (
                          <div>
                            <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">MITRE Techniques</h4>
                            <div className="flex flex-wrap gap-1">
                              {ctx.mitre_mappings.map((m: any) => (
                                <span key={m.id} className="px-2 py-0.5 bg-purple-50 text-purple-700 rounded text-xs font-mono">
                                  {m.technique_id}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ====== TREATMENT TAB ====== */}
      {activeTab === 'treatment' && (
        <div>
          <div className="grid grid-cols-3 gap-4">
            {/* Column: Untreated */}
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-500" />
                Untreated ({untreated.length})
              </h3>
              <div className="space-y-2">
                {untreated.map((r) => (
                  <TreatmentCard key={r.id} risk={r} onTreat={async () => {
                    setTreatmentModal({ riskId: r.id, risk: r })
                    setTreatmentForm({ treatment: 'mitigate', treatment_plan: '', treatment_measures: [], treatment_owner: '', treatment_due_date: '', residual_risk_level: '' })
                    setTreatmentContext(null)
                    setTreatmentContextLoading(true)
                    try { const res = await risksApi.getFullContext(r.id); setTreatmentContext(res.data) } catch (err: any) { setActionError(err.response?.data?.detail || 'Failed to load context') }
                    setTreatmentContextLoading(false)
                  }} />
                ))}
                {untreated.length === 0 && <p className="text-xs text-gray-400 text-center py-4">No untreated risks</p>}
              </div>
            </div>

            {/* Column: Treated */}
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-green-500" />
                Treated ({treated.length})
              </h3>
              <div className="space-y-2">
                {treated.map((r) => (
                  <TreatmentCard key={r.id} risk={r} onTreat={async () => {
                    setTreatmentModal({ riskId: r.id, risk: r })
                    setTreatmentForm({
                      treatment: r.treatment || 'mitigate',
                      treatment_plan: r.treatment_plan || '',
                      treatment_measures: (r as any).treatment_measures || [],
                      treatment_owner: r.treatment_owner || '',
                      treatment_due_date: r.treatment_due_date || '',
                      residual_risk_level: r.residual_risk_level || '',
                    })
                    setTreatmentContext(null)
                    setTreatmentContextLoading(true)
                    try { const res = await risksApi.getFullContext(r.id); setTreatmentContext(res.data) } catch (err: any) { setActionError(err.response?.data?.detail || 'Failed to load context') }
                    setTreatmentContextLoading(false)
                  }} />
                ))}
                {treated.length === 0 && <p className="text-xs text-gray-400 text-center py-4">No treated risks</p>}
              </div>
            </div>

            {/* Column: Monitoring */}
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
                <Eye className="w-4 h-4 text-blue-500" />
                Monitoring ({monitoring.length})
              </h3>
              <div className="space-y-2">
                {monitoring.map((r) => (
                  <TreatmentCard key={r.id} risk={r} />
                ))}
                {monitoring.length === 0 && <p className="text-xs text-gray-400 text-center py-4">No risks in monitoring</p>}
              </div>
            </div>
          </div>

          {/* Treatment Modal */}
          {treatmentModal && (() => {
            // Build context tags for relevance scoring
            const ctxTags: string[] = []
            if (treatmentContext?.threat?.threat_type) ctxTags.push(treatmentContext.threat.threat_type)
            if (treatmentContext?.finding?.category) ctxTags.push(treatmentContext.finding.category)
            if (treatmentContext?.finding?.severity) ctxTags.push(treatmentContext.finding.severity)
            const exposure = (treatmentContext as any)?.asset?.exposure
            if (exposure) Object.entries(exposure).forEach(([k, v]) => { if (v) ctxTags.push(`exposure_${k}`) })
            const zone = (treatmentContext as any)?.asset?.zone
            if (zone) ctxTags.push(`zone_${zone}`)
            const measuresOptions = getContextualOptions(treatmentForm.treatment, ctxTags)
            const toggleMeasure = (id: string) => {
              setTreatmentForm((f) => ({
                ...f,
                treatment_measures: f.treatment_measures.includes(id)
                  ? f.treatment_measures.filter((m) => m !== id)
                  : [...f.treatment_measures, id],
              }))
            }

            return (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
              <div className="bg-white rounded-xl shadow-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
                <h3 className="font-semibold mb-4">Update Treatment</h3>
                <p className="text-sm text-gray-500 mb-4 line-clamp-2" title={treatmentModal.risk.scenario}>{treatmentModal.risk.scenario}</p>

                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Treatment Type</label>
                    <select value={treatmentForm.treatment} onChange={(e) => setTreatmentForm((f) => ({ ...f, treatment: e.target.value, treatment_measures: [] }))} className="w-full px-3 py-2 border rounded-lg text-sm">
                      <option value="mitigate">Mitigate</option>
                      <option value="transfer">Transfer</option>
                      <option value="avoid">Avoid</option>
                      <option value="accept">Accept</option>
                    </select>
                  </div>

                  {/* Treatment Measures Checklist */}
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1 flex items-center gap-1">
                      <CheckSquare className="w-3.5 h-3.5" />
                      Treatment Measures
                      {treatmentContextLoading && <Loader2 className="w-3 h-3 animate-spin text-gray-400 ml-1" />}
                    </label>
                    <div className="max-h-52 overflow-y-auto border rounded-lg divide-y">
                      {measuresOptions.map((opt: TreatmentOption) => (
                        <label key={opt.id} className="flex items-start gap-3 px-3 py-2 hover:bg-gray-50 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={treatmentForm.treatment_measures.includes(opt.id)}
                            onChange={() => toggleMeasure(opt.id)}
                            className="mt-0.5 rounded border-gray-300"
                          />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium">{opt.label}</p>
                            <p className="text-xs text-gray-500">{opt.description}</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {opt.iso27001_controls.map((ctrl) => (
                                <span key={ctrl} className="px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded text-[10px] font-mono">{ctrl}</span>
                              ))}
                              {opt.mitre_mitigations.map((mit) => (
                                <span key={mit} className="px-1.5 py-0.5 bg-purple-50 text-purple-700 rounded text-[10px] font-mono">{mit}</span>
                              ))}
                            </div>
                          </div>
                        </label>
                      ))}
                    </div>
                    {treatmentForm.treatment_measures.length > 0 && (
                      <p className="text-xs text-gray-500 mt-1">{treatmentForm.treatment_measures.length} measure(s) selected</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Additional Notes</label>
                    <textarea value={treatmentForm.treatment_plan} onChange={(e) => setTreatmentForm((f) => ({ ...f, treatment_plan: e.target.value }))} className="w-full px-3 py-2 border rounded-lg text-sm" rows={3} placeholder="Describe any additional treatment plan details..." />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-1">Owner</label>
                      <input value={treatmentForm.treatment_owner} onChange={(e) => setTreatmentForm((f) => ({ ...f, treatment_owner: e.target.value }))} className="w-full px-3 py-2 border rounded-lg text-sm" placeholder="e.g., IT Security" />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-1">Due Date</label>
                      <input type="date" value={treatmentForm.treatment_due_date} onChange={(e) => setTreatmentForm((f) => ({ ...f, treatment_due_date: e.target.value }))} className="w-full px-3 py-2 border rounded-lg text-sm" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Residual Risk Level</label>
                    <select value={treatmentForm.residual_risk_level} onChange={(e) => setTreatmentForm((f) => ({ ...f, residual_risk_level: e.target.value }))} className="w-full px-3 py-2 border rounded-lg text-sm">
                      <option value="">Not assessed</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>

                <div className="flex justify-end gap-2 mt-6">
                  <button onClick={() => setTreatmentModal(null)} className="btn-secondary text-sm">Cancel</button>
                  <button onClick={saveTreatment} disabled={treatmentSaving} className="btn-primary text-sm flex items-center gap-2">
                    {treatmentSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                    Save Treatment
                  </button>
                </div>
              </div>
            </div>
            )
          })()}
        </div>
      )}
    </div>
  )
}

// --- Treatment Card Sub-Component ---
function TreatmentCard({ risk, onTreat }: { risk: Risk; onTreat?: () => void }) {
  const slaDays = SLA_DAYS[risk.risk_level]
  let slaText = ''
  if (slaDays && risk.created_at) {
    const created = new Date(risk.created_at)
    const due = new Date(created.getTime() + slaDays * 86400000)
    const remaining = Math.ceil((due.getTime() - Date.now()) / 86400000)
    slaText = remaining > 0 ? `${remaining}d remaining` : `${Math.abs(remaining)}d overdue`
  }

  return (
    <div className="card p-3 border hover:shadow-sm transition-shadow">
      <div className="flex items-center gap-2 mb-1">
        <Badge variant={risk.risk_level as any}>{risk.risk_level}</Badge>
        {risk.treatment && <Badge variant="info">{risk.treatment}</Badge>}
        {risk.residual_risk_level && (
          <span className="text-xs text-gray-400">&rarr; <Badge variant={risk.residual_risk_level as any}>{risk.residual_risk_level}</Badge></span>
        )}
      </div>
      <p className="text-xs text-gray-700 line-clamp-2 mb-2" title={risk.scenario}>{risk.scenario}</p>
      <div className="flex items-center justify-between">
        {slaText && (
          <span className={`text-xs ${slaText.includes('overdue') ? 'text-red-600 font-medium' : 'text-gray-400'}`}>
            <Clock className="w-3 h-3 inline mr-1" />{slaText}
          </span>
        )}
        {onTreat && (
          <button onClick={onTreat} className="text-xs text-brand-600 hover:text-brand-800 font-medium">
            Update Treatment
          </button>
        )}
      </div>
    </div>
  )
}
