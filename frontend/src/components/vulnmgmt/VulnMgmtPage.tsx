import { useEffect, useState, useMemo } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import {
  AlertTriangle, CheckCircle2, Clock, Shield, RefreshCw, Loader2,
  ChevronDown, ChevronUp, X, ExternalLink, Plus, Filter, ArrowUpDown,
  ShieldAlert, Timer, Bug, FileText,
} from 'lucide-react'
import api from '../../api/client'
import { vulnMgmtApi, risksApi } from '../../api/endpoints'

interface FindingInfo {
  id: string
  title: string
  severity: string
  category: string
  asset_id: string
  status: string
  exploitability_score?: number
  source_tool?: string
  created_at?: string
}

interface EnrichedFinding {
  finding: {
    id: string; title: string; severity: string; category: string; status: string
    description?: string; remediation?: string; cwe_id?: string; cpe?: string
    raw_output_snippet?: string; source_tool?: string; source_check?: string
    cve_ids?: string[]; exploitability_score?: number
    exploitability_rationale?: Record<string, any>
    created_at?: string; updated_at?: string
  }
  asset: {
    id: string; hostname: string | null; ip_address: string; asset_type: string
    zone: string; criticality: string; vendor?: string; os_guess?: string
  } | null
  mitre_mappings: Array<{ technique_id: string; technique_name: string; tactic: string; confidence: number }>
  risks: Array<{ id: string; scenario: string; risk_level: string; likelihood: string; impact: string; treatment?: string }>
}

interface VulnMetrics {
  total: number
  open: number; in_progress: number; fixed: number
  accepted: number; exception: number; verified: number
  mttr_days: number; sla_compliance_rate: number
  sla_breached: number; sla_at_risk: number
}

type SortField = 'severity' | 'exploitability' | 'title' | 'category' | 'status'
type SortDir = 'asc' | 'desc'

const SEVERITY_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const VALID_TRANSITIONS: Record<string, string[]> = {
  open: ['in_progress', 'accepted', 'exception'],
  in_progress: ['fixed', 'open'],
  fixed: ['verified', 'open'],
  accepted: ['open'],
  exception: ['open'],
  verified: [],
}

export default function VulnMgmtPage() {
  const [findings, setFindings] = useState<FindingInfo[]>([])
  const [metrics, setMetrics] = useState<VulnMetrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [enrichedCache, setEnrichedCache] = useState<Record<string, EnrichedFinding>>({})
  const [enrichedLoading, setEnrichedLoading] = useState<string | null>(null)

  // Sorting & Filtering
  const [sortField, setSortField] = useState<SortField>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [filterCategory, setFilterCategory] = useState<string>('all')

  // Risk creation form
  const [showRiskForm, setShowRiskForm] = useState(false)
  const [riskScenario, setRiskScenario] = useState('')
  const [riskLikelihood, setRiskLikelihood] = useState('medium')
  const [riskImpact, setRiskImpact] = useState('moderate')
  const [riskCreating, setRiskCreating] = useState(false)

  // Status change comment
  const [commentFor, setCommentFor] = useState<string | null>(null)
  const [comment, setComment] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setLoading(true)
    try {
      const [findingsRes, metricsRes] = await Promise.allSettled([
        api.get('/findings', { params: { page_size: 200 } }),
        vulnMgmtApi.metrics(),
      ])
      if (findingsRes.status === 'fulfilled') {
        setFindings(findingsRes.value.data.items || [])
      }
      if (metricsRes.status === 'fulfilled') {
        setMetrics(metricsRes.value.data)
      }
    } catch (err: any) {
      console.error('Failed to load vuln data:', err.message)
    }
    setLoading(false)
  }

  async function selectFinding(findingId: string) {
    if (selectedId === findingId) {
      setSelectedId(null)
      return
    }
    setSelectedId(findingId)
    if (!enrichedCache[findingId]) {
      setEnrichedLoading(findingId)
      try {
        const res = await vulnMgmtApi.enrichedFinding(findingId)
        setEnrichedCache(prev => ({ ...prev, [findingId]: res.data }))
      } catch (err: any) {
        console.error('Failed to load enriched finding:', err.message)
      }
      setEnrichedLoading(null)
    }
  }

  async function updateStatus(findingId: string, newStatus: string, comment?: string) {
    setUpdating(findingId)
    try {
      await api.put(`/findings/${findingId}`, { status: newStatus })
      setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: newStatus } : f))
      // Update enriched cache too
      if (enrichedCache[findingId]) {
        setEnrichedCache(prev => ({
          ...prev,
          [findingId]: {
            ...prev[findingId],
            finding: { ...prev[findingId].finding, status: newStatus },
          },
        }))
      }
      setCommentFor(null)
      setComment('')
    } catch (err: any) {
      console.error('Failed to update status:', err.message)
    }
    setUpdating(null)
  }

  async function createRisk() {
    if (!selectedId || !riskScenario.trim()) return
    setRiskCreating(true)
    try {
      const finding = findings.find(f => f.id === selectedId)
      await risksApi.create({
        finding_id: selectedId,
        scenario: riskScenario,
        likelihood: riskLikelihood,
        impact: riskImpact,
        risk_level: riskLikelihood === 'very_high' || riskImpact === 'critical' ? 'critical'
          : riskLikelihood === 'high' || riskImpact === 'significant' ? 'high'
          : riskLikelihood === 'medium' ? 'medium' : 'low',
        treatment: 'mitigate',
      } as any)
      setShowRiskForm(false)
      setRiskScenario('')
      // Refresh enriched data
      if (selectedId) {
        try {
          const res = await vulnMgmtApi.enrichedFinding(selectedId)
          setEnrichedCache(prev => ({ ...prev, [selectedId!]: res.data }))
        } catch {}
      }
    } catch (err: any) {
      console.error('Failed to create risk:', err.message)
    }
    setRiskCreating(false)
  }

  // Derived unique values for filters
  const categories = useMemo(() => [...new Set(findings.map(f => f.category))].filter(Boolean), [findings])

  // Filtered & sorted findings
  const filteredFindings = useMemo(() => {
    let result = [...findings]
    if (filterSeverity !== 'all') result = result.filter(f => f.severity === filterSeverity)
    if (filterStatus !== 'all') result = result.filter(f => f.status === filterStatus)
    if (filterCategory !== 'all') result = result.filter(f => f.category === filterCategory)

    result.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'severity':
          cmp = (SEVERITY_ORDER[a.severity] || 0) - (SEVERITY_ORDER[b.severity] || 0)
          break
        case 'exploitability':
          cmp = (a.exploitability_score || 0) - (b.exploitability_score || 0)
          break
        case 'title':
          cmp = a.title.localeCompare(b.title)
          break
        case 'category':
          cmp = (a.category || '').localeCompare(b.category || '')
          break
        case 'status':
          cmp = a.status.localeCompare(b.status)
          break
      }
      return sortDir === 'desc' ? -cmp : cmp
    })
    return result
  }, [findings, filterSeverity, filterStatus, filterCategory, sortField, sortDir])

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('desc')
    }
  }

  const enriched = selectedId ? enrichedCache[selectedId] : null
  const isEnrichedLoading = enrichedLoading === selectedId

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    findings.forEach(f => { counts[f.status] = (counts[f.status] || 0) + 1 })
    return counts
  }, [findings])

  return (
    <div>
      <PageHeader
        title="Vulnerability Management"
        description="Track and manage vulnerability lifecycle"
        actions={
          <button onClick={loadData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
        }
      />

      {/* Top Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
        <MetricCard icon={AlertTriangle} color="text-red-500" label="Open" value={metrics?.open ?? statusCounts['open'] ?? 0} />
        <MetricCard icon={Clock} color="text-yellow-500" label="In Progress" value={metrics?.in_progress ?? statusCounts['in_progress'] ?? 0} />
        <MetricCard icon={CheckCircle2} color="text-green-500" label="Fixed" value={metrics?.fixed ?? statusCounts['fixed'] ?? 0} />
        <MetricCard icon={Shield} color="text-blue-500" label="Accepted" value={(metrics?.accepted ?? 0) + (metrics?.exception ?? 0)} />
        <MetricCard icon={CheckCircle2} color="text-emerald-600" label="Verified" value={metrics?.verified ?? statusCounts['verified'] ?? 0} />
        <MetricCard icon={ShieldAlert} color="text-red-600" label="SLA Breached" value={metrics?.sla_breached ?? 0} highlight={!!metrics?.sla_breached} />
        <MetricCard icon={Timer} color="text-purple-500" label="MTTR (days)" value={metrics?.mttr_days ?? 0} />
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : findings.length === 0 ? (
        <div className="card p-8 text-center text-gray-500">
          No findings to manage. Run an assessment workflow first.
        </div>
      ) : (
        <div className="flex gap-4">
          {/* Main Table */}
          <div className={`${selectedId ? 'w-1/2 xl:w-3/5' : 'w-full'} transition-all`}>
            <div className="card">
              {/* Filters */}
              <div className="px-4 py-3 border-b flex items-center gap-3 flex-wrap">
                <Filter className="w-4 h-4 text-gray-400" />
                <select
                  value={filterSeverity}
                  onChange={e => setFilterSeverity(e.target.value)}
                  className="text-xs border rounded px-2 py-1"
                >
                  <option value="all">All Severities</option>
                  {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <select
                  value={filterStatus}
                  onChange={e => setFilterStatus(e.target.value)}
                  className="text-xs border rounded px-2 py-1"
                >
                  <option value="all">All Statuses</option>
                  {['open', 'in_progress', 'fixed', 'accepted', 'exception', 'verified'].map(s => (
                    <option key={s} value={s}>{s.replace('_', ' ')}</option>
                  ))}
                </select>
                <select
                  value={filterCategory}
                  onChange={e => setFilterCategory(e.target.value)}
                  className="text-xs border rounded px-2 py-1"
                >
                  <option value="all">All Categories</option>
                  {categories.map(c => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
                <span className="text-xs text-gray-400 ml-auto">{filteredFindings.length} findings</span>
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b bg-gray-50">
                      <SortHeader label="Severity" field="severity" current={sortField} dir={sortDir} onSort={toggleSort} />
                      <SortHeader label="Title" field="title" current={sortField} dir={sortDir} onSort={toggleSort} />
                      <SortHeader label="Category" field="category" current={sortField} dir={sortDir} onSort={toggleSort} />
                      <SortHeader label="Exploitability" field="exploitability" current={sortField} dir={sortDir} onSort={toggleSort} />
                      <SortHeader label="Status" field="status" current={sortField} dir={sortDir} onSort={toggleSort} />
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {filteredFindings.map(f => (
                      <tr
                        key={f.id}
                        onClick={() => selectFinding(f.id)}
                        className={`cursor-pointer hover:bg-gray-50 transition-colors ${selectedId === f.id ? 'bg-brand-50 border-l-2 border-l-brand-500' : ''}`}
                      >
                        <td className="px-4 py-2.5">
                          <Badge variant={f.severity as any}>{f.severity}</Badge>
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="whitespace-pre-wrap">{f.title}</span>
                        </td>
                        <td className="px-4 py-2.5 capitalize text-gray-600">{f.category}</td>
                        <td className="px-4 py-2.5">
                          {f.exploitability_score != null ? (
                            <ExploitBar score={f.exploitability_score} />
                          ) : (
                            <span className="text-xs text-gray-400">N/A</span>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          <StatusBadge status={f.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Detail Panel */}
          {selectedId && (
            <div className="w-1/2 xl:w-2/5">
              <div className="card sticky top-4 max-h-[calc(100vh-8rem)] overflow-y-auto">
                {isEnrichedLoading ? (
                  <div className="flex items-center justify-center py-16">
                    <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                  </div>
                ) : enriched ? (
                  <div>
                    {/* Header */}
                    <div className="px-5 py-4 border-b sticky top-0 bg-white z-10">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant={enriched.finding.severity as any}>{enriched.finding.severity}</Badge>
                            <StatusBadge status={enriched.finding.status} />
                          </div>
                          <h3 className="font-semibold text-base whitespace-pre-wrap">{enriched.finding.title}</h3>
                          {enriched.asset && (
                            <p className="text-xs text-gray-500 mt-1">
                              {enriched.asset.hostname || enriched.asset.ip_address} ({enriched.asset.ip_address})
                              {enriched.asset.zone && <> &middot; {enriched.asset.zone} zone</>}
                            </p>
                          )}
                        </div>
                        <button onClick={() => setSelectedId(null)} className="text-gray-400 hover:text-gray-600 shrink-0">
                          <X className="w-5 h-5" />
                        </button>
                      </div>

                      {/* Status Transitions */}
                      {VALID_TRANSITIONS[enriched.finding.status]?.length > 0 && (
                        <div className="flex items-center gap-2 mt-3 flex-wrap">
                          {VALID_TRANSITIONS[enriched.finding.status].map(nextStatus => {
                            const needsComment = nextStatus === 'accepted' || nextStatus === 'exception'
                            return (
                              <button
                                key={nextStatus}
                                onClick={() => {
                                  if (needsComment) {
                                    setCommentFor(nextStatus)
                                  } else {
                                    updateStatus(enriched.finding.id, nextStatus)
                                  }
                                }}
                                disabled={updating === enriched.finding.id}
                                className="text-xs px-3 py-1.5 rounded-lg border border-gray-300 hover:bg-gray-50 font-medium capitalize"
                              >
                                {updating === enriched.finding.id ? '...' : nextStatus.replace('_', ' ')}
                              </button>
                            )
                          })}
                        </div>
                      )}

                      {/* Comment dialog for accept/exception */}
                      {commentFor && (
                        <div className="mt-3 p-3 bg-gray-50 rounded-lg">
                          <p className="text-xs text-gray-600 mb-2">Reason for {commentFor.replace('_', ' ')}:</p>
                          <textarea
                            value={comment}
                            onChange={e => setComment(e.target.value)}
                            className="w-full text-xs border rounded p-2 h-16"
                            placeholder="Required: Enter justification..."
                          />
                          <div className="flex gap-2 mt-2">
                            <button
                              onClick={() => { if (comment.trim()) updateStatus(enriched.finding.id, commentFor) }}
                              disabled={!comment.trim() || updating === enriched.finding.id}
                              className="text-xs px-3 py-1.5 bg-brand-600 text-white rounded-lg disabled:opacity-50"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => { setCommentFor(null); setComment('') }}
                              className="text-xs px-3 py-1.5 border rounded-lg"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="divide-y">
                      {/* Proof of Vulnerability */}
                      {enriched.finding.raw_output_snippet && (
                        <DetailSection title="Proof of Vulnerability" icon={<Bug className="w-4 h-4" />}>
                          <pre className="bg-gray-900 text-green-400 p-3 rounded-lg text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                            {enriched.finding.raw_output_snippet}
                          </pre>
                          {(enriched.finding.source_tool || enriched.finding.source_check) && (
                            <p className="text-xs text-gray-500 mt-2">
                              Detected by <span className="font-medium">{enriched.finding.source_tool}</span>
                              {enriched.finding.source_check && <> during <span className="font-medium">{enriched.finding.source_check}</span></>}
                            </p>
                          )}
                        </DetailSection>
                      )}

                      {/* Exploit Mapping */}
                      <DetailSection title="Exploit Mapping" icon={<ShieldAlert className="w-4 h-4" />}>
                        {/* CVEs */}
                        {enriched.finding.cve_ids && enriched.finding.cve_ids.length > 0 && (
                          <div className="mb-3">
                            <p className="text-xs text-gray-400 uppercase font-medium mb-1">CVE References</p>
                            <div className="flex flex-wrap gap-1.5">
                              {enriched.finding.cve_ids.map(cve => (
                                <a
                                  key={cve}
                                  href={`https://cvefeed.io/vuln/detail/${cve}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-xs bg-red-50 text-red-700 px-2 py-0.5 rounded font-mono hover:bg-red-100 flex items-center gap-1"
                                >
                                  {cve} <ExternalLink className="w-2.5 h-2.5" />
                                </a>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* CWE */}
                        {enriched.finding.cwe_id && (
                          <div className="mb-3">
                            <p className="text-xs text-gray-400 uppercase font-medium mb-1">CWE Reference</p>
                            <a
                              href={`https://cwe.mitre.org/data/definitions/${enriched.finding.cwe_id.replace('CWE-', '')}.html`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs bg-purple-50 text-purple-700 px-2 py-0.5 rounded font-mono hover:bg-purple-100 inline-flex items-center gap-1"
                            >
                              {enriched.finding.cwe_id} <ExternalLink className="w-2.5 h-2.5" />
                            </a>
                          </div>
                        )}

                        {/* Exploitability Score */}
                        {enriched.finding.exploitability_score != null && (
                          <div className="mb-3">
                            <p className="text-xs text-gray-400 uppercase font-medium mb-1">Exploitability Score</p>
                            <div className="flex items-center gap-3">
                              <div className="flex-1 bg-gray-200 rounded-full h-2.5">
                                <div
                                  className={`h-2.5 rounded-full ${
                                    enriched.finding.exploitability_score >= 7 ? 'bg-red-500'
                                    : enriched.finding.exploitability_score >= 4 ? 'bg-orange-500'
                                    : 'bg-green-500'
                                  }`}
                                  style={{ width: `${(enriched.finding.exploitability_score / 10) * 100}%` }}
                                />
                              </div>
                              <span className="text-sm font-bold">{enriched.finding.exploitability_score}/10</span>
                            </div>
                          </div>
                        )}

                        {/* Exploitability Rationale */}
                        {enriched.finding.exploitability_rationale && Object.keys(enriched.finding.exploitability_rationale).length > 0 && (
                          <div className="mb-3">
                            <p className="text-xs text-gray-400 uppercase font-medium mb-1">Exploitability Factors</p>
                            <div className="space-y-1">
                              {Object.entries(enriched.finding.exploitability_rationale).map(([key, val]) => (
                                <div key={key} className="flex items-center gap-2 text-xs">
                                  <span className="text-gray-500 capitalize">{key.replace(/_/g, ' ')}:</span>
                                  <span className="font-medium">{String(val)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* MITRE ATT&CK */}
                        {enriched.mitre_mappings.length > 0 && (
                          <div>
                            <p className="text-xs text-gray-400 uppercase font-medium mb-1">MITRE ATT&CK Techniques</p>
                            <div className="space-y-1.5">
                              {enriched.mitre_mappings.map(m => (
                                <a
                                  key={m.technique_id}
                                  href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="flex items-center gap-2 text-xs p-1.5 rounded hover:bg-gray-50"
                                >
                                  <span className="bg-brand-50 text-brand-700 px-1.5 py-0.5 rounded font-mono shrink-0">{m.technique_id}</span>
                                  <span className="text-gray-700 flex-1">{m.technique_name}</span>
                                  <span className="text-gray-400 text-[10px]">{m.tactic}</span>
                                  <span className="text-gray-400 text-[10px]">{Math.round(m.confidence * 100)}%</span>
                                </a>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Empty state */}
                        {!enriched.finding.cve_ids?.length && !enriched.finding.cwe_id && enriched.mitre_mappings.length === 0 && enriched.finding.exploitability_score == null && (
                          <p className="text-xs text-gray-400">No exploit mapping data available</p>
                        )}
                      </DetailSection>

                      {/* Risk Assessment */}
                      <DetailSection title="Risk Assessment" icon={<Shield className="w-4 h-4" />}>
                        {enriched.risks.length > 0 ? (
                          <div className="space-y-3">
                            {enriched.risks.map(r => (
                              <div key={r.id} className="p-3 bg-gray-50 rounded-lg">
                                <div className="flex items-center gap-2 mb-1">
                                  <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                                  {r.treatment && (
                                    <span className="text-[10px] text-gray-500 capitalize">{r.treatment}</span>
                                  )}
                                </div>
                                <p className="text-xs text-gray-700 whitespace-pre-wrap">{r.scenario}</p>
                                <div className="flex gap-4 mt-2 text-[10px] text-gray-500">
                                  <span>Likelihood: <span className="font-medium">{r.likelihood}</span></span>
                                  <span>Impact: <span className="font-medium">{r.impact}</span></span>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-gray-400 mb-2">No risk scenarios linked to this finding</p>
                        )}

                        <button
                          onClick={() => setShowRiskForm(!showRiskForm)}
                          className="mt-2 text-xs text-brand-600 hover:text-brand-800 font-medium flex items-center gap-1"
                        >
                          <Plus className="w-3 h-3" /> Create Risk Assessment
                        </button>

                        {showRiskForm && (
                          <div className="mt-3 p-3 bg-gray-50 rounded-lg space-y-2">
                            <textarea
                              value={riskScenario}
                              onChange={e => setRiskScenario(e.target.value)}
                              placeholder="Describe the risk scenario..."
                              className="w-full text-xs border rounded p-2 h-20"
                            />
                            <div className="flex gap-2">
                              <select value={riskLikelihood} onChange={e => setRiskLikelihood(e.target.value)} className="text-xs border rounded px-2 py-1 flex-1">
                                <option value="very_low">Very Low</option>
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="very_high">Very High</option>
                              </select>
                              <select value={riskImpact} onChange={e => setRiskImpact(e.target.value)} className="text-xs border rounded px-2 py-1 flex-1">
                                <option value="negligible">Negligible</option>
                                <option value="minor">Minor</option>
                                <option value="moderate">Moderate</option>
                                <option value="significant">Significant</option>
                                <option value="critical">Critical</option>
                              </select>
                            </div>
                            <div className="flex gap-2">
                              <button
                                onClick={createRisk}
                                disabled={!riskScenario.trim() || riskCreating}
                                className="text-xs px-3 py-1.5 bg-brand-600 text-white rounded-lg disabled:opacity-50"
                              >
                                {riskCreating ? 'Creating...' : 'Submit'}
                              </button>
                              <button onClick={() => setShowRiskForm(false)} className="text-xs px-3 py-1.5 border rounded-lg">
                                Cancel
                              </button>
                            </div>
                          </div>
                        )}
                      </DetailSection>

                      {/* Remediation */}
                      {(enriched.finding.remediation || enriched.finding.description) && (
                        <DetailSection title="Remediation & Details" icon={<FileText className="w-4 h-4" />}>
                          {enriched.finding.description && (
                            <div className="mb-3">
                              <p className="text-xs text-gray-400 uppercase font-medium mb-1">Description</p>
                              <p className="text-xs text-gray-700 whitespace-pre-wrap">{enriched.finding.description}</p>
                            </div>
                          )}
                          {enriched.finding.remediation && (
                            <div>
                              <p className="text-xs text-gray-400 uppercase font-medium mb-1">Remediation</p>
                              <p className="text-xs text-gray-700 whitespace-pre-wrap">{enriched.finding.remediation}</p>
                            </div>
                          )}
                        </DetailSection>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="p-6 text-center text-gray-400">
                    <p className="text-sm">Failed to load finding details</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}


// ─── Helper Components ────────────────────────────────────────────────

function MetricCard({ icon: Icon, color, label, value, highlight }: {
  icon: any; color: string; label: string; value: number | string; highlight?: boolean
}) {
  return (
    <div className={`card p-3 text-center ${highlight ? 'ring-2 ring-red-300 bg-red-50' : ''}`}>
      <Icon className={`w-5 h-5 mx-auto mb-1 ${color}`} />
      <p className="text-xl font-bold">{value}</p>
      <p className="text-[10px] text-gray-500">{label}</p>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: 'bg-red-100 text-red-700',
    in_progress: 'bg-yellow-100 text-yellow-700',
    fixed: 'bg-green-100 text-green-700',
    accepted: 'bg-blue-100 text-blue-700',
    exception: 'bg-blue-100 text-blue-700',
    verified: 'bg-emerald-100 text-emerald-700',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium capitalize ${colors[status] || 'bg-gray-100 text-gray-600'}`}>
      {status.replace('_', ' ')}
    </span>
  )
}

function ExploitBar({ score }: { score: number }) {
  const color = score >= 7 ? 'bg-red-500' : score >= 4 ? 'bg-orange-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 bg-gray-200 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${(score / 10) * 100}%` }} />
      </div>
      <span className="text-xs font-medium">{score}</span>
    </div>
  )
}

function SortHeader({ label, field, current, dir, onSort }: {
  label: string; field: SortField; current: SortField; dir: SortDir; onSort: (f: SortField) => void
}) {
  return (
    <th
      className="px-4 py-2.5 font-medium text-xs cursor-pointer hover:bg-gray-100 select-none"
      onClick={() => onSort(field)}
    >
      <span className="flex items-center gap-1">
        {label}
        {current === field ? (
          dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
        ) : (
          <ArrowUpDown className="w-3 h-3 text-gray-300" />
        )}
      </span>
    </th>
  )
}

function DetailSection({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="px-5 py-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-gray-500">{icon}</span>
        <h4 className="text-sm font-semibold text-gray-800">{title}</h4>
      </div>
      {children}
    </div>
  )
}
