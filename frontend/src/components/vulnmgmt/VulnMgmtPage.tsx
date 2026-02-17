import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { AlertTriangle, CheckCircle2, Clock, Shield, RefreshCw, ChevronDown, ChevronUp, Loader2 } from 'lucide-react'
import api from '../../api/client'

interface FindingInfo {
  id: string
  title: string
  severity: string
  category: string
  asset_id: string
  status: string
}

interface FindingDetail {
  id: string; title: string; severity: string; category: string; status: string
  description?: string; remediation?: string; evidence?: string
  asset_id?: string; source_tool?: string; created_at?: string
}

interface VulnMetrics {
  total_findings: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  [key: string]: unknown
}

interface FindingContext {
  finding: FindingDetail
  asset: { id: string; hostname: string | null; ip_address: string; asset_type: string; zone: string; criticality: string } | null
  mitre_mappings: Array<{ technique_id: string; technique_name: string; tactic: string }>
  risks: Array<{ id: string; scenario: string; risk_level: string }>
}

export default function VulnMgmtPage() {
  const [findings, setFindings] = useState<FindingInfo[]>([])
  const [metrics, setMetrics] = useState<VulnMetrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [contextCache, setContextCache] = useState<Record<string, FindingContext>>({})
  const [contextLoading, setContextLoading] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setLoading(true)
    try {
      const [findingsRes, metricsRes] = await Promise.allSettled([
        api.get('/findings', { params: { page_size: 100 } }),
        api.get('/vulns/metrics'),
      ])
      if (findingsRes.status === 'fulfilled') {
        setFindings(findingsRes.value.data.items || [])
      }
      if (metricsRes.status === 'fulfilled') {
        setMetrics(metricsRes.value.data)
      }
    } catch (err: any) { console.error('Failed to load vuln data:', err.message) }
    setLoading(false)
  }

  async function updateStatus(findingId: string, newStatus: string) {
    setUpdating(findingId)
    try {
      await api.put(`/findings/${findingId}`, { status: newStatus })
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
      )
    } catch (err: any) { console.error('Failed to update finding status:', err.message) }
    setUpdating(null)
  }

  async function toggleExpand(findingId: string) {
    if (expandedId === findingId) {
      setExpandedId(null)
      return
    }
    setExpandedId(findingId)
    if (!contextCache[findingId]) {
      setContextLoading(findingId)
      try {
        const res = await api.get(`/findings/${findingId}/context`)
        setContextCache((prev) => ({ ...prev, [findingId]: res.data }))
      } catch (err: any) { console.error('Failed to load finding context:', err.message) }
      setContextLoading(null)
    }
  }

  const grouped = {
    open: findings.filter((f) => f.status === 'open'),
    in_progress: findings.filter((f) => f.status === 'in_progress'),
    fixed: findings.filter((f) => f.status === 'fixed'),
    accepted: findings.filter((f) => f.status === 'accepted' || f.status === 'exception'),
    verified: findings.filter((f) => f.status === 'verified'),
  }

  const statusFlow: Array<{ key: string; label: string; icon: any; color: string }> = [
    { key: 'open', label: 'Open', icon: AlertTriangle, color: 'text-red-500' },
    { key: 'in_progress', label: 'In Progress', icon: Clock, color: 'text-yellow-500' },
    { key: 'fixed', label: 'Fixed', icon: CheckCircle2, color: 'text-green-500' },
    { key: 'accepted', label: 'Accepted/Exception', icon: Shield, color: 'text-blue-500' },
    { key: 'verified', label: 'Verified', icon: CheckCircle2, color: 'text-emerald-600' },
  ]

  const nextStatus: Record<string, string> = {
    open: 'in_progress',
    in_progress: 'fixed',
    fixed: 'verified',
  }

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

      {/* Metrics summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        {statusFlow.map((s) => (
          <div key={s.key} className="card p-4 text-center">
            <s.icon className={`w-6 h-6 mx-auto mb-1 ${s.color}`} />
            <p className="text-2xl font-bold">{grouped[s.key as keyof typeof grouped]?.length || 0}</p>
            <p className="text-xs text-gray-500">{s.label}</p>
          </div>
        ))}
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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Kanban-style columns for main statuses */}
          {['open', 'in_progress', 'fixed'].map((statusKey) => {
            const items = grouped[statusKey as keyof typeof grouped] || []
            const config = statusFlow.find((s) => s.key === statusKey)!
            return (
              <div key={statusKey} className="card">
                <div className="px-4 py-3 border-b flex items-center gap-2">
                  <config.icon className={`w-4 h-4 ${config.color}`} />
                  <h3 className="font-semibold text-sm">{config.label}</h3>
                  <span className="ml-auto text-xs bg-gray-100 px-2 py-0.5 rounded-full">{items.length}</span>
                </div>
                <div className="p-3 space-y-2 max-h-[600px] overflow-y-auto">
                  {items.length === 0 ? (
                    <p className="text-xs text-gray-400 text-center py-4">No items</p>
                  ) : (
                    items.map((f) => {
                      const isExpanded = expandedId === f.id
                      const ctx = contextCache[f.id]
                      const isCtxLoading = contextLoading === f.id
                      return (
                        <div key={f.id} className="bg-gray-50 rounded-lg overflow-hidden">
                          <div className="p-3">
                            <div className="flex items-start justify-between gap-2">
                              <Badge variant={f.severity as any}>{f.severity}</Badge>
                              <button
                                onClick={() => toggleExpand(f.id)}
                                className="text-gray-400 hover:text-gray-600 shrink-0"
                              >
                                {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                              </button>
                            </div>
                            <p className="text-sm font-medium mt-1.5 line-clamp-2">{f.title}</p>
                            <p className="text-xs text-gray-500 mt-1 capitalize">{f.category}</p>
                            {nextStatus[statusKey] && (
                              <button
                                onClick={() => updateStatus(f.id, nextStatus[statusKey])}
                                disabled={updating === f.id}
                                className="mt-2 text-xs text-brand-600 hover:text-brand-800 font-medium"
                              >
                                {updating === f.id ? 'Updating...' : `Move to ${nextStatus[statusKey].replace('_', ' ')}`}
                              </button>
                            )}
                          </div>

                          {/* Expanded Detail */}
                          {isExpanded && (
                            <div className="border-t px-3 py-3 bg-white space-y-3">
                              {isCtxLoading ? (
                                <div className="flex items-center gap-2 text-xs text-gray-500">
                                  <Loader2 className="w-3 h-3 animate-spin" /> Loading details...
                                </div>
                              ) : ctx ? (
                                <>
                                  {/* Asset */}
                                  {ctx.asset && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">Asset</p>
                                      <button
                                        onClick={() => navigate(`/assets/${ctx.asset!.id}`)}
                                        className="text-sm text-brand-600 hover:text-brand-800 font-medium"
                                      >
                                        {ctx.asset.hostname || ctx.asset.ip_address} ({ctx.asset.ip_address})
                                      </button>
                                    </div>
                                  )}

                                  {/* Description */}
                                  {ctx.finding?.description && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">Description</p>
                                      <p className="text-xs text-gray-700 line-clamp-4">{ctx.finding.description}</p>
                                    </div>
                                  )}

                                  {/* Remediation */}
                                  {ctx.finding?.remediation && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">Remediation</p>
                                      <p className="text-xs text-gray-700">{ctx.finding.remediation}</p>
                                    </div>
                                  )}

                                  {/* CWE */}
                                  {ctx.finding?.cwe_id && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">CWE</p>
                                      <Badge variant="info">{ctx.finding.cwe_id}</Badge>
                                    </div>
                                  )}

                                  {/* Evidence */}
                                  {ctx.finding?.raw_output_snippet && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">Evidence</p>
                                      <pre className="bg-gray-900 text-green-400 p-2 rounded text-xs overflow-x-auto max-h-24 overflow-y-auto">
                                        {ctx.finding.raw_output_snippet}
                                      </pre>
                                    </div>
                                  )}

                                  {/* MITRE */}
                                  {ctx.mitre_mappings?.length > 0 && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">MITRE Techniques</p>
                                      <div className="flex flex-wrap gap-1">
                                        {ctx.mitre_mappings.map((m) => (
                                          <span key={m.technique_id} className="bg-brand-50 text-brand-700 px-1.5 py-0.5 rounded text-xs font-mono">
                                            {m.technique_id}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Risks */}
                                  {ctx.risks?.length > 0 && (
                                    <div>
                                      <p className="text-xs text-gray-400 uppercase font-medium mb-1">Impact</p>
                                      <div className="space-y-1">
                                        {ctx.risks.map((r) => (
                                          <div key={r.id} className="flex items-start gap-2">
                                            <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                                            <p className="text-xs text-gray-600 line-clamp-2">{r.scenario}</p>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </>
                              ) : (
                                <p className="text-xs text-gray-400">Failed to load details</p>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
