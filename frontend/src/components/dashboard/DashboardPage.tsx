import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import StatCard from '../common/StatCard'
import Badge from '../common/Badge'
import { Monitor, AlertTriangle, Shield, Target, Bug, CheckCircle, FileText, Crosshair, X, Loader2 } from 'lucide-react'
import api from '../../api/client'

interface DashboardStats {
  total_assets: number
  total_findings: number
  total_risks: number
  total_threats: number
  findings_by_severity: Record<string, number>
  risks_by_level: Record<string, number>
  recent_findings: Array<{ id: string; title: string; severity: string; category: string }>
}

interface ModalFinding {
  id: string; title: string; severity: string; description: string; category: string
  asset?: { hostname: string | null; ip_address: string } | null
  mitre_techniques?: Array<{ technique_id: string; technique_name: string }> | null
}

interface ModalRisk {
  id: string; scenario: string; risk_level: string; likelihood: string; impact: string
  asset?: { hostname: string | null; ip_address: string } | null
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  // Modal state
  const [sevModal, setSevModal] = useState<{ severity: string; items: ModalFinding[]; loading: boolean } | null>(null)
  const [riskModal, setRiskModal] = useState<{ level: string; items: ModalRisk[]; loading: boolean } | null>(null)

  useEffect(() => {
    async function loadStats() {
      try {
        const [assetsRes, findingsRes, risksRes, threatsRes, findingsDetailRes] = await Promise.allSettled([
          api.get('/assets', { params: { page_size: 1 } }),
          api.get('/findings', { params: { page_size: 1 } }),
          api.get('/risks', { params: { page_size: 1 } }),
          api.get('/threats', { params: { page_size: 1 } }),
          api.get('/findings', { params: { page_size: 10 } }),
        ])

        const findingsAll = findingsDetailRes.status === 'fulfilled' ? findingsDetailRes.value.data.items || [] : []

        const findingsBySeverity: Record<string, number> = {}
        findingsAll.forEach((f: any) => {
          findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1
        })

        let risksByLevel: Record<string, number> = {}
        try {
          const risksDetailRes = await api.get('/risks', { params: { page_size: 100 } })
          const allRisks = risksDetailRes.data.items || []
          allRisks.forEach((r: any) => {
            risksByLevel[r.risk_level] = (risksByLevel[r.risk_level] || 0) + 1
          })
        } catch { /* empty */ }

        setStats({
          total_assets: assetsRes.status === 'fulfilled' ? assetsRes.value.data.total : 0,
          total_findings: findingsRes.status === 'fulfilled' ? findingsRes.value.data.total : 0,
          total_risks: risksRes.status === 'fulfilled' ? risksRes.value.data.total : 0,
          total_threats: threatsRes.status === 'fulfilled' ? threatsRes.value.data.total : 0,
          findings_by_severity: findingsBySeverity,
          risks_by_level: risksByLevel,
          recent_findings: findingsAll.slice(0, 5),
        })
      } catch {
        setStats({
          total_assets: 0, total_findings: 0, total_risks: 0, total_threats: 0,
          findings_by_severity: {}, risks_by_level: {}, recent_findings: [],
        })
      } finally {
        setLoading(false)
      }
    }
    loadStats()
  }, [])

  async function openSeverityModal(severity: string) {
    setSevModal({ severity, items: [], loading: true })
    try {
      const res = await api.get('/findings', {
        params: { severity, page_size: 50, include_asset: true, include_mitre: true },
      })
      setSevModal({ severity, items: res.data.items || [], loading: false })
    } catch {
      setSevModal({ severity, items: [], loading: false })
    }
  }

  async function openRiskModal(level: string) {
    setRiskModal({ level, items: [], loading: true })
    try {
      const res = await api.get('/risks', {
        params: { risk_level: level, page_size: 50, include_asset: true },
      })
      setRiskModal({ level, items: res.data.items || [], loading: false })
    } catch {
      setRiskModal({ level, items: [], loading: false })
    }
  }

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Home Network Security Overview"
      />

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard title="Total Assets" value={stats?.total_assets ?? 0} icon={Monitor} color="blue" onClick={() => navigate('/assets')} />
            <StatCard title="Findings" value={stats?.total_findings ?? 0} icon={AlertTriangle} color="yellow" onClick={() => navigate('/findings')} />
            <StatCard title="Risks" value={stats?.total_risks ?? 0} icon={Shield} color="red" onClick={() => navigate('/risks')} />
            <StatCard title="Threats" value={stats?.total_threats ?? 0} icon={Target} color="purple" onClick={() => navigate('/mitre')} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Findings by Severity */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Findings by Severity</h3>
              <div className="space-y-3">
                {['critical', 'high', 'medium', 'low'].map((sev) => {
                  const count = stats?.findings_by_severity[sev] || 0
                  const total = stats?.total_findings || 1
                  const pct = Math.round((count / total) * 100) || 0
                  const colors: Record<string, string> = {
                    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500',
                  }
                  return (
                    <div
                      key={sev}
                      className="flex items-center gap-3 cursor-pointer hover:bg-gray-50 rounded-lg p-1 -m-1 transition-colors"
                      onClick={() => openSeverityModal(sev)}
                    >
                      <Badge variant={sev as any}>{sev}</Badge>
                      <div className="flex-1 bg-gray-100 rounded-full h-2">
                        <div className={`h-2 rounded-full ${colors[sev]}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-sm text-gray-600 w-8 text-right">{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Risk Distribution */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Risk Distribution</h3>
              <div className="space-y-3">
                {['critical', 'high', 'medium', 'low'].map((level) => {
                  const count = stats?.risks_by_level[level] || 0
                  const total = stats?.total_risks || 1
                  const pct = Math.round((count / total) * 100) || 0
                  const colors: Record<string, string> = {
                    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500',
                  }
                  return (
                    <div
                      key={level}
                      className="flex items-center gap-3 cursor-pointer hover:bg-gray-50 rounded-lg p-1 -m-1 transition-colors"
                      onClick={() => openRiskModal(level)}
                    >
                      <Badge variant={level as any}>{level}</Badge>
                      <div className="flex-1 bg-gray-100 rounded-full h-2">
                        <div className={`h-2 rounded-full ${colors[level]}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-sm text-gray-600 w-8 text-right">{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Quick Actions */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
              <div className="space-y-3">
                <button onClick={() => navigate('/workflow')} className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 transition-colors w-full text-left">
                  <div className="w-10 h-10 rounded-lg bg-brand-50 text-brand-600 flex items-center justify-center">
                    <Bug className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-medium text-sm">Start New Scan</p>
                    <p className="text-xs text-gray-500">Run discovery and vulnerability scanning</p>
                  </div>
                </button>
                <button onClick={() => navigate('/copilot')} className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 transition-colors w-full text-left">
                  <div className="w-10 h-10 rounded-lg bg-yellow-50 text-yellow-600 flex items-center justify-center">
                    <Crosshair className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-medium text-sm">AI Triage</p>
                    <p className="text-xs text-gray-500">Get AI-assisted finding prioritization</p>
                  </div>
                </button>
                <button onClick={() => navigate('/reports')} className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 transition-colors w-full text-left">
                  <div className="w-10 h-10 rounded-lg bg-green-50 text-green-600 flex items-center justify-center">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-medium text-sm">Generate Report</p>
                    <p className="text-xs text-gray-500">Create security assessment report</p>
                  </div>
                </button>
              </div>
            </div>
          </div>

          {/* Recent Findings */}
          {(stats?.recent_findings?.length ?? 0) > 0 && (
            <div className="card p-6 mt-6">
              <h3 className="text-lg font-semibold mb-4">Recent Findings</h3>
              <div className="space-y-2">
                {stats?.recent_findings.map((f) => (
                  <div
                    key={f.id}
                    className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => navigate(`/findings/${f.id}`)}
                  >
                    <Badge variant={f.severity as any}>{f.severity}</Badge>
                    <p className="text-sm flex-1 truncate">{f.title}</p>
                    <span className="text-xs text-gray-400 capitalize">{f.category}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Severity Drill-Down Modal */}
      {sevModal && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setSevModal(null)}>
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Badge variant={sevModal.severity as any}>{sevModal.severity}</Badge>
                <h3 className="font-semibold text-lg">Findings</h3>
                <span className="text-sm text-gray-500">({sevModal.items.length})</span>
              </div>
              <button onClick={() => setSevModal(null)} className="text-gray-400 hover:text-gray-600">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="overflow-y-auto flex-1 divide-y">
              {sevModal.loading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                </div>
              ) : sevModal.items.length === 0 ? (
                <div className="p-6 text-center text-gray-500 text-sm">No findings with this severity</div>
              ) : (
                sevModal.items.map((f) => (
                  <div
                    key={f.id}
                    className="px-6 py-4 hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => { setSevModal(null); navigate(`/findings/${f.id}`) }}
                  >
                    <div className="flex items-center gap-3 mb-1">
                      <Badge variant={f.severity as any}>{f.severity}</Badge>
                      <span className="font-medium text-sm flex-1 truncate">{f.title}</span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      {f.asset && (
                        <span>Host: {f.asset.hostname || f.asset.ip_address}</span>
                      )}
                      {f.mitre_techniques && f.mitre_techniques.length > 0 && (
                        <div className="flex gap-1 flex-wrap">
                          {f.mitre_techniques.slice(0, 3).map((t) => (
                            <span key={t.technique_id} className="bg-brand-50 text-brand-700 px-1.5 py-0.5 rounded text-xs font-mono">
                              {t.technique_id}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    {f.description && (
                      <p className="text-xs text-gray-500 mt-1 line-clamp-2">{f.description}</p>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Risk Drill-Down Modal */}
      {riskModal && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setRiskModal(null)}>
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Badge variant={riskModal.level as any}>{riskModal.level}</Badge>
                <h3 className="font-semibold text-lg">Risk Scenarios</h3>
                <span className="text-sm text-gray-500">({riskModal.items.length})</span>
              </div>
              <button onClick={() => setRiskModal(null)} className="text-gray-400 hover:text-gray-600">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="overflow-y-auto flex-1 divide-y">
              {riskModal.loading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                </div>
              ) : riskModal.items.length === 0 ? (
                <div className="p-6 text-center text-gray-500 text-sm">No risks at this level</div>
              ) : (
                riskModal.items.map((r) => (
                  <div key={r.id} className="px-6 py-4">
                    <div className="flex items-center gap-3 mb-2">
                      <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                      <span className="text-xs text-gray-500">L: {r.likelihood} / I: {r.impact}</span>
                      {r.asset && (
                        <span className="text-xs text-gray-500 ml-auto">
                          Host: {r.asset.hostname || r.asset.ip_address}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-700">{r.scenario}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
