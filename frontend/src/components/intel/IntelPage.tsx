import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import StatCard from '../common/StatCard'
import Badge from '../common/Badge'
import { intelApi } from '../../api/endpoints'
import { Crosshair, AlertTriangle, Shield, Target, RefreshCw, Loader2, ChevronDown, ChevronUp, Sparkles } from 'lucide-react'

interface IntelSummary {
  period_days: number
  totals: { assets: number; findings: number; threats: number; risks: number }
  recent_threats_count: number
  threat_by_type: Record<string, number>
  findings_by_severity: Record<string, number>
  risk_distribution: Record<string, number>
  open_critical_high: number
  critical_risks: number
  top_mitre: Array<{ technique_id: string; technique_name: string; tactic: string; count: number }>
  asset_exposure: Array<{ asset_id: string; hostname: string | null; ip_address: string; criticality: string; threat_count: number }>
  recent_threats: Array<{ id: string; title: string; threat_type: string; confidence: number; created_at: string | null }>
}

interface DailyBrief {
  brief: string
  ai_generated: boolean
  stats: Record<string, any>
}

type Period = 1 | 7 | 30

export default function IntelPage() {
  const [summary, setSummary] = useState<IntelSummary | null>(null)
  const [brief, setBrief] = useState<DailyBrief | null>(null)
  const [loading, setLoading] = useState(true)
  const [briefLoading, setBriefLoading] = useState(false)
  const [period, setPeriod] = useState<Period>(7)
  const [briefOpen, setBriefOpen] = useState(true)

  useEffect(() => {
    loadSummary(period)
  }, [period])

  useEffect(() => {
    loadBrief()
  }, [])

  async function loadSummary(days: Period) {
    setLoading(true)
    try {
      const res = await intelApi.summary(days)
      setSummary(res.data)
    } catch (err: any) {
      console.error('Failed to load intel summary:', err.message)
    } finally {
      setLoading(false)
    }
  }

  async function loadBrief() {
    setBriefLoading(true)
    try {
      const res = await intelApi.dailyBrief()
      setBrief(res.data)
    } catch (err: any) {
      console.error('Failed to load daily brief:', err.message)
    } finally {
      setBriefLoading(false)
    }
  }

  const severityColors: Record<string, string> = {
    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500', info: 'bg-blue-300',
  }

  const strideLabels: Record<string, string> = {
    spoofing: 'Spoofing', tampering: 'Tampering', repudiation: 'Repudiation',
    information_disclosure: 'Info Disclosure', denial_of_service: 'DoS', elevation_of_privilege: 'Priv Escalation',
  }

  const maxThreatType = Math.max(1, ...Object.values(summary?.threat_by_type || {}))
  const maxSeverity = Math.max(1, ...Object.values(summary?.findings_by_severity || {}))

  return (
    <div>
      <PageHeader
        title="Threat Intelligence"
        description="Security posture overview and threat landscape analysis"
        actions={
          <div className="flex items-center gap-2">
            {([1, 7, 30] as Period[]).map((d) => (
              <button
                key={d}
                onClick={() => setPeriod(d)}
                className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                  period === d
                    ? 'bg-brand-600 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {d === 1 ? '24h' : `${d}d`}
              </button>
            ))}
          </div>
        }
      />

      {loading && !summary ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : (
        <>
          {/* Stat Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <StatCard
              title="Total Threats"
              value={summary?.totals.threats ?? 0}
              icon={Crosshair}
              color="purple"
            />
            <StatCard
              title={`New Threats (${period === 1 ? '24h' : `${period}d`})`}
              value={summary?.recent_threats_count ?? 0}
              icon={Target}
              color="red"
            />
            <StatCard
              title="Open Critical/High"
              value={summary?.open_critical_high ?? 0}
              icon={AlertTriangle}
              color="yellow"
            />
            <StatCard
              title="Critical Risks"
              value={summary?.critical_risks ?? 0}
              icon={Shield}
              color="red"
            />
          </div>

          {/* Daily Brief */}
          <div className="card mb-6">
            <div
              className="flex items-center justify-between px-6 py-4 cursor-pointer"
              onClick={() => setBriefOpen(!briefOpen)}
            >
              <div className="flex items-center gap-3">
                <h3 className="font-semibold">Daily Threat Brief</h3>
                {brief?.ai_generated && (
                  <span className="flex items-center gap-1 text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">
                    <Sparkles className="w-3 h-3" /> AI Generated
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={(e) => { e.stopPropagation(); loadBrief() }}
                  disabled={briefLoading}
                  className="p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
                  title="Refresh brief"
                >
                  <RefreshCw className={`w-4 h-4 text-gray-500 ${briefLoading ? 'animate-spin' : ''}`} />
                </button>
                {briefOpen ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
              </div>
            </div>
            {briefOpen && (
              <div className="px-6 pb-6 border-t pt-4">
                {briefLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                  </div>
                ) : brief ? (
                  <div className="prose prose-sm max-w-none text-gray-700" dangerouslySetInnerHTML={{ __html: renderMarkdown(brief.brief) }} />
                ) : (
                  <p className="text-sm text-gray-500">No brief available</p>
                )}
              </div>
            )}
          </div>

          {/* 3-Column Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            {/* Findings by Severity */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Findings by Severity</h3>
              <div className="space-y-3">
                {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                  const count = summary?.findings_by_severity[sev] || 0
                  const pct = Math.round((count / maxSeverity) * 100) || 0
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <Badge variant={sev === 'info' ? 'info' : sev as any}>{sev}</Badge>
                      <div className="flex-1 bg-gray-100 rounded-full h-2">
                        <div className={`h-2 rounded-full ${severityColors[sev]}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-sm text-gray-600 w-8 text-right">{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Threat Categories */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Threat Categories</h3>
              {Object.keys(summary?.threat_by_type || {}).length === 0 ? (
                <p className="text-sm text-gray-500">No threats in this period</p>
              ) : (
                <div className="space-y-3">
                  {Object.entries(summary?.threat_by_type || {}).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
                    const pct = Math.round((count / maxThreatType) * 100) || 0
                    return (
                      <div key={type} className="flex items-center gap-3">
                        <span className="text-xs font-medium text-gray-600 w-24 truncate" title={strideLabels[type] || type}>
                          {strideLabels[type] || type}
                        </span>
                        <div className="flex-1 bg-gray-100 rounded-full h-2">
                          <div className="h-2 rounded-full bg-brand-500" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-sm text-gray-600 w-8 text-right">{count}</span>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Top MITRE Techniques */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Top MITRE Techniques</h3>
              {(summary?.top_mitre?.length || 0) === 0 ? (
                <p className="text-sm text-gray-500">No MITRE mappings yet</p>
              ) : (
                <div className="space-y-2.5">
                  {summary?.top_mitre.map((m) => (
                    <div key={m.technique_id} className="flex items-center gap-2">
                      <span className="bg-brand-50 text-brand-700 px-1.5 py-0.5 rounded text-xs font-mono shrink-0">
                        {m.technique_id}
                      </span>
                      <span className="text-sm text-gray-700 flex-1 truncate" title={m.technique_name}>
                        {m.technique_name}
                      </span>
                      <span className="text-xs text-gray-400">{m.tactic}</span>
                      <span className="text-sm font-medium text-gray-600 w-6 text-right">{m.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* 2-Column Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Asset Exposure */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Asset Exposure</h3>
              {(summary?.asset_exposure?.length || 0) === 0 ? (
                <p className="text-sm text-gray-500">No asset-threat associations found</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-500 border-b">
                        <th className="pb-2 font-medium">Host</th>
                        <th className="pb-2 font-medium">IP</th>
                        <th className="pb-2 font-medium">Criticality</th>
                        <th className="pb-2 font-medium text-right">Threats</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {summary?.asset_exposure.map((a) => (
                        <tr key={a.asset_id} className="hover:bg-gray-50">
                          <td className="py-2 font-medium">{a.hostname || '—'}</td>
                          <td className="py-2 font-mono text-xs">{a.ip_address}</td>
                          <td className="py-2">
                            <Badge variant={a.criticality === 'critical' ? 'critical' : a.criticality === 'high' ? 'high' : a.criticality === 'medium' ? 'medium' : 'low'}>
                              {a.criticality}
                            </Badge>
                          </td>
                          <td className="py-2 text-right font-medium">{a.threat_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Recent Threats */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold mb-4">Recent Threats</h3>
              {(summary?.recent_threats?.length || 0) === 0 ? (
                <p className="text-sm text-gray-500">No threats recorded yet</p>
              ) : (
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {summary?.recent_threats.map((t) => (
                    <div key={t.id} className="flex items-start gap-3 p-2 rounded-lg hover:bg-gray-50">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{t.title}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="info">{t.threat_type}</Badge>
                          <span className="text-xs text-gray-400">
                            {t.confidence != null ? `${Math.round(t.confidence * 100)}%` : ''}
                          </span>
                          {t.created_at && (
                            <span className="text-xs text-gray-400">
                              {new Date(t.created_at).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}


/** Simple markdown to HTML for the daily brief. */
function renderMarkdown(md: string): string {
  return md
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h3 class="text-base font-semibold mt-4 mb-2">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold mt-4 mb-2">$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^\- (.+)$/gm, '<li class="ml-4 list-disc">$1</li>')
    .replace(/^\| (.+)$/gm, (line) => {
      const cells = line.split('|').filter(c => c.trim()).map(c => c.trim())
      if (cells.every(c => /^-+$/.test(c))) return ''
      const tag = 'td'
      return '<tr>' + cells.map(c => `<${tag} class="border px-2 py-1 text-sm">${c}</${tag}>`).join('') + '</tr>'
    })
    .replace(/(<tr>.*<\/tr>\n?)+/g, (match) => `<table class="w-full border-collapse border my-2">${match}</table>`)
    .replace(/\n\n/g, '<br/><br/>')
    .replace(/\n/g, '<br/>')
}
