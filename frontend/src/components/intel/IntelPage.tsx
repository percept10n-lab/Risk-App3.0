import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import StatCard from '../common/StatCard'
import Badge from '../common/Badge'
import { intelApi } from '../../api/endpoints'
import { Crosshair, AlertTriangle, Shield, Target, RefreshCw, Loader2, ChevronDown, ChevronUp, Sparkles, Newspaper, ExternalLink, Search, Globe, Activity } from 'lucide-react'

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

interface NewsArticle {
  title: string
  link: string
  source: string
  published: string
  summary: string
  iso27001_controls: Array<{ control: string; name: string; recommendation: string }>
  home_network_risk: string
}

interface NewsResponse {
  articles: NewsArticle[]
  fetched_at: string
  source_count: number
}

type Period = 1 | 7 | 30

const SOURCE_COLORS: Record<string, string> = {
  'SecurityWeek': 'bg-blue-100 text-blue-700',
  'The Hacker News': 'bg-orange-100 text-orange-700',
  'BleepingComputer': 'bg-red-100 text-red-700',
}

export default function IntelPage({ embedded }: { embedded?: boolean }) {
  const [summary, setSummary] = useState<IntelSummary | null>(null)
  const [brief, setBrief] = useState<DailyBrief | null>(null)
  const [news, setNews] = useState<NewsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [briefLoading, setBriefLoading] = useState(false)
  const [newsLoading, setNewsLoading] = useState(true)
  const [period, setPeriod] = useState<Period>(7)
  const [briefOpen, setBriefOpen] = useState(false)

  useEffect(() => {
    loadSummary(period)
  }, [period])

  useEffect(() => {
    loadBrief()
    loadNews(true)
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

  async function loadNews(force?: boolean) {
    setNewsLoading(true)
    try {
      const res = await intelApi.news(force)
      setNews(res.data)
    } catch (err: any) {
      console.error('Failed to load security news:', err.message)
    } finally {
      setNewsLoading(false)
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
      {!embedded && (
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
      )}

      {loading && !summary ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : (
        <>
          {/* Main 2-Column Layout: Sidebar (stats + lookup + brief) | News Feed */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            {/* Left Sidebar */}
            <div className="lg:col-span-1 space-y-4">
              {/* Compact Stats (2x2) */}
              <div className="grid grid-cols-2 gap-3">
                <StatCard title="Total Threats" value={summary?.totals.threats ?? 0} icon={Crosshair} color="purple" />
                <StatCard title={`New (${period === 1 ? '24h' : `${period}d`})`} value={summary?.recent_threats_count ?? 0} icon={Target} color="red" />
                <StatCard title="Open Crit/High" value={summary?.open_critical_high ?? 0} icon={AlertTriangle} color="yellow" />
                <StatCard title="Critical Risks" value={summary?.critical_risks ?? 0} icon={Shield} color="red" />
              </div>

              {/* Intelligence Lookup */}
              <IntelLookupSection />

              {/* Daily Brief (collapsed by default) */}
              <div className="card">
                <div
                  className="flex items-center justify-between px-4 py-3 cursor-pointer"
                  onClick={() => setBriefOpen(!briefOpen)}
                >
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-sm">Daily Threat Brief</h3>
                    {brief?.ai_generated && (
                      <span className="flex items-center gap-1 text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded-full">
                        <Sparkles className="w-2.5 h-2.5" /> AI
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={(e) => { e.stopPropagation(); loadBrief() }}
                      disabled={briefLoading}
                      className="p-1 rounded hover:bg-gray-100 transition-colors"
                      title="Refresh brief"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 text-gray-500 ${briefLoading ? 'animate-spin' : ''}`} />
                    </button>
                    {briefOpen ? <ChevronUp className="w-3.5 h-3.5 text-gray-400" /> : <ChevronDown className="w-3.5 h-3.5 text-gray-400" />}
                  </div>
                </div>
                {briefOpen && (
                  <div className="px-4 pb-4 border-t pt-3">
                    {briefLoading ? (
                      <div className="flex items-center justify-center py-4">
                        <Loader2 className="w-5 h-5 animate-spin text-brand-500" />
                      </div>
                    ) : brief ? (
                      <div className="prose prose-sm max-w-none text-gray-700 text-xs" dangerouslySetInnerHTML={{ __html: renderMarkdown(brief.brief) }} />
                    ) : (
                      <p className="text-xs text-gray-500">No brief available</p>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Right: Security News Feed (prominent) */}
            <div className="lg:col-span-2">
              <div className="card h-full">
                <div className="px-5 py-4 border-b flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Newspaper className="w-5 h-5 text-brand-600" />
                    <h3 className="font-semibold">Security News & Threat Briefing</h3>
                    {news && <span className="text-xs text-gray-400">{news.source_count} sources</span>}
                  </div>
                  <div className="flex items-center gap-3">
                    {news?.fetched_at && (
                      <span className="text-xs text-gray-400">
                        Updated {new Date(news.fetched_at).toLocaleTimeString()}
                      </span>
                    )}
                    <button
                      onClick={() => loadNews(true)}
                      disabled={newsLoading}
                      className="p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
                      title="Force refresh news"
                    >
                      <RefreshCw className={`w-4 h-4 text-gray-500 ${newsLoading ? 'animate-spin' : ''}`} />
                    </button>
                  </div>
                </div>
                <div className="p-5 max-h-[calc(100vh-16rem)] overflow-y-auto">
                  {newsLoading && !news ? (
                    <div className="flex items-center justify-center py-12">
                      <Loader2 className="w-6 h-6 animate-spin text-brand-500" />
                    </div>
                  ) : !news || news.articles.length === 0 ? (
                    <p className="text-sm text-gray-500 text-center py-8">No security news available. Check back later.</p>
                  ) : (
                    <div className="space-y-4">
                      {news.articles.map((article, idx) => (
                        <div key={idx} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${SOURCE_COLORS[article.source] || 'bg-gray-100 text-gray-600'}`}>
                              {article.source}
                            </span>
                            {article.published && (
                              <span className="text-xs text-gray-400">
                                {(() => {
                                  try { return new Date(article.published).toLocaleDateString() } catch { return article.published }
                                })()}
                              </span>
                            )}
                          </div>
                          <a
                            href={article.link}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sm font-semibold text-gray-900 hover:text-brand-600 flex items-start gap-1"
                          >
                            {article.title}
                            <ExternalLink className="w-3 h-3 shrink-0 mt-1 text-gray-400" />
                          </a>
                          {article.summary && (
                            <p className="text-xs text-gray-600 mt-2 line-clamp-3">{article.summary}</p>
                          )}

                          {/* ISO 27001 Controls */}
                          <div className="mt-3 p-2.5 bg-blue-50 rounded-md">
                            <p className="text-xs font-semibold text-blue-800 mb-1">ISO 27001 Controls</p>
                            {article.iso27001_controls.map((ctrl, ci) => (
                              <div key={ci} className="text-xs text-blue-700 mt-1">
                                <span className="font-mono font-medium">{ctrl.control}</span> — {ctrl.name}
                                <p className="text-blue-600 mt-0.5">{ctrl.recommendation}</p>
                              </div>
                            ))}
                          </div>

                          {/* Home Network Risk */}
                          <div className="mt-2 p-2.5 bg-amber-50 rounded-md">
                            <p className="text-xs font-semibold text-amber-800 mb-1">Home Network Impact</p>
                            <p className="text-xs text-amber-700">{article.home_network_risk}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Analytics: 3-Column Grid */}
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


function IntelLookupSection() {
  const [tab, setTab] = useState<'cve' | 'ip' | 'ioc' | 'feeds'>('cve')
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<any>(null)
  const [searching, setSearching] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = async () => {
    if (!query.trim()) return
    setSearching(true)
    setError(null)
    setResult(null)
    try {
      let res
      if (tab === 'cve') {
        res = await intelApi.lookupCve(query.trim())
      } else if (tab === 'ip') {
        res = await intelApi.lookupIp(query.trim())
      } else if (tab === 'ioc') {
        res = await intelApi.searchIoc(query.trim())
      }
      setResult(res?.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Lookup failed')
    } finally {
      setSearching(false)
    }
  }

  const handleFeedStatus = async () => {
    setSearching(true)
    setError(null)
    try {
      const res = await intelApi.feedStatus()
      setResult(res.data)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setSearching(false)
    }
  }

  return (
    <div className="card mb-6">
      <div className="px-6 py-4 border-b">
        <div className="flex items-center gap-3 mb-3">
          <Search className="w-5 h-5 text-brand-600" />
          <h3 className="font-semibold">Intelligence Lookup</h3>
        </div>
        <div className="flex gap-1">
          {([
            { id: 'cve' as const, label: 'CVE Lookup', icon: Shield },
            { id: 'ip' as const, label: 'IP Reputation', icon: Globe },
            { id: 'ioc' as const, label: 'IoC Search', icon: Target },
            { id: 'feeds' as const, label: 'Feed Status', icon: Activity },
          ]).map((t) => (
            <button
              key={t.id}
              onClick={() => { setTab(t.id); setResult(null); setError(null) }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                tab === t.id ? 'bg-brand-100 text-brand-700' : 'text-gray-500 hover:bg-gray-100'
              }`}
            >
              <t.icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          ))}
        </div>
      </div>
      <div className="p-6">
        {tab !== 'feeds' ? (
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder={
                tab === 'cve' ? 'Enter CVE ID (e.g. CVE-2024-3400)' :
                tab === 'ip' ? 'Enter IP address' :
                'Enter IoC (IP, domain, hash)'
              }
              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm"
            />
            <button
              onClick={handleSearch}
              disabled={searching || !query.trim()}
              className="btn-primary text-sm flex items-center gap-2"
            >
              {searching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Search
            </button>
          </div>
        ) : (
          <button
            onClick={handleFeedStatus}
            disabled={searching}
            className="btn-primary text-sm flex items-center gap-2 mb-4"
          >
            {searching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
            Check Feed Status
          </button>
        )}

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700 mb-4">{error}</div>
        )}

        {result && tab === 'cve' && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold">{result.cve_id}</span>
              {result.in_kev ? (
                <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs font-medium">In CISA KEV</span>
              ) : (
                <span className="px-2 py-0.5 bg-green-100 text-green-800 rounded text-xs font-medium">Not in KEV</span>
              )}
            </div>
            {result.epss && (
              <div>
                <span className="text-sm text-gray-500">EPSS: </span>
                <span className="font-bold">{(result.epss.epss_score * 100).toFixed(1)}%</span>
                <span className="text-xs text-gray-500 ml-1">(P{result.epss.percentile?.toFixed(0)})</span>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                  <div
                    className={`h-full rounded-full ${result.epss.epss_score >= 0.7 ? 'bg-red-500' : result.epss.epss_score >= 0.3 ? 'bg-yellow-500' : 'bg-green-500'}`}
                    style={{ width: `${result.epss.epss_score * 100}%` }}
                  />
                </div>
              </div>
            )}
            {result.nvd && (
              <div>
                {result.nvd.cvss_v31_score != null && (
                  <div className="text-sm">
                    <span className="text-gray-500">CVSS v3.1: </span>
                    <span className="font-bold">{result.nvd.cvss_v31_score}</span>
                    <span className="text-xs text-gray-500 ml-1">({result.nvd.cvss_v31_severity})</span>
                  </div>
                )}
                {result.nvd.description && (
                  <p className="text-sm text-gray-600 mt-1">{result.nvd.description}</p>
                )}
              </div>
            )}
            {result.kev && (
              <div className="p-2 bg-red-50 rounded text-xs text-red-700">
                <span className="font-medium">Required Action:</span> {result.kev.required_action}
              </div>
            )}
          </div>
        )}

        {result && tab === 'ip' && (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold">{result.ip}</span>
              <span className="text-sm text-gray-500">{result.sources_checked} sources checked</span>
            </div>
            {result.risk_score != null && (
              <div>
                <span className="text-sm text-gray-500">Risk Score: </span>
                <span className={`font-bold text-lg ${result.risk_score >= 70 ? 'text-red-600' : result.risk_score >= 40 ? 'text-yellow-600' : 'text-green-600'}`}>
                  {result.risk_score}/100
                </span>
              </div>
            )}
            {result.message && <p className="text-sm text-gray-500">{result.message}</p>}
            {Object.entries(result.details || {}).map(([source, data]: [string, any]) => (
              <div key={source} className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs font-semibold text-gray-700 mb-1 uppercase">{source}</p>
                {data.error ? (
                  <p className="text-xs text-red-500">{data.error}</p>
                ) : (
                  <pre className="text-xs text-gray-600 whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre>
                )}
              </div>
            ))}
          </div>
        )}

        {result && tab === 'ioc' && (
          <div className="space-y-3">
            <p className="text-sm font-medium">Results for: {result.indicator}</p>
            {result.urlhaus && (
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs font-semibold text-gray-700 mb-1">URLhaus</p>
                <p className="text-sm">URLs: {result.urlhaus.url_count} (online: {result.urlhaus.urls_online})</p>
              </div>
            )}
            {result.threatfox && (
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs font-semibold text-gray-700 mb-1">ThreatFox</p>
                <p className="text-sm">Indicators: {result.threatfox.result_count}</p>
                {result.threatfox.indicators?.slice(0, 5).map((ind: any, i: number) => (
                  <div key={i} className="text-xs text-gray-600 mt-1">
                    {ind.ioc_type}: {ind.malware} ({ind.threat_type})
                  </div>
                ))}
              </div>
            )}
            {!result.urlhaus && !result.threatfox && (
              <p className="text-sm text-gray-500">No results found for this indicator.</p>
            )}
          </div>
        )}

        {result && tab === 'feeds' && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 bg-gray-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-gray-900">{result.kev_count}</p>
                <p className="text-xs text-gray-500">KEV Entries</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-gray-900">{result.epss_count}</p>
                <p className="text-xs text-gray-500">EPSS Entries</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-gray-900">{result.cve_cached ?? result.nvd_cached ?? 0}</p>
                <p className="text-xs text-gray-500">CVE Cached</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg text-center">
                <p className="text-lg font-bold text-gray-900 capitalize">{result.mode}</p>
                <p className="text-xs text-gray-500">Feed Mode</p>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-700 mb-1">Free Sources (no API key)</p>
              <div className="flex flex-wrap gap-1">
                {(result.free_sources || []).map((s: string) => (
                  <span key={s} className="px-2 py-0.5 bg-green-100 text-green-700 rounded text-xs">{s}</span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-700 mb-1">API-Key Sources</p>
              <div className="flex flex-wrap gap-1">
                {Object.entries(result.api_sources || {}).map(([name, configured]: [string, any]) => (
                  <span
                    key={name}
                    className={`px-2 py-0.5 rounded text-xs ${configured ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}
                  >
                    {name} {configured ? '(active)' : '(not configured)'}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
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
