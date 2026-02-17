import { useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useThreatIntelStore } from '../../stores/threatIntelStore'
import Badge from '../common/Badge'
import {
  RefreshCw, AlertTriangle, Shield, Activity, Clock,
  ChevronRight, ExternalLink, Copy, Loader2, Zap,
  Database, Globe, FileWarning, TrendingUp, Server,
  CheckCircle2, XCircle, ArrowUpRight,
} from 'lucide-react'

const TYPE_LABELS: Record<string, string> = {
  exploited_cve: 'Exploited CVE',
  high_risk_cve: 'High-risk CVE',
  advisory: 'Advisory',
  campaign: 'Campaign',
  ransomware: 'Ransomware',
}

const TYPE_COLORS: Record<string, string> = {
  exploited_cve: 'bg-red-100 text-red-800',
  high_risk_cve: 'bg-orange-100 text-orange-800',
  advisory: 'bg-blue-100 text-blue-800',
  campaign: 'bg-purple-100 text-purple-800',
}

const BADGE_COLORS: Record<string, string> = {
  kev: 'bg-red-600 text-white',
  cisa_kev: 'bg-red-600 text-white',
  'CISA-KEV': 'bg-red-600 text-white',
  nvd: 'bg-blue-600 text-white',
  epss: 'bg-amber-600 text-white',
  first_epss: 'bg-amber-600 text-white',
  cert_bund: 'bg-yellow-600 text-white',
  'CERT-Bund': 'bg-yellow-600 text-white',
  BSI: 'bg-yellow-600 text-white',
  ENISA: 'bg-indigo-600 text-white',
}

function timeAgo(ts: string | null): string {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export default function ThreatIntelLanding() {
  const {
    triage, counters, kevLatest, epssTop, advisoriesLatest, connectors,
    loading, ingesting, error, timeWindow,
    setTimeWindow, fetchDashboard, runIngest,
  } = useThreatIntelStore()
  const navigate = useNavigate()

  useEffect(() => { fetchDashboard() }, [])

  const copyList = (items: { primary_id: string }[]) => {
    navigator.clipboard.writeText(items.map(i => i.primary_id).join('\n'))
  }

  return (
    <div className="space-y-5">
      {/* ── Top bar: Global controls ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Threat Intelligence</h1>
          <p className="text-sm text-gray-500 mt-0.5">Security triage signals from free, reputable sources</p>
        </div>
        <div className="flex items-center gap-3">
          {/* Time window */}
          <div className="flex bg-gray-100 rounded-lg p-0.5">
            {([24, 72, 168] as const).map(h => (
              <button
                key={h}
                onClick={() => setTimeWindow(h)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                  timeWindow === h ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                {h === 24 ? '24h' : h === 72 ? '72h' : '7d'}
              </button>
            ))}
          </div>
          {/* Ingest */}
          <button
            onClick={runIngest}
            disabled={ingesting}
            className="btn-primary flex items-center gap-2 text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${ingesting ? 'animate-spin' : ''}`} />
            {ingesting ? 'Fetching...' : 'Fetch Sources'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {/* ── B) Key Counters ── */}
      {counters && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
          <CounterCard
            label="KEV Additions" sublabel="7d" value={counters.kev_additions_7d}
            icon={<Zap className="w-4 h-4" />} color="red"
            onClick={() => navigate('/intel/vulnerabilities?kev_only=true')}
          />
          <CounterCard
            label="Exploited ITW" sublabel="72h" value={counters.exploited_wild_72h}
            icon={<AlertTriangle className="w-4 h-4" />} color="red"
            onClick={() => navigate('/intel/vulnerabilities?kev_only=true')}
          />
          <CounterCard
            label="High EPSS" sublabel="72h" value={counters.high_epss_72h}
            icon={<TrendingUp className="w-4 h-4" />} color="amber"
            onClick={() => navigate('/intel/vulnerabilities?min_epss=0.7')}
          />
          <CounterCard
            label="Critical Advisories" sublabel="72h" value={counters.critical_advisories_72h}
            icon={<FileWarning className="w-4 h-4" />} color="orange"
            onClick={() => navigate('/intel/advisories?severity=critical')}
          />
          <CounterCard
            label="National Adv." sublabel="72h" value={counters.national_advisories_72h}
            icon={<Globe className="w-4 h-4" />} color="blue"
            onClick={() => navigate('/intel/advisories?issuer=CERT-Bund')}
          />
          <CounterCard
            label="Total CVEs" sublabel="" value={counters.total_cves}
            icon={<Database className="w-4 h-4" />} color="gray"
            onClick={() => navigate('/intel/vulnerabilities')}
          />
          <CounterCard
            label="Total Advisories" sublabel="" value={counters.total_advisories}
            icon={<Shield className="w-4 h-4" />} color="gray"
            onClick={() => navigate('/intel/advisories')}
          />
        </div>
      )}

      {/* ── A) Today's Triage (primary widget) ── */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Zap className="w-4 h-4 text-red-500" />
            Today's Triage
            <span className="text-xs font-normal text-gray-400 ml-1">max 12 items, ranked by UrgencyScore</span>
          </h2>
          <button
            onClick={() => copyList(triage)}
            className="text-xs text-gray-400 hover:text-gray-600 flex items-center gap-1"
            title="Copy ID list"
          >
            <Copy className="w-3.5 h-3.5" /> Copy IDs
          </button>
        </div>
        <div className="divide-y divide-gray-50">
          {loading && triage.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-gray-400">
              <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading triage...
            </div>
          ) : triage.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-400">
              <Shield className="w-10 h-10 mb-2" />
              <p className="text-sm font-medium">No triage items yet</p>
              <p className="text-xs mt-1">Click "Fetch Sources" to ingest threat intelligence data</p>
            </div>
          ) : (
            triage.map((item) => (
              <div
                key={item.id}
                onClick={() => item.deep_link && navigate(item.deep_link.replace(/^\//, '/intel/'))}
                className="flex items-center gap-4 px-5 py-3 hover:bg-gray-50 cursor-pointer group transition-colors"
              >
                {/* Score */}
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold shrink-0 ${
                  item.urgency_score >= 80 ? 'bg-red-100 text-red-700' :
                  item.urgency_score >= 60 ? 'bg-orange-100 text-orange-700' :
                  'bg-yellow-100 text-yellow-700'
                }`}>
                  {item.urgency_score}
                </div>
                {/* Type badge */}
                <span className={`text-xs font-medium px-2 py-0.5 rounded shrink-0 ${TYPE_COLORS[item.item_type] || 'bg-gray-100 text-gray-700'}`}>
                  {TYPE_LABELS[item.item_type] || item.item_type}
                </span>
                {/* ID */}
                <code className="text-sm font-mono font-semibold text-gray-800 shrink-0 w-36 truncate">
                  {item.primary_id}
                </code>
                {/* Why here */}
                <span className="text-sm text-gray-500 flex-1 truncate">{item.why_here}</span>
                {/* Source badges */}
                <div className="flex items-center gap-1 shrink-0">
                  {(item.source_badges || []).slice(0, 4).map((badge) => (
                    <span key={badge} className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${BADGE_COLORS[badge] || 'bg-gray-200 text-gray-700'}`}>
                      {badge.replace('_', '-').toUpperCase()}
                    </span>
                  ))}
                </div>
                {/* Timestamp */}
                <span className="text-xs text-gray-400 shrink-0 flex items-center gap-1">
                  <Clock className="w-3 h-3" /> {timeAgo(item.updated_at)}
                </span>
                <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500 shrink-0" />
              </div>
            ))
          )}
        </div>
      </div>

      {/* ── Two-column: Exploit Pressure + Advisories ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* C) Exploit Pressure */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
          <div className="px-5 py-4 border-b border-gray-100">
            <h2 className="text-base font-semibold flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-500" /> Exploit Pressure
            </h2>
          </div>
          <div className="grid grid-cols-2 divide-x divide-gray-100">
            {/* KEV latest */}
            <div>
              <div className="px-4 py-2 border-b border-gray-50">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">KEV Latest</span>
              </div>
              <div className="divide-y divide-gray-50">
                {kevLatest.slice(0, 8).map(cve => (
                  <Link
                    key={cve.cve_id}
                    to={`/intel/vulnerabilities?search=${cve.cve_id}`}
                    className="block px-4 py-2.5 hover:bg-red-50/50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <code className="text-xs font-mono font-semibold text-gray-800">{cve.cve_id}</code>
                      {cve.cvss_base && (
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          cve.cvss_base >= 9 ? 'bg-red-100 text-red-700' :
                          cve.cvss_base >= 7 ? 'bg-orange-100 text-orange-700' :
                          'bg-yellow-100 text-yellow-700'
                        }`}>
                          {cve.cvss_base.toFixed(1)}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5 truncate">
                      {cve.product_summary || cve.vendor_project || '—'}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      {cve.epss_score != null && (
                        <span className="text-[10px] text-amber-600 font-medium">EPSS {(cve.epss_score * 100).toFixed(0)}%</span>
                      )}
                      {!cve.patch_available && (
                        <span className="text-[10px] text-red-600 font-medium">No patch</span>
                      )}
                    </div>
                  </Link>
                ))}
                {kevLatest.length === 0 && (
                  <div className="px-4 py-8 text-center text-xs text-gray-400">No KEV data</div>
                )}
              </div>
            </div>
            {/* EPSS top */}
            <div>
              <div className="px-4 py-2 border-b border-gray-50">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">High EPSS</span>
              </div>
              <div className="divide-y divide-gray-50">
                {epssTop.slice(0, 8).map(cve => (
                  <Link
                    key={cve.cve_id}
                    to={`/intel/vulnerabilities?search=${cve.cve_id}`}
                    className="block px-4 py-2.5 hover:bg-amber-50/50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <code className="text-xs font-mono font-semibold text-gray-800">{cve.cve_id}</code>
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-100 text-amber-700">
                        EPSS {cve.epss_score != null ? (cve.epss_score * 100).toFixed(0) : '?'}%
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5 truncate">
                      {cve.product_summary || cve.vendor_project || '—'}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      {cve.cvss_base != null && (
                        <span className="text-[10px] text-gray-500">CVSS {cve.cvss_base.toFixed(1)}</span>
                      )}
                      {cve.kev_listed && (
                        <span className="text-[10px] text-red-600 font-medium">KEV</span>
                      )}
                    </div>
                  </Link>
                ))}
                {epssTop.length === 0 && (
                  <div className="px-4 py-8 text-center text-xs text-gray-400">No EPSS data</div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* D) National / EU Advisories */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
          <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
            <h2 className="text-base font-semibold flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-500" /> National / EU Advisories
            </h2>
            <Link to="/intel/advisories" className="text-xs text-brand-600 hover:text-brand-700 flex items-center gap-1">
              View all <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="divide-y divide-gray-50">
            {advisoriesLatest.slice(0, 8).map(adv => (
              <Link
                key={adv.advisory_id}
                to={`/intel/advisories?search=${encodeURIComponent(adv.advisory_id)}`}
                className="flex items-start gap-3 px-5 py-3 hover:bg-blue-50/30 transition-colors"
              >
                <Badge variant={adv.severity === 'critical' ? 'critical' : adv.severity === 'high' ? 'high' : adv.severity === 'medium' ? 'medium' : 'low'}>
                  {adv.severity}
                </Badge>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-800 truncate">{adv.title}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-800">{adv.issuer}</span>
                    <span className="text-xs text-gray-400">{adv.advisory_id}</span>
                    {adv.cve_ids && adv.cve_ids.length > 0 && (
                      <span className="text-xs text-gray-400">{adv.cve_ids.length} CVE(s)</span>
                    )}
                  </div>
                </div>
                <span className="text-xs text-gray-400 shrink-0">{timeAgo(adv.published_at || adv.created_at)}</span>
              </Link>
            ))}
            {advisoriesLatest.length === 0 && (
              <div className="flex flex-col items-center justify-center py-12 text-gray-400">
                <Globe className="w-8 h-8 mb-2" />
                <p className="text-xs">No advisories ingested yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── E) Source Health ── */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Server className="w-4 h-4 text-gray-500" /> Source Health
          </h2>
          <Link to="/intel/sources" className="text-xs text-brand-600 hover:text-brand-700 flex items-center gap-1">
            Details <ArrowUpRight className="w-3 h-3" />
          </Link>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-px bg-gray-100">
          {connectors.map(c => {
            const isHealthy = c.last_success && !c.last_error
            const age = c.last_success ? timeAgo(c.last_success) : 'Never'
            return (
              <div key={c.connector_name} className="bg-white p-4">
                <div className="flex items-center gap-2 mb-2">
                  {isHealthy
                    ? <CheckCircle2 className="w-4 h-4 text-green-500" />
                    : c.last_error
                      ? <XCircle className="w-4 h-4 text-red-500" />
                      : <Clock className="w-4 h-4 text-gray-400" />
                  }
                  <span className="text-sm font-medium text-gray-800">{c.display_name}</span>
                </div>
                <div className="space-y-1 text-xs text-gray-500">
                  <div className="flex justify-between">
                    <span>Last success</span>
                    <span className={isHealthy ? 'text-green-600 font-medium' : 'text-gray-400'}>{age}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Items</span>
                    <span className="font-medium">{c.items_ingested.toLocaleString()}</span>
                  </div>
                  {c.last_error && (
                    <p className="text-red-500 truncate mt-1" title={c.last_error}>{c.last_error}</p>
                  )}
                </div>
              </div>
            )
          })}
          {connectors.length === 0 && (
            <div className="bg-white col-span-full py-8 text-center text-xs text-gray-400">
              No connectors registered. Click "Fetch Sources" to initialize.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/* ── Counter card subcomponent ── */
function CounterCard({ label, sublabel, value, icon, color, onClick }: {
  label: string; sublabel: string; value: number
  icon: React.ReactNode; color: string; onClick: () => void
}) {
  const colorMap: Record<string, string> = {
    red: 'bg-red-50 text-red-600 border-red-100',
    amber: 'bg-amber-50 text-amber-600 border-amber-100',
    orange: 'bg-orange-50 text-orange-600 border-orange-100',
    blue: 'bg-blue-50 text-blue-600 border-blue-100',
    gray: 'bg-gray-50 text-gray-600 border-gray-100',
  }
  return (
    <button
      onClick={onClick}
      className={`flex flex-col items-center p-3 rounded-xl border transition-all hover:shadow-sm ${colorMap[color] || colorMap.gray}`}
    >
      <div className="flex items-center gap-1.5 mb-1 opacity-70">{icon}<span className="text-[10px] font-medium uppercase tracking-wider">{sublabel}</span></div>
      <span className="text-2xl font-bold">{value}</span>
      <span className="text-[10px] font-medium opacity-70 mt-0.5 text-center leading-tight">{label}</span>
    </button>
  )
}
