import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import Pagination from '../common/Pagination'
import Badge from '../common/Badge'
import { useThreatStore } from '../../stores/threatStore'
import { useAssetStore } from '../../stores/assetStore'
import { threatsApi } from '../../api/endpoints'
import { formatRelativeTime } from '../../utils/format'
import type { Threat, EnrichedThreat } from '../../types'
import {
  ChevronDown,
  ChevronRight,
  Trash2,
  Loader2,
  Zap,
  Shield,
  Network,
} from 'lucide-react'

type Tab = 'threats' | 'generate' | 'boundaries'

// Backend stores snake_case threat_type values matching STRIDE
const STRIDE_TYPES = [
  { value: 'spoofing', label: 'Spoofing', abbr: 'S' },
  { value: 'tampering', label: 'Tampering', abbr: 'T' },
  { value: 'repudiation', label: 'Repudiation', abbr: 'R' },
  { value: 'information_disclosure', label: 'Info Disclosure', abbr: 'ID' },
  { value: 'denial_of_service', label: 'Denial of Service', abbr: 'DoS' },
  { value: 'elevation_of_privilege', label: 'Elev. of Privilege', abbr: 'EoP' },
]

// Backend stores lowercase zone values
const ZONES = [
  { value: 'lan', label: 'LAN' },
  { value: 'iot', label: 'IoT' },
  { value: 'guest', label: 'Guest' },
  { value: 'dmz', label: 'DMZ' },
]

const SOURCES = ['rule', 'manual', 'ai_suggested']

const strideBadgeColor: Record<string, string> = {
  spoofing: 'bg-purple-100 text-purple-800',
  tampering: 'bg-red-100 text-red-800',
  repudiation: 'bg-yellow-100 text-yellow-800',
  information_disclosure: 'bg-blue-100 text-blue-800',
  denial_of_service: 'bg-orange-100 text-orange-800',
  elevation_of_privilege: 'bg-pink-100 text-pink-800',
}

const c4BadgeColor: Record<string, string> = {
  system_context: 'bg-purple-100 text-purple-800',
  container: 'bg-blue-100 text-blue-800',
  component: 'bg-gray-100 text-gray-700',
}

const c4Label: Record<string, string> = {
  system_context: 'System Context',
  container: 'Container',
  component: 'Component',
}

const strideLabel: Record<string, string> = Object.fromEntries(
  STRIDE_TYPES.map((s) => [s.value, s.label])
)

const zoneLabel: Record<string, string> = Object.fromEntries(
  ZONES.map((z) => [z.value, z.label])
)

const TRUST_BOUNDARIES = [
  { name: 'WAN <> Router', from: 'WAN', to: 'Router', description: 'Internet-facing perimeter boundary' },
  { name: 'Router <> LAN', from: 'Router', to: 'LAN', description: 'Core network segmentation point' },
  { name: 'LAN <> IoT', from: 'LAN', to: 'IoT', description: 'IoT device isolation boundary' },
  { name: 'LAN <> Guest', from: 'LAN', to: 'Guest', description: 'Guest network isolation boundary' },
]

const ZONE_INFO: Record<string, { description: string; risk: string }> = {
  lan: { description: 'Trusted local area network with managed devices', risk: 'Medium' },
  iot: { description: 'IoT devices with limited update capability', risk: 'High' },
  guest: { description: 'Untrusted guest network with internet-only access', risk: 'High' },
  dmz: { description: 'Demilitarized zone for exposed services', risk: 'Critical' },
}

export default function ThreatsPage({ embedded }: { embedded?: boolean }) {
  const [activeTab, setActiveTab] = useState<Tab>('threats')

  const tabs = [
    { id: 'threats' as Tab, label: 'Threats', icon: Shield },
    { id: 'generate' as Tab, label: 'Generate', icon: Zap },
    { id: 'boundaries' as Tab, label: 'Trust Boundaries', icon: Network },
  ]

  return (
    <div>
      {!embedded && (
        <PageHeader
          title="Threat Modeling"
          description="STRIDE-based threat analysis and zone trust boundary mapping"
        />
      )}

      <div className="flex gap-1 mb-6 border-b border-gray-200">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-brand-600 text-brand-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'threats' && <ThreatsTab />}
      {activeTab === 'generate' && <GenerateTab />}
      {activeTab === 'boundaries' && <BoundariesTab />}
    </div>
  )
}

/* ───────────────── Tab 1: Threats List ───────────────── */

function ThreatsTab() {
  const { threats, total, page, pageSize, loading, filters, fetchThreats, setFilters, setPage, deleteThreat } = useThreatStore()
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [stats, setStats] = useState<{
    total: number
    by_c4_level: Record<string, number>
    by_stride: Record<string, number>
  } | null>(null)

  useEffect(() => {
    fetchThreats()
    threatsApi.stats().then((res) => setStats(res.data)).catch(() => {})
  }, [])

  const strideCounts = stats?.by_stride || {}
  const c4Counts = stats?.by_c4_level || { system_context: 0, container: 0, component: 0 }

  return (
    <div>
      {/* C4 Level Summary */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        {(['system_context', 'container', 'component'] as const).map((level) => (
          <div key={level} className="card p-3 flex items-center gap-3">
            <span className={`px-2 py-1 rounded text-xs font-medium ${c4BadgeColor[level]}`}>
              {c4Label[level]}
            </span>
            <span className="text-xl font-bold text-gray-900">{c4Counts[level]}</span>
            <span className="text-xs text-gray-500">threats</span>
          </div>
        ))}
      </div>

      {/* STRIDE stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
        <div className="card p-3 text-center">
          <p className="text-2xl font-bold text-gray-900">{total}</p>
          <p className="text-xs text-gray-500">Total</p>
        </div>
        {STRIDE_TYPES.map((st) => (
          <div key={st.value} className="card p-3 text-center">
            <p className="text-2xl font-bold text-gray-900">{strideCounts[st.value] || 0}</p>
            <p className="text-xs text-gray-500 truncate">{st.abbr}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-4">
        <select
          value={filters.threat_type || ''}
          onChange={(e) => setFilters({ threat_type: e.target.value || undefined })}
          className="btn-secondary text-sm"
        >
          <option value="">All STRIDE Types</option>
          {STRIDE_TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        <select
          value={filters.zone || ''}
          onChange={(e) => setFilters({ zone: e.target.value || undefined })}
          className="btn-secondary text-sm"
        >
          <option value="">All Zones</option>
          {ZONES.map((z) => (
            <option key={z.value} value={z.value}>{z.label}</option>
          ))}
        </select>
        <select
          value={filters.source || ''}
          onChange={(e) => setFilters({ source: e.target.value || undefined })}
          className="btn-secondary text-sm"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      {loading ? (
        <div className="card p-8 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full mx-auto" />
          <p className="mt-3 text-sm text-gray-500">Loading...</p>
        </div>
      ) : threats.length === 0 ? (
        <div className="card p-8 text-center">
          <p className="text-sm text-gray-500">No threats yet. Use the Generate tab to run STRIDE threat modeling.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50">
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-8" />
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">C4</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Asset</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Zone</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">MITRE</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Confidence</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-10" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {threats.map((threat) => (
                  <ThreatRow
                    key={threat.id}
                    threat={threat}
                    expanded={expandedId === threat.id}
                    onToggle={() => setExpandedId(expandedId === threat.id ? null : threat.id)}
                    onDelete={() => deleteThreat(threat.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} />
    </div>
  )
}

function ThreatRow({ threat, expanded, onToggle, onDelete }: {
  threat: EnrichedThreat
  expanded: boolean
  onToggle: () => void
  onDelete: () => void
}) {
  const mitreTechniques = threat.mitre_techniques || []
  const linkedFindings = threat.linked_findings || []
  const asset = threat.asset || null

  return (
    <>
      <tr className="hover:bg-gray-50 transition-colors cursor-pointer" onClick={onToggle}>
        <td className="px-4 py-3">
          {expanded ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
        </td>
        <td className="px-4 py-3">
          {threat.c4_level ? (
            <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${c4BadgeColor[threat.c4_level] || 'bg-gray-100 text-gray-700'}`}>
              {c4Label[threat.c4_level] || threat.c4_level}
            </span>
          ) : (
            <span className="text-xs text-gray-400">-</span>
          )}
        </td>
        <td className="px-4 py-3">
          <span className={`badge ${strideBadgeColor[threat.threat_type] || 'bg-gray-100 text-gray-800'}`}>
            {strideLabel[threat.threat_type] || threat.threat_type}
          </span>
        </td>
        <td className="px-4 py-3">
          <p className="font-medium text-sm">
            {threat.title}
            {asset && <span className="text-xs font-mono text-gray-400 ml-1.5">[{asset.ip_address}]</span>}
          </p>
          <p className="text-xs text-gray-500 mt-0.5 line-clamp-2" title={threat.description}>{threat.description}</p>
        </td>
        <td className="px-4 py-3">
          {asset ? (
            <div className="text-xs">
              <span className="font-mono">{asset.ip_address}</span>
              {asset.hostname && <span className="text-gray-500 ml-1">({asset.hostname})</span>}
            </div>
          ) : (
            <span className="text-xs text-gray-400">—</span>
          )}
        </td>
        <td className="px-4 py-3 text-sm">{zoneLabel[threat.zone || ''] || threat.zone || '—'}</td>
        <td className="px-4 py-3">
          {mitreTechniques.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {mitreTechniques.slice(0, 2).map((m) => (
                <span key={m.technique_id} className="px-1.5 py-0.5 bg-purple-50 text-purple-700 rounded text-xs font-mono">
                  {m.technique_id}
                </span>
              ))}
              {mitreTechniques.length > 2 && <span className="text-xs text-purple-500">+{mitreTechniques.length - 2}</span>}
            </div>
          ) : (
            <span className="text-xs text-gray-400">—</span>
          )}
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  threat.confidence >= 0.8 ? 'bg-green-500' : threat.confidence >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${threat.confidence * 100}%` }}
              />
            </div>
            <span className="text-xs text-gray-500">{Math.round(threat.confidence * 100)}%</span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="font-mono text-xs">{threat.source}</span>
        </td>
        <td className="px-4 py-3 text-sm text-gray-500">{formatRelativeTime(threat.created_at)}</td>
        <td className="px-4 py-3">
          <button
            onClick={(e) => { e.stopPropagation(); onDelete() }}
            className="text-gray-400 hover:text-red-500 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="bg-gray-50">
          <td colSpan={11} className="px-8 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <p className="font-medium text-gray-700 mb-1">Description</p>
                <p className="text-gray-600">{threat.description}</p>
              </div>
              {threat.stride_category_detail && (
                <div>
                  <p className="font-medium text-gray-700 mb-1">STRIDE Analysis</p>
                  <p className="text-gray-600 bg-blue-50 border border-blue-100 rounded p-2">{threat.stride_category_detail}</p>
                </div>
              )}
              {threat.rationale && !threat.stride_category_detail && (
                <div>
                  <p className="font-medium text-gray-700 mb-1">Rationale</p>
                  <p className="text-gray-600">{threat.rationale}</p>
                </div>
              )}
              {threat.trust_boundary && (
                <div>
                  <p className="font-medium text-gray-700 mb-1">Trust Boundary</p>
                  <Badge variant="info">{threat.trust_boundary}</Badge>
                </div>
              )}
              {linkedFindings.length > 0 && (
                <div>
                  <p className="font-medium text-gray-700 mb-1">Linked Findings</p>
                  <div className="flex flex-wrap gap-1">
                    {linkedFindings.map((f) => (
                      <span key={f.id} className="inline-flex items-center gap-1 px-2 py-0.5 bg-gray-100 border rounded text-xs">
                        <Badge variant={f.severity as any}>{f.severity}</Badge>
                        <span>{f.title}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {linkedFindings.length === 0 && threat.linked_finding_ids?.length > 0 && (
                <div>
                  <p className="font-medium text-gray-700 mb-1">Linked Findings</p>
                  <div className="flex flex-wrap gap-1">
                    {threat.linked_finding_ids.map((fid: string) => (
                      <span key={fid} className="font-mono text-xs bg-gray-200 px-2 py-0.5 rounded">
                        {fid.slice(0, 8)}...
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {mitreTechniques.length > 0 && (
                <div>
                  <p className="font-medium text-gray-700 mb-1">MITRE ATT&CK Techniques</p>
                  <div className="flex flex-wrap gap-1">
                    {mitreTechniques.map((m) => (
                      <span key={m.technique_id} className="inline-flex items-center gap-1 px-2 py-0.5 bg-purple-50 text-purple-700 rounded text-xs">
                        <span className="font-mono font-medium">{m.technique_id}</span>
                        <span className="text-purple-500">{m.technique_name}</span>
                        <span className="text-purple-400">({m.tactic})</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

/* ───────────────── Tab 2: Evaluate & Generate Threats ───────────────── */

interface ThreatCandidate {
  title: string
  description: string
  threat_type: string
  source: string
  zone: string | null
  trust_boundary: string | null
  confidence: number
  c4_level: string | null
  stride_category_detail: string | null
  asset_id: string
  asset_ip: string
  asset_hostname: string | null
  is_duplicate: boolean
}

interface EvaluateResult {
  high: ThreatCandidate[]
  medium: ThreatCandidate[]
  low: ThreatCandidate[]
  total_candidates: number
  total_assets: number
  duplicates: number
}

interface AcceptResult {
  status: string
  created: number
  skipped: number
}

function GenerateTab() {
  const { assets, fetchAssets } = useAssetStore()
  const { fetchThreats } = useThreatStore()

  const [selectedAssetId, setSelectedAssetId] = useState('')
  const [selectedZone, setSelectedZone] = useState('')
  const [evaluateMode, setEvaluateMode] = useState<'asset' | 'all' | 'zone'>('all')
  const [loading, setLoading] = useState<string | null>(null)
  const [evalResult, setEvalResult] = useState<EvaluateResult | null>(null)
  const [acceptResult, setAcceptResult] = useState<AcceptResult | null>(null)
  const [selectedCandidates, setSelectedCandidates] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchAssets()
  }, [])

  // Generate a unique key for each candidate
  const candidateKey = (c: ThreatCandidate) => `${c.asset_id}:${c.title}`

  // Initialize selections when evaluation completes
  const initializeSelections = (result: EvaluateResult) => {
    const selected = new Set<string>()
    // Pre-check high confidence, pre-check medium non-duplicates
    result.high.forEach((c) => selected.add(candidateKey(c)))
    result.medium.forEach((c) => { if (!c.is_duplicate) selected.add(candidateKey(c)) })
    // Low confidence: unchecked by default
    setSelectedCandidates(selected)
  }

  const handleEvaluate = async () => {
    setLoading('evaluate')
    setError(null)
    setEvalResult(null)
    setAcceptResult(null)
    try {
      const params: Record<string, string> = {}
      if (evaluateMode === 'asset' && selectedAssetId) params.asset_id = selectedAssetId
      if (evaluateMode === 'zone' && selectedZone) params.zone = selectedZone
      const res = await threatsApi.evaluate(params)
      setEvalResult(res.data)
      initializeSelections(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(null)
    }
  }

  const toggleCandidate = (c: ThreatCandidate) => {
    const key = candidateKey(c)
    setSelectedCandidates((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const toggleTier = (candidates: ThreatCandidate[], checked: boolean) => {
    setSelectedCandidates((prev) => {
      const next = new Set(prev)
      candidates.forEach((c) => {
        const key = candidateKey(c)
        if (checked) next.add(key)
        else next.delete(key)
      })
      return next
    })
  }

  const handleAcceptSelected = async () => {
    if (!evalResult) return
    setLoading('accept')
    setError(null)
    try {
      const allCandidates = [...evalResult.high, ...evalResult.medium, ...evalResult.low]
      const toAccept = allCandidates.filter((c) => selectedCandidates.has(candidateKey(c)))
      const res = await threatsApi.acceptBatch(toAccept)
      setAcceptResult(res.data)
      setEvalResult(null)
      fetchThreats()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(null)
    }
  }

  const renderTier = (label: string, candidates: ThreatCandidate[], color: string, bgColor: string) => {
    if (candidates.length === 0) return null
    const tierSelected = candidates.filter((c) => selectedCandidates.has(candidateKey(c))).length
    const allChecked = tierSelected === candidates.length

    return (
      <div className="mb-4">
        <div className={`flex items-center gap-3 px-4 py-2.5 ${bgColor} rounded-t-lg border border-b-0`}>
          <input
            type="checkbox"
            checked={allChecked}
            onChange={(e) => toggleTier(candidates, e.target.checked)}
            className="w-4 h-4 rounded border-gray-300"
          />
          <span className={`text-sm font-semibold ${color}`}>
            {label} ({candidates.length})
          </span>
          {tierSelected > 0 && tierSelected < candidates.length && (
            <span className="text-xs text-gray-500">{tierSelected} selected</span>
          )}
        </div>
        <div className="border rounded-b-lg divide-y divide-gray-100">
          {candidates.map((c) => {
            const key = candidateKey(c)
            const checked = selectedCandidates.has(key)
            return (
              <label key={key} className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggleCandidate(c)}
                  className="w-4 h-4 rounded border-gray-300"
                />
                <span className="text-sm font-medium flex-1 truncate">{c.title}</span>
                <span className={`badge ${strideBadgeColor[c.threat_type] || 'bg-gray-100 text-gray-800'}`}>
                  {strideLabel[c.threat_type] || c.threat_type}
                </span>
                <span className="text-xs text-gray-500 font-mono w-10 text-right">
                  {Math.round(c.confidence * 100)}%
                </span>
                <span className="text-xs text-gray-500 font-mono truncate max-w-[140px]">
                  {c.asset_hostname || c.asset_ip}
                </span>
                {c.is_duplicate && (
                  <span className="text-xs px-1.5 py-0.5 bg-yellow-100 text-yellow-700 rounded">dup</span>
                )}
              </label>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Step 1: Evaluate Controls */}
      {!evalResult && (
        <>
          <div className="card p-6">
            <h3 className="text-lg font-semibold mb-4">Evaluate Threats</h3>
            <p className="text-sm text-gray-500 mb-4">
              Generate threat candidates with confidence scoring. Review and approve before saving.
            </p>
            <div className="flex gap-3 mb-4">
              <select
                value={evaluateMode}
                onChange={(e) => setEvaluateMode(e.target.value as any)}
                className="btn-secondary text-sm"
              >
                <option value="all">All Assets</option>
                <option value="asset">Specific Asset</option>
                <option value="zone">By Zone</option>
              </select>
              {evaluateMode === 'asset' && (
                <select
                  value={selectedAssetId}
                  onChange={(e) => setSelectedAssetId(e.target.value)}
                  className="btn-secondary text-sm flex-1"
                >
                  <option value="">Select an asset...</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.hostname || a.ip_address} ({a.zone})
                    </option>
                  ))}
                </select>
              )}
              {evaluateMode === 'zone' && (
                <select
                  value={selectedZone}
                  onChange={(e) => setSelectedZone(e.target.value)}
                  className="btn-secondary text-sm"
                >
                  <option value="">Select a zone...</option>
                  {ZONES.map((z) => (
                    <option key={z.value} value={z.value}>{z.label}</option>
                  ))}
                </select>
              )}
            </div>
            <button
              onClick={handleEvaluate}
              disabled={
                loading === 'evaluate' ||
                (evaluateMode === 'asset' && !selectedAssetId) ||
                (evaluateMode === 'zone' && !selectedZone)
              }
              className="btn-primary text-sm disabled:opacity-50 flex items-center gap-2"
            >
              {loading === 'evaluate' && <Loader2 className="w-4 h-4 animate-spin" />}
              Evaluate
            </button>
          </div>
        </>
      )}

      {/* Step 2: Review candidates */}
      {evalResult && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-semibold">Review Threat Candidates</h3>
              <p className="text-sm text-gray-500">
                {evalResult.total_candidates} candidates from {evalResult.total_assets} assets
                {evalResult.duplicates > 0 && ` (${evalResult.duplicates} duplicates)`}
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleAcceptSelected}
                disabled={selectedCandidates.size === 0 || loading === 'accept'}
                className="btn-primary text-sm disabled:opacity-50 flex items-center gap-2"
              >
                {loading === 'accept' && <Loader2 className="w-4 h-4 animate-spin" />}
                Accept Selected ({selectedCandidates.size})
              </button>
              <button
                onClick={() => { setEvalResult(null); setSelectedCandidates(new Set()) }}
                className="btn-secondary text-sm"
              >
                Discard All
              </button>
            </div>
          </div>

          {renderTier('HIGH CONFIDENCE', evalResult.high, 'text-green-700', 'bg-green-50')}
          {renderTier('MEDIUM CONFIDENCE', evalResult.medium, 'text-yellow-700', 'bg-yellow-50')}
          {renderTier('LOW CONFIDENCE — review carefully', evalResult.low, 'text-red-700', 'bg-red-50')}

          {evalResult.total_candidates === 0 && (
            <div className="card p-8 text-center">
              <p className="text-sm text-gray-500">No threat candidates generated. All assets may already have comprehensive threat models.</p>
            </div>
          )}
        </div>
      )}

      {/* Results */}
      {error && (
        <div className="card p-4 border-red-200 bg-red-50">
          <p className="text-sm text-red-700 font-medium">Error</p>
          <p className="text-sm text-red-600 mt-1">{error}</p>
        </div>
      )}

      {acceptResult && (
        <div className="card p-4 border-green-200 bg-green-50">
          <p className="text-sm text-green-700 font-medium">Threats Accepted</p>
          <div className="grid grid-cols-2 gap-4 mt-3">
            <div className="text-center">
              <p className="text-2xl font-bold text-green-700">{acceptResult.created}</p>
              <p className="text-xs text-green-600">Created</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-yellow-700">{acceptResult.skipped}</p>
              <p className="text-xs text-yellow-600">Skipped (duplicate)</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ───────────────── Tab 3: Trust Boundaries ───────────────── */

function BoundariesTab() {
  const { threats } = useThreatStore()

  const zoneThreatCounts = ZONES.reduce<Record<string, number>>((acc, z) => {
    acc[z.value] = threats.filter((t) => t.zone === z.value).length
    return acc
  }, {})

  const boundaryThreatCounts = TRUST_BOUNDARIES.reduce<Record<string, number>>((acc, b) => {
    acc[b.name] = threats.filter((t) => t.trust_boundary === b.name).length
    return acc
  }, {})

  return (
    <div className="space-y-8">
      {/* Zone Cards */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Network Zones</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {ZONES.map((zone) => {
            const info = ZONE_INFO[zone.value]
            const riskColor = info.risk === 'Critical' ? 'text-red-600' : info.risk === 'High' ? 'text-orange-600' : 'text-yellow-600'
            return (
              <div key={zone.value} className="card p-5">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-gray-900">{zone.label}</h4>
                  <span className={`text-xs font-medium ${riskColor}`}>{info.risk} Risk</span>
                </div>
                <p className="text-xs text-gray-500 mb-4">{info.description}</p>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Threats</span>
                  <span className="text-xl font-bold text-gray-900">{zoneThreatCounts[zone.value] || 0}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Trust Boundary Cards */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Trust Boundaries</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {TRUST_BOUNDARIES.map((boundary) => (
            <div key={boundary.name} className="card p-5">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-semibold text-gray-900">{boundary.name}</h4>
                <span className="text-xl font-bold text-gray-900">{boundaryThreatCounts[boundary.name] || 0}</span>
              </div>
              <p className="text-xs text-gray-500 mb-3">{boundary.description}</p>
              <div className="flex items-center gap-2 text-xs">
                <Badge variant="info">{boundary.from}</Badge>
                <span className="text-gray-400">&rarr;</span>
                <Badge variant="info">{boundary.to}</Badge>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
