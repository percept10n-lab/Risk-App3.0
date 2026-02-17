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

export default function ThreatsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('threats')

  const tabs = [
    { id: 'threats' as Tab, label: 'Threats', icon: Shield },
    { id: 'generate' as Tab, label: 'Generate', icon: Zap },
    { id: 'boundaries' as Tab, label: 'Trust Boundaries', icon: Network },
  ]

  return (
    <div>
      <PageHeader
        title="Threat Modeling"
        description="STRIDE-based threat analysis and zone trust boundary mapping"
      />

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

  useEffect(() => {
    fetchThreats()
  }, [])

  const strideCounts = STRIDE_TYPES.reduce<Record<string, number>>((acc, t) => {
    acc[t.value] = threats.filter((th) => th.threat_type === t.value).length
    return acc
  }, {})

  return (
    <div>
      {/* Summary stats */}
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
          <span className={`badge ${strideBadgeColor[threat.threat_type] || 'bg-gray-100 text-gray-800'}`}>
            {strideLabel[threat.threat_type] || threat.threat_type}
          </span>
        </td>
        <td className="px-4 py-3">
          <p className="font-medium text-sm">{threat.title}</p>
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
          <td colSpan={10} className="px-8 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <p className="font-medium text-gray-700 mb-1">Description</p>
                <p className="text-gray-600">{threat.description}</p>
              </div>
              {threat.rationale && (
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

/* ───────────────── Tab 2: Generate Threats ───────────────── */

interface GenerateResult {
  status: string
  threats_created: number
  threats_skipped_duplicate: number
  total_assets: number
}

interface ZoneResult {
  status: string
  zone: string
  threats_created: number
  assets_in_zone: number
}

function GenerateTab() {
  const { assets, fetchAssets } = useAssetStore()
  const { fetchThreats } = useThreatStore()

  const [selectedAssetId, setSelectedAssetId] = useState('')
  const [selectedZone, setSelectedZone] = useState('')
  const [loading, setLoading] = useState<string | null>(null)
  const [genResult, setGenResult] = useState<GenerateResult | null>(null)
  const [zoneResult, setZoneResult] = useState<ZoneResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchAssets()
  }, [])

  const handleGenerateForAsset = async () => {
    if (!selectedAssetId) return
    setLoading('asset')
    setError(null)
    setGenResult(null)
    try {
      const res = await threatsApi.generate({ asset_id: selectedAssetId })
      setGenResult(res.data)
      fetchThreats()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(null)
    }
  }

  const handleGenerateAll = async () => {
    setLoading('all')
    setError(null)
    setGenResult(null)
    try {
      const res = await threatsApi.generate()
      setGenResult(res.data)
      fetchThreats()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(null)
    }
  }

  const handleZoneAnalysis = async () => {
    if (!selectedZone) return
    setLoading('zone')
    setError(null)
    setZoneResult(null)
    try {
      const res = await threatsApi.zoneAnalysis({ zone: selectedZone })
      setZoneResult(res.data)
      fetchThreats()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Generate for specific asset */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold mb-4">Generate for Asset</h3>
        <p className="text-sm text-gray-500 mb-4">Run STRIDE threat modeling against a specific asset.</p>
        <div className="flex gap-3">
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
          <button
            onClick={handleGenerateForAsset}
            disabled={!selectedAssetId || loading === 'asset'}
            className="btn-primary text-sm disabled:opacity-50 flex items-center gap-2"
          >
            {loading === 'asset' && <Loader2 className="w-4 h-4 animate-spin" />}
            Generate for Asset
          </button>
        </div>
      </div>

      {/* Generate for ALL assets */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold mb-4">Generate for ALL Assets</h3>
        <p className="text-sm text-gray-500 mb-4">Run STRIDE threat modeling against every discovered asset.</p>
        <button
          onClick={handleGenerateAll}
          disabled={loading === 'all'}
          className="btn-primary text-sm disabled:opacity-50 flex items-center gap-2"
        >
          {loading === 'all' && <Loader2 className="w-4 h-4 animate-spin" />}
          Generate for ALL Assets
        </button>
      </div>

      {/* Zone Analysis */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold mb-4">Zone Analysis</h3>
        <p className="text-sm text-gray-500 mb-4">Analyze threats specific to a network zone and its trust boundaries.</p>
        <div className="flex gap-3">
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
          <button
            onClick={handleZoneAnalysis}
            disabled={!selectedZone || loading === 'zone'}
            className="btn-primary text-sm disabled:opacity-50 flex items-center gap-2"
          >
            {loading === 'zone' && <Loader2 className="w-4 h-4 animate-spin" />}
            Analyze Zone
          </button>
        </div>
      </div>

      {/* Results */}
      {error && (
        <div className="card p-4 border-red-200 bg-red-50">
          <p className="text-sm text-red-700 font-medium">Error</p>
          <p className="text-sm text-red-600 mt-1">{error}</p>
        </div>
      )}

      {genResult && (
        <div className="card p-4 border-green-200 bg-green-50">
          <p className="text-sm text-green-700 font-medium">Threat Generation Complete</p>
          <div className="grid grid-cols-3 gap-4 mt-3">
            <div className="text-center">
              <p className="text-2xl font-bold text-green-700">{genResult.threats_created}</p>
              <p className="text-xs text-green-600">Created</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-yellow-700">{genResult.threats_skipped_duplicate}</p>
              <p className="text-xs text-yellow-600">Skipped (duplicate)</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-700">{genResult.total_assets}</p>
              <p className="text-xs text-gray-600">Assets Processed</p>
            </div>
          </div>
        </div>
      )}

      {zoneResult && (
        <div className="card p-4 border-green-200 bg-green-50">
          <p className="text-sm text-green-700 font-medium">Zone Analysis Complete — {zoneResult.zone}</p>
          <div className="grid grid-cols-2 gap-4 mt-3">
            <div className="text-center">
              <p className="text-2xl font-bold text-green-700">{zoneResult.threats_created}</p>
              <p className="text-xs text-green-600">Threats Created</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-700">{zoneResult.assets_in_zone}</p>
              <p className="text-xs text-gray-600">Assets in Zone</p>
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
