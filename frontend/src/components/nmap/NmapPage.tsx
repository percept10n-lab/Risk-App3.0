import { useEffect, useState, useRef } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { useAssetStore } from '../../stores/assetStore'
import { nmapApi } from '../../api/endpoints'
import api from '../../api/client'
import {
  Play, Loader2, CheckCircle2, XCircle, Clock, Shield,
  AlertTriangle, X, ChevronDown, ChevronRight, Terminal,
} from 'lucide-react'

interface ScanProfile {
  id: string
  name: string
  args: string
  category: string
  risk: string
  description: string
  timeout: number
}

interface PortResult {
  port: number
  protocol: string
  state: string
  service: string
  product: string
  version: string
  extrainfo: string
  scripts: Record<string, string>
}

interface ScanHostDetail {
  host: string
  state: string
  ports: PortResult[]
  os: Array<{ name: string; accuracy: string }>
}

interface ScanResult {
  status: string
  profile: string
  target: string
  asset_id: string | null
  command_line: string
  scan_details: ScanHostDetail[]
  findings: Array<{
    title: string; severity: string; finding_id?: string; is_new?: boolean
    description?: string; evidence?: string; category?: string; remediation?: string
  }>
  findings_created: number
  total_findings: number
  error?: string
}

interface ProfileStatus {
  status: 'idle' | 'running' | 'completed' | 'error'
  startTime: number | null
  endTime: number | null
  result: ScanResult | null
  error: string | null
}

interface HistoryItem {
  id: string
  action: string
  timestamp: string | null
  actor: string
  details: any
  run_id: string | null
}

type TabKey = 'profiles' | 'results' | 'verify' | 'history'

const CATEGORY_STYLES: Record<string, { label: string; color: string; border: string }> = {
  active: { label: 'Active Scans', color: 'bg-blue-50 text-blue-700', border: 'border-blue-200' },
  passive: { label: 'Reconnaissance', color: 'bg-green-50 text-green-700', border: 'border-green-200' },
  offensive: { label: 'Offensive', color: 'bg-red-50 text-red-700', border: 'border-red-200' },
}

const RISK_BADGE: Record<string, string> = {
  low: 'low',
  medium: 'medium',
  high: 'critical',
}

const PORT_STATE_COLORS: Record<string, string> = {
  open: 'text-green-600 bg-green-50',
  closed: 'text-gray-500 bg-gray-50',
  filtered: 'text-yellow-600 bg-yellow-50',
}

export default function NmapPage() {
  const { assets, fetchAssets } = useAssetStore()
  const [selectedAssets, setSelectedAssets] = useState<string[]>([])
  const [freeTarget, setFreeTarget] = useState('')
  const [profiles, setProfiles] = useState<Record<string, ScanProfile[]>>({})
  const [profileStates, setProfileStates] = useState<Record<string, ProfileStatus>>({})
  const [activeTab, setActiveTab] = useState<TabKey>('profiles')
  const [expandedScans, setExpandedScans] = useState<Record<string, boolean>>({})
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [verifyResult, setVerifyResult] = useState<any>(null)
  const [verifyLoading, setVerifyLoading] = useState(false)
  const [assessResult, setAssessResult] = useState<any>(null)
  const [assessLoading, setAssessLoading] = useState(false)
  const [assetDropdownOpen, setAssetDropdownOpen] = useState(false)
  const timerRef = useRef<Record<string, ReturnType<typeof setInterval>>>({})
  const [, setTick] = useState(0)

  useEffect(() => {
    fetchAssets()
    nmapApi.listProfiles().then((res) => setProfiles(res.data.profiles || {}))
    return () => {
      Object.values(timerRef.current).forEach(clearInterval)
    }
  }, [])

  // Build list of scan targets: asset IDs + free target IP
  const scanTargets: Array<{ asset_id?: string; target?: string; label: string }> = [
    ...selectedAssets.map((aid) => {
      const a = assets.find((x) => x.id === aid)
      return { asset_id: aid, label: a ? `${a.ip_address} (${a.hostname || aid.slice(0, 8)})` : aid.slice(0, 8) }
    }),
    ...(freeTarget.trim() ? [{ target: freeTarget.trim(), label: freeTarget.trim() }] : []),
  ]

  const hasTargets = scanTargets.length > 0

  const handleScan = async (profileId: string) => {
    if (!hasTargets) return

    for (const t of scanTargets) {
      const key = `${profileId}_${t.asset_id || t.target}`
      const startTime = Date.now()
      setProfileStates((prev) => ({
        ...prev,
        [key]: { status: 'running', startTime, endTime: null, result: null, error: null },
      }))

      timerRef.current[key] = setInterval(() => setTick((n) => n + 1), 1000)

      try {
        const res = await nmapApi.scan({
          asset_id: t.asset_id || null,
          target: t.target || null,
          profile_id: profileId,
        })
        clearInterval(timerRef.current[key])

        if (res.data.status === 'error') {
          setProfileStates((prev) => ({
            ...prev,
            [key]: { status: 'error', startTime, endTime: Date.now(), result: null, error: res.data.error },
          }))
        } else {
          setProfileStates((prev) => ({
            ...prev,
            [key]: { status: 'completed', startTime, endTime: Date.now(), result: res.data, error: null },
          }))
        }
      } catch (err: any) {
        clearInterval(timerRef.current[key])
        setProfileStates((prev) => ({
          ...prev,
          [key]: { status: 'error', startTime, endTime: Date.now(), result: null, error: err.message || 'Scan failed' },
        }))
      }
    }
  }

  function formatElapsed(startTime: number, endTime: number | null) {
    const elapsed = ((endTime || Date.now()) - startTime) / 1000
    if (elapsed < 60) return `${Math.floor(elapsed)}s`
    return `${Math.floor(elapsed / 60)}m ${Math.floor(elapsed % 60)}s`
  }

  // All completed scan results
  const completedScans = Object.entries(profileStates)
    .filter(([, s]) => s.status === 'completed' && s.result)
    .map(([key, s]) => ({ key, ...s.result! }))

  const sessionFindings = completedScans.flatMap((s) =>
    (s.findings || []).map((f) => ({ ...f, profileKey: s.key, target: s.target }))
  )

  const handleVerify = async () => {
    if (selectedAssets.length === 0) return
    setVerifyLoading(true)
    setVerifyResult(null)
    try {
      const res = await nmapApi.verify({ asset_id: selectedAssets[0] })
      setVerifyResult(res.data)
    } catch (err: any) {
      setVerifyResult({ status: 'error', error: err.message })
    }
    setVerifyLoading(false)
  }

  const handleAssessRisk = async () => {
    if (selectedAssets.length === 0) return
    setAssessLoading(true)
    setAssessResult(null)
    try {
      const res = await nmapApi.assessRisk({ asset_id: selectedAssets[0] })
      setAssessResult(res.data)
    } catch (err: any) {
      setAssessResult({ status: 'error', error: err.message })
    }
    setAssessLoading(false)
  }

  async function loadHistory() {
    setHistoryLoading(true)
    try {
      const res = await api.get('/audit', { params: { entity_type: 'nmap_scan', limit: 50 } })
      setHistory(res.data.items || res.data.history || [])
    } catch { /* empty */ }
    setHistoryLoading(false)
  }

  const toggleAsset = (id: string) => {
    setSelectedAssets((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id]
    )
  }

  const selectedAssetObjects = assets.filter((a) => selectedAssets.includes(a.id))

  const tabs: Array<{ key: TabKey; label: string; count?: number }> = [
    { key: 'profiles', label: 'Scan Profiles' },
    { key: 'results', label: 'Results', count: completedScans.length },
    { key: 'verify', label: 'Verify' },
    { key: 'history', label: 'History' },
  ]

  return (
    <div>
      <PageHeader
        title="Nmap Scanner"
        description="Targeted network scanning with vulnerability verification and risk assessment"
      />

      {/* Target Selector */}
      <div className="card p-4 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Asset Dropdown */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Target Assets</label>
            <div className="relative">
              <button
                onClick={() => setAssetDropdownOpen(!assetDropdownOpen)}
                className="w-full px-3 py-2 border rounded-lg text-sm text-left flex items-center justify-between focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              >
                <span className="text-gray-500">
                  {selectedAssets.length === 0 ? 'Select assets...' : `${selectedAssets.length} asset(s) selected`}
                </span>
                <ChevronDown className="w-4 h-4 text-gray-400" />
              </button>
              {assetDropdownOpen && (
                <div className="absolute z-20 mt-1 w-full bg-white border rounded-lg shadow-lg max-h-60 overflow-y-auto">
                  {assets.map((asset) => (
                    <label
                      key={asset.id}
                      className="flex items-center gap-3 px-4 py-2 hover:bg-gray-50 cursor-pointer text-sm"
                    >
                      <input
                        type="checkbox"
                        checked={selectedAssets.includes(asset.id)}
                        onChange={() => toggleAsset(asset.id)}
                        className="rounded border-gray-300"
                      />
                      <span className="font-mono text-xs">{asset.ip_address}</span>
                      <span className="text-gray-500 truncate">{asset.hostname || '\u2014'}</span>
                      <Badge variant={asset.criticality as any}>{asset.criticality}</Badge>
                    </label>
                  ))}
                  {assets.length === 0 && (
                    <div className="p-4 text-center text-gray-500 text-sm">No assets found</div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Free Target IP */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Free Target IP</label>
            <input
              type="text"
              value={freeTarget}
              onChange={(e) => setFreeTarget(e.target.value)}
              placeholder="e.g., 192.168.178.100 or 192.168.178.0/24"
              className="w-full px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
            />
            <p className="text-xs text-gray-400 mt-1">RFC 1918 only — supports single IP or CIDR notation</p>
          </div>
        </div>

        {/* Selected chips */}
        {(selectedAssetObjects.length > 0 || freeTarget.trim()) && (
          <div className="flex flex-wrap gap-2 mt-3">
            {selectedAssetObjects.map((a) => (
              <span key={a.id} className="inline-flex items-center gap-1 px-2 py-1 bg-brand-50 text-brand-700 rounded-full text-xs">
                {a.ip_address} {a.hostname ? `(${a.hostname})` : ''}
                <button onClick={() => toggleAsset(a.id)} className="hover:text-brand-900">
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
            {freeTarget.trim() && (
              <span className="inline-flex items-center gap-1 px-2 py-1 bg-purple-50 text-purple-700 rounded-full text-xs">
                <Terminal className="w-3 h-3" />
                {freeTarget.trim()}
                <button onClick={() => setFreeTarget('')} className="hover:text-purple-900">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => {
              setActiveTab(tab.key)
              if (tab.key === 'history' && history.length === 0) loadHistory()
            }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? 'border-brand-600 text-brand-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="ml-1.5 bg-brand-100 text-brand-700 px-1.5 py-0.5 rounded-full text-xs">{tab.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* Scan Profiles Tab */}
      {activeTab === 'profiles' && (
        <div className="space-y-8">
          {Object.entries(CATEGORY_STYLES).map(([cat, style]) => {
            const catProfiles = profiles[cat] || []
            if (catProfiles.length === 0) return null
            return (
              <div key={cat}>
                <h3 className={`text-sm font-semibold mb-3 px-2 py-1 rounded inline-block ${style.color}`}>
                  {style.label}
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {catProfiles.map((profile) => {
                    // Aggregate states for this profile across all targets
                    const targetKeys = scanTargets.map((t) => `${profile.id}_${t.asset_id || t.target}`)
                    const states = targetKeys.map((k) => profileStates[k]).filter(Boolean)
                    const isRunning = states.some((s) => s.status === 'running')
                    const completed = states.filter((s) => s.status === 'completed' && s.result)
                    const errors = states.filter((s) => s.status === 'error')
                    const totalPorts = completed.reduce((acc, s) =>
                      acc + (s.result?.scan_details?.reduce((a: number, h: ScanHostDetail) => a + h.ports.length, 0) || 0), 0)
                    const totalFindings = completed.reduce((acc, s) => acc + (s.result?.total_findings || 0), 0)

                    return (
                      <div key={profile.id} className={`card p-5 border ${style.border}`}>
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-medium text-sm">{profile.name}</h4>
                          <Badge variant={RISK_BADGE[profile.risk] as any}>{profile.risk} risk</Badge>
                        </div>
                        <code className="block text-xs font-mono text-gray-500 bg-gray-50 px-2 py-1 rounded mb-2">
                          nmap {profile.args}
                        </code>
                        <p className="text-xs text-gray-500 mb-3">{profile.description}</p>

                        {/* Status + Results */}
                        {states.length > 0 && (
                          <div className="mb-3 p-2 rounded-lg bg-gray-50 space-y-1">
                            {isRunning && (
                              <div className="flex items-center gap-2 text-sm text-brand-600">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                <span>Running... {states.find((s) => s.status === 'running') && formatElapsed(states.find((s) => s.status === 'running')!.startTime!, null)}</span>
                              </div>
                            )}
                            {completed.length > 0 && !isRunning && (
                              <div className="flex items-center gap-2 text-sm text-green-600">
                                <CheckCircle2 className="w-4 h-4" />
                                <span>{totalPorts} ports, {totalFindings} findings</span>
                              </div>
                            )}
                            {errors.length > 0 && !isRunning && (
                              <div className="flex items-center gap-2 text-sm text-red-600">
                                <XCircle className="w-4 h-4" />
                                <span className="truncate">{errors[0].error || 'Failed'}</span>
                              </div>
                            )}

                            {/* Inline scan results: ports table */}
                            {completed.length > 0 && !isRunning && (
                              <div className="mt-2 space-y-2 max-h-48 overflow-y-auto">
                                {completed.map((s) =>
                                  s.result!.scan_details.map((host, hi) => (
                                    <div key={hi}>
                                      <div className="text-xs font-medium text-gray-600 mb-1">
                                        {host.host} ({host.state})
                                        {host.os.length > 0 && <span className="ml-2 text-gray-400">OS: {host.os[0].name}</span>}
                                      </div>
                                      {host.ports.length > 0 && (
                                        <table className="w-full text-xs">
                                          <thead>
                                            <tr className="text-gray-400">
                                              <th className="text-left pr-2">Port</th>
                                              <th className="text-left pr-2">State</th>
                                              <th className="text-left pr-2">Service</th>
                                              <th className="text-left">Version</th>
                                            </tr>
                                          </thead>
                                          <tbody>
                                            {host.ports.slice(0, 10).map((p, pi) => (
                                              <tr key={pi}>
                                                <td className="pr-2 font-mono">{p.port}/{p.protocol}</td>
                                                <td className="pr-2">
                                                  <span className={`px-1 rounded ${PORT_STATE_COLORS[p.state] || ''}`}>{p.state}</span>
                                                </td>
                                                <td className="pr-2">{p.service}</td>
                                                <td className="text-gray-400 truncate max-w-[120px]">
                                                  {p.product}{p.version ? ` ${p.version}` : ''}
                                                </td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      )}
                                      {host.ports.length > 10 && (
                                        <div className="text-xs text-gray-400 mt-1">+{host.ports.length - 10} more ports</div>
                                      )}
                                      {host.ports.length === 0 && (
                                        <div className="text-xs text-gray-400">No open ports detected</div>
                                      )}
                                    </div>
                                  ))
                                )}
                              </div>
                            )}
                          </div>
                        )}

                        <button
                          onClick={() => handleScan(profile.id)}
                          disabled={!hasTargets || isRunning}
                          className="btn-primary w-full flex items-center justify-center gap-2 text-sm"
                        >
                          {isRunning ? (
                            <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</>
                          ) : (
                            <><Play className="w-4 h-4" /> Scan</>
                          )}
                        </button>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Results Tab */}
      {activeTab === 'results' && (
        <div>
          <div className="flex gap-2 mb-4">
            <button
              onClick={handleVerify}
              disabled={selectedAssets.length === 0 || completedScans.length === 0 || verifyLoading}
              className="btn-secondary flex items-center gap-2 text-sm"
            >
              {verifyLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              Verify with Vuln Scan
            </button>
            <button
              onClick={handleAssessRisk}
              disabled={selectedAssets.length === 0 || completedScans.length === 0 || assessLoading}
              className="btn-secondary flex items-center gap-2 text-sm"
            >
              {assessLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <AlertTriangle className="w-4 h-4" />}
              Assess Risk
            </button>
          </div>

          {/* Assess result */}
          {assessResult && (
            <div className={`card p-4 mb-4 ${assessResult.status === 'error' ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
              {assessResult.status === 'error' ? (
                <p className="text-sm text-red-700">{assessResult.error}</p>
              ) : (
                <div className="text-sm text-green-700">
                  <p className="font-medium">Risk Assessment Complete</p>
                  <p>Created: {assessResult.risks_created} | Updated: {assessResult.risks_updated} | Assets: {assessResult.total_assets}</p>
                </div>
              )}
            </div>
          )}

          {/* Per-scan detailed results */}
          {completedScans.length === 0 ? (
            <div className="card p-6 text-center text-gray-500 text-sm">
              No scan results yet. Run a scan to see results.
            </div>
          ) : (
            <div className="space-y-3">
              {completedScans.map((scan) => {
                const isExpanded = expandedScans[scan.key]
                return (
                  <div key={scan.key} className="card">
                    {/* Scan Header */}
                    <button
                      onClick={() => setExpandedScans((prev) => ({ ...prev, [scan.key]: !prev[scan.key] }))}
                      className="w-full px-4 py-3 flex items-center gap-3 hover:bg-gray-50 text-left"
                    >
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                      <span className="font-mono text-sm font-medium">{scan.target}</span>
                      <Badge variant="info">{scan.profile}</Badge>
                      <span className="text-xs text-gray-400 ml-auto">
                        {scan.scan_details.reduce((a, h) => a + h.ports.length, 0)} ports |{' '}
                        {scan.total_findings} findings ({scan.findings_created} new)
                      </span>
                      <CheckCircle2 className="w-4 h-4 text-green-500" />
                    </button>

                    {/* Expanded Details */}
                    {isExpanded && (
                      <div className="px-4 pb-4 border-t bg-gray-50">
                        {/* Command line */}
                        <div className="mt-3 mb-3">
                          <code className="text-xs font-mono text-gray-500 bg-gray-100 px-2 py-1 rounded block">
                            $ {scan.command_line}
                          </code>
                        </div>

                        {/* Port/Service Table */}
                        {scan.scan_details.map((host, hi) => (
                          <div key={hi} className="mb-4">
                            <h4 className="text-sm font-medium text-gray-700 mb-2">
                              Host: {host.host} <span className={`text-xs px-1 rounded ${host.state === 'up' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>{host.state}</span>
                              {host.os.length > 0 && <span className="text-xs text-gray-400 ml-2">OS: {host.os.map(o => `${o.name} (${o.accuracy}%)`).join(', ')}</span>}
                            </h4>
                            {host.ports.length > 0 ? (
                              <div className="overflow-x-auto">
                                <table className="w-full text-sm border rounded-lg overflow-hidden">
                                  <thead className="bg-white">
                                    <tr>
                                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Port</th>
                                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">State</th>
                                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Service</th>
                                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Product</th>
                                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Version</th>
                                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Info</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y bg-white">
                                    {host.ports.map((p, pi) => (
                                      <tr key={pi} className="hover:bg-blue-50">
                                        <td className="px-3 py-1.5 font-mono text-xs">{p.port}/{p.protocol}</td>
                                        <td className="px-3 py-1.5">
                                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${PORT_STATE_COLORS[p.state] || ''}`}>{p.state}</span>
                                        </td>
                                        <td className="px-3 py-1.5 text-xs">{p.service}</td>
                                        <td className="px-3 py-1.5 text-xs">{p.product || '\u2014'}</td>
                                        <td className="px-3 py-1.5 text-xs font-mono">{p.version || '\u2014'}</td>
                                        <td className="px-3 py-1.5 text-xs text-gray-400 truncate max-w-[200px]">{p.extrainfo || '\u2014'}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            ) : (
                              <p className="text-xs text-gray-400">No open ports detected</p>
                            )}

                            {/* NSE Script outputs */}
                            {host.ports.some((p) => Object.keys(p.scripts).length > 0) && (
                              <div className="mt-3">
                                <h5 className="text-xs font-semibold text-gray-500 uppercase mb-1">NSE Script Output</h5>
                                <div className="space-y-2">
                                  {host.ports.filter((p) => Object.keys(p.scripts).length > 0).map((p, pi) =>
                                    Object.entries(p.scripts).map(([name, output]) => (
                                      <div key={`${pi}-${name}`} className="bg-white rounded p-2 border">
                                        <div className="flex items-center gap-2 mb-1">
                                          <span className="font-mono text-xs font-medium">{p.port}/{p.protocol}</span>
                                          <span className="text-xs text-purple-600">{name}</span>
                                        </div>
                                        <pre className="text-xs text-gray-600 whitespace-pre-wrap max-h-32 overflow-y-auto">{output}</pre>
                                      </div>
                                    ))
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}

                        {/* Findings */}
                        {scan.findings.length > 0 && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-700 mb-2">Findings ({scan.findings.length})</h4>
                            <div className="space-y-1">
                              {scan.findings.map((f, fi) => (
                                <div key={fi} className="flex items-start gap-2 bg-white rounded p-2 border text-xs">
                                  <Badge variant={f.severity as any}>{f.severity}</Badge>
                                  <div className="flex-1 min-w-0">
                                    <p className="font-medium">{f.title}</p>
                                    {f.evidence && <p className="text-gray-500 mt-0.5 font-mono">{f.evidence}</p>}
                                    {f.remediation && <p className="text-blue-600 mt-0.5">{f.remediation}</p>}
                                  </div>
                                  {f.is_new ? (
                                    <span className="text-green-600 font-medium shrink-0">NEW</span>
                                  ) : (
                                    <span className="text-gray-400 shrink-0">existing</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Verify Tab */}
      {activeTab === 'verify' && (
        <div>
          <div className="mb-4">
            <button
              onClick={handleVerify}
              disabled={selectedAssets.length === 0 || verifyLoading}
              className="btn-primary flex items-center gap-2 text-sm"
            >
              {verifyLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              Run Vulnerability Verification
            </button>
          </div>

          {verifyResult && (
            <div className="space-y-4">
              <div className={`card p-4 ${verifyResult.status === 'error' ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
                {verifyResult.status === 'error' ? (
                  <p className="text-sm text-red-700">{verifyResult.error}</p>
                ) : (
                  <div className="text-sm text-green-700">
                    <p className="font-medium">Verification Complete</p>
                    <p>Nmap findings checked: {verifyResult.nmap_findings_checked} | Checks run: {(verifyResult.checks_run || []).join(', ') || 'none'}</p>
                  </div>
                )}
              </div>

              {verifyResult.results && verifyResult.results.length > 0 && (
                <div className="card">
                  <div className="px-4 py-3 border-b">
                    <h3 className="font-semibold text-sm">Verification Results</h3>
                  </div>
                  <div className="divide-y">
                    {verifyResult.results.map((r: any, i: number) => (
                      <div key={i} className="px-4 py-3">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-medium text-sm">{r.check}</span>
                          {r.error ? (
                            <Badge variant="critical">Error</Badge>
                          ) : r.result?.status === 'completed' ? (
                            <Badge variant="low">Completed</Badge>
                          ) : (
                            <Badge variant="medium">{r.result?.status}</Badge>
                          )}
                        </div>
                        {r.result?.findings && (
                          <div className="ml-4 space-y-1">
                            {r.result.findings.slice(0, 5).map((f: any, j: number) => (
                              <div key={j} className="flex items-center gap-2 text-xs">
                                <Badge variant={f.severity as any}>{f.severity}</Badge>
                                <span className="truncate">{f.title}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {!verifyResult && !verifyLoading && (
            <div className="card p-8 text-center text-gray-500 text-sm">
              Select an asset and run verification to cross-check nmap findings with targeted vulnerability scans.
            </div>
          )}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="card">
          <div className="px-4 py-3 border-b flex items-center justify-between">
            <h3 className="font-semibold text-sm">Scan History</h3>
            <button onClick={loadHistory} className="text-xs text-brand-600 hover:text-brand-800">Refresh</button>
          </div>
          <div className="divide-y">
            {historyLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="w-5 h-5 animate-spin text-brand-500" />
              </div>
            ) : history.length === 0 ? (
              <div className="p-6 text-center text-gray-500 text-sm">
                No nmap scan history recorded yet.
              </div>
            ) : (
              history.map((h) => (
                <div key={h.id} className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <Clock className="w-4 h-4 text-gray-400" />
                    <span className="text-sm font-medium">{h.action}</span>
                    <span className="text-xs text-gray-400 ml-auto">
                      {h.timestamp ? new Date(h.timestamp).toLocaleString() : '-'}
                    </span>
                  </div>
                  {h.details && (
                    <div className="ml-7 mt-1 text-xs text-gray-500">
                      {h.details.target && <span>Target: {h.details.target}</span>}
                      {h.details.profile && <span className="ml-2">Profile: {h.details.profile}</span>}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
