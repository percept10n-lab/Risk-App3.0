import { useState, useMemo } from 'react'
import Badge from '../common/Badge'
import { threatsApi } from '../../api/endpoints'
import { useAssetStore } from '../../stores/assetStore'
import { ShieldAlert, Play, Loader2, Search, X, FileDown, Eye, CheckCircle2, AlertTriangle } from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_URL || ''

export default function ThreatModelingTab({ embedded }: { embedded?: boolean }) {
  const { assets, fetchAssets } = useAssetStore()
  const [selectedAssetIds, setSelectedAssetIds] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [runRiskAnalysis, setRunRiskAnalysis] = useState(true)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [assetSearch, setAssetSearch] = useState('')
  const [showPicker, setShowPicker] = useState(false)

  // Fetch assets on first render
  useState(() => { fetchAssets() })

  const filteredAssets = useMemo(() => {
    if (!assetSearch) return assets
    const q = assetSearch.toLowerCase()
    return assets.filter(
      a => a.ip_address?.toLowerCase().includes(q) ||
           a.hostname?.toLowerCase().includes(q) ||
           a.zone?.toLowerCase().includes(q)
    )
  }, [assets, assetSearch])

  const toggleAsset = (id: string) => {
    setSelectedAssetIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const selectAll = () => {
    setSelectedAssetIds(new Set(filteredAssets.map(a => a.id)))
  }

  const deselectAll = () => setSelectedAssetIds(new Set())

  const handleRun = async () => {
    setRunning(true)
    setError(null)
    setResult(null)
    try {
      const payload: any = { run_risk_analysis: runRiskAnalysis }
      if (selectedAssetIds.size > 0) {
        payload.asset_ids = [...selectedAssetIds]
      } else if (manualTarget.trim()) {
        payload.manual_target = manualTarget.trim()
      }
      const res = await threatsApi.standaloneThreatModel(payload)
      setResult(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Threat modeling failed')
    } finally {
      setRunning(false)
    }
  }

  const handleViewReport = () => {
    if (result?.report_id) {
      window.open(`${API_BASE}/api/threats/report/${result.report_id}/view`, '_blank')
    }
  }

  const handleDownloadReport = async () => {
    if (!result?.report_id) return
    try {
      const res = await threatsApi.downloadThreatReport(result.report_id)
      const blob = new Blob([res.data], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threat-model-report-${result.report_id.slice(0, 8)}.html`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      console.error('Download failed:', err.message)
    }
  }

  return (
    <div>
      {/* Asset Selection */}
      <div className="card p-5 mb-4">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="w-5 h-5 text-brand-600" />
          <h3 className="font-semibold">Threat Modeling — Target Selection</h3>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          {/* Asset Picker */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Select Assets ({selectedAssetIds.size} selected)
            </label>
            <button
              onClick={() => setShowPicker(!showPicker)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm text-left bg-white hover:bg-gray-50"
            >
              {selectedAssetIds.size > 0
                ? `${selectedAssetIds.size} asset${selectedAssetIds.size !== 1 ? 's' : ''} selected`
                : 'Click to select assets (leave empty for all)'}
            </button>
          </div>

          {/* Manual target */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Or Enter IP Manually
            </label>
            <input
              type="text"
              value={manualTarget}
              onChange={e => setManualTarget(e.target.value)}
              placeholder="192.168.178.1"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              disabled={selectedAssetIds.size > 0}
            />
          </div>
        </div>

        {/* Asset picker dropdown */}
        {showPicker && (
          <div className="mb-4 border border-gray-200 rounded-lg overflow-hidden">
            <div className="px-4 py-3 bg-gray-50 border-b flex items-center gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  value={assetSearch}
                  onChange={e => setAssetSearch(e.target.value)}
                  placeholder="Filter by IP, hostname, or zone..."
                  className="w-full pl-9 pr-8 py-2 border border-gray-300 rounded-lg text-sm"
                />
                {assetSearch && (
                  <button onClick={() => setAssetSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
              <button onClick={selectAll} className="text-xs text-brand-600 hover:text-brand-700 font-medium">Select All</button>
              <span className="text-gray-300">|</span>
              <button onClick={deselectAll} className="text-xs text-gray-500 hover:text-gray-700 font-medium">None</button>
            </div>
            <div className="max-h-48 overflow-y-auto divide-y divide-gray-100">
              {filteredAssets.length === 0 ? (
                <div className="px-4 py-4 text-center text-sm text-gray-500">
                  {assets.length === 0 ? 'No assets discovered yet.' : 'No assets match your filter.'}
                </div>
              ) : (
                filteredAssets.map(asset => (
                  <label key={asset.id} className="flex items-center gap-3 px-4 py-2 hover:bg-gray-50 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedAssetIds.has(asset.id)}
                      onChange={() => toggleAsset(asset.id)}
                      className="w-4 h-4 rounded border-gray-300 text-brand-600"
                    />
                    <span className="font-mono text-sm text-gray-800">{asset.ip_address}</span>
                    {asset.hostname && <span className="text-sm text-gray-500">— {asset.hostname}</span>}
                    <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">{asset.zone}</span>
                  </label>
                ))
              )}
            </div>
          </div>
        )}

        {/* Options */}
        <div className="flex items-center gap-6">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={runRiskAnalysis}
              onChange={e => setRunRiskAnalysis(e.target.checked)}
              className="w-4 h-4 rounded border-gray-300 text-brand-600"
            />
            Run Risk Analysis (ISO 27005)
          </label>
          <button
            onClick={handleRun}
            disabled={running}
            className="btn-primary flex items-center gap-2"
          >
            {running ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Running...</>
            ) : (
              <><Play className="w-4 h-4" /> Run Threat Modeling</>
            )}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle2 className="w-5 h-5 text-green-500" />
            <h3 className="font-semibold">Results</h3>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            <div className="p-3 bg-gray-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-gray-900">{result.threats_created ?? 0}</p>
              <p className="text-xs text-gray-500">Threats Created</p>
            </div>
            <div className="p-3 bg-gray-50 rounded-lg text-center">
              <p className="text-2xl font-bold text-gray-900">{result.total_assets ?? 0}</p>
              <p className="text-xs text-gray-500">Assets Analyzed</p>
            </div>
            {result.by_c4_level && (
              <>
                <div className="p-3 bg-gray-50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-gray-900">
                    {(result.by_c4_level.system_context ?? 0) + (result.by_c4_level.container ?? 0) + (result.by_c4_level.component ?? 0)}
                  </p>
                  <p className="text-xs text-gray-500">C4 Levels</p>
                </div>
              </>
            )}
            {result.risk_analysis && (
              <div className="p-3 bg-gray-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-gray-900">{result.risk_analysis?.risks_created ?? 0}</p>
                <p className="text-xs text-gray-500">Risk Scenarios</p>
              </div>
            )}
          </div>

          {/* STRIDE breakdown */}
          {result.by_stride && Object.keys(result.by_stride).length > 0 && (
            <div className="mb-4">
              <p className="text-sm font-medium text-gray-700 mb-2">STRIDE Breakdown</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.by_stride as Record<string, number>).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                  <span key={type} className="px-2.5 py-1 bg-brand-50 text-brand-700 rounded-lg text-xs font-medium">
                    {type.replace(/_/g, ' ')}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* C4 level breakdown */}
          {result.by_c4_level && (
            <div className="mb-4">
              <p className="text-sm font-medium text-gray-700 mb-2">By C4 Level</p>
              <div className="flex gap-3">
                <Badge variant="info">L1 System Context: {result.by_c4_level.system_context ?? 0}</Badge>
                <Badge variant="medium">L2 Container: {result.by_c4_level.container ?? 0}</Badge>
                <Badge variant="high">L3 Component: {result.by_c4_level.component ?? 0}</Badge>
              </div>
            </div>
          )}

          {/* Report actions */}
          {result.report_id && (
            <div className="flex gap-3 pt-4 border-t">
              <button onClick={handleViewReport} className="btn-primary flex items-center gap-2 text-sm">
                <Eye className="w-4 h-4" /> View Report
              </button>
              <button onClick={handleDownloadReport} className="btn-secondary flex items-center gap-2 text-sm">
                <FileDown className="w-4 h-4" /> Download Report
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
