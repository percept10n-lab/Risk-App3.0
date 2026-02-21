import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import DataTable from '../common/DataTable'
import Pagination from '../common/Pagination'
import Badge from '../common/Badge'
import Modal from '../common/Modal'
import { useFindingStore } from '../../stores/findingStore'
import { useAssetStore } from '../../stores/assetStore'
import { vulnScanApi } from '../../api/endpoints'
import { formatRelativeTime } from '../../utils/format'
import { Loader2, Search } from 'lucide-react'
import type { Finding, EnrichedFinding } from '../../types'

const columns = [
  {
    key: 'severity',
    header: 'Severity',
    render: (f: EnrichedFinding) => (
      <Badge variant={f.severity as any}>{f.severity}</Badge>
    ),
    className: 'w-24',
  },
  {
    key: 'title',
    header: 'Title',
    render: (f: EnrichedFinding) => (
      <div>
        <p className="font-medium text-sm">
          {f.title}
          {f.asset?.ip_address && (
            <span className="text-xs font-mono text-gray-400 ml-1.5">[{f.asset.ip_address}]</span>
          )}
        </p>
        <p className="text-xs text-gray-500 mt-0.5 line-clamp-2 max-w-lg" title={f.description}>{f.description}</p>
      </div>
    ),
  },
  {
    key: 'asset',
    header: 'Asset',
    render: (f: EnrichedFinding) => {
      if (!f.asset) return <span className="text-xs text-gray-400">—</span>
      return (
        <div className="text-xs">
          <span className="font-mono">{f.asset.ip_address}</span>
          {f.asset.hostname && <span className="text-gray-500 ml-1">({f.asset.hostname})</span>}
        </div>
      )
    },
  },
  {
    key: 'category',
    header: 'Category',
    render: (f: EnrichedFinding) => <span className="capitalize text-sm">{f.category}</span>,
  },
  {
    key: 'source_tool',
    header: 'Source',
    render: (f: EnrichedFinding) => <span className="font-mono text-xs">{f.source_tool}</span>,
  },
  {
    key: 'mitre',
    header: 'MITRE',
    render: (f: EnrichedFinding) => {
      const techniques = f.mitre_techniques || []
      if (techniques.length === 0) return <span className="text-xs text-gray-400">—</span>
      const visible = techniques.slice(0, 2)
      const overflow = techniques.length - 2
      return (
        <div className="flex flex-wrap gap-1">
          {visible.map((m) => (
            <span key={m.technique_id} className="px-1.5 py-0.5 bg-purple-50 text-purple-700 rounded text-xs font-mono">
              {m.technique_id}
            </span>
          ))}
          {overflow > 0 && <span className="text-xs text-purple-500">+{overflow}</span>}
        </div>
      )
    },
  },
  {
    key: 'status',
    header: 'Status',
    render: (f: EnrichedFinding) => {
      const variant = f.status === 'open' ? 'high' : f.status === 'fixed' ? 'success' : 'info'
      return <Badge variant={variant}>{f.status}</Badge>
    },
  },
  {
    key: 'created_at',
    header: 'Found',
    render: (f: EnrichedFinding) => formatRelativeTime(f.created_at),
  },
]

export default function FindingsPage({ embedded }: { embedded?: boolean }) {
  const { findings, total, page, pageSize, loading, filters, fetchFindings, setFilters, setPage } = useFindingStore()
  const { assets, fetchAssets } = useAssetStore()
  const navigate = useNavigate()

  const [scanModalOpen, setScanModalOpen] = useState(false)
  const [scanAssetId, setScanAssetId] = useState('')
  const [scanLoading, setScanLoading] = useState(false)
  const [scanResult, setScanResult] = useState<{
    status: string
    findings_created: number
    findings_duplicate: number
    errors: number
    total_assets: number
  } | null>(null)

  useEffect(() => {
    fetchFindings()
    fetchAssets()
  }, [])

  const handleScan = async () => {
    setScanLoading(true)
    setScanResult(null)
    try {
      const data = scanAssetId ? { asset_id: scanAssetId } : {}
      const res = await vulnScanApi.scan(data)
      setScanResult(res.data)
      fetchFindings()
    } catch (err: any) {
      setScanResult({ status: 'error', findings_created: 0, findings_duplicate: 0, errors: 1, total_assets: 0 })
    } finally {
      setScanLoading(false)
    }
  }

  return (
    <div>
      {!embedded && (
        <PageHeader
          title="Findings"
          description="Vulnerability and misconfiguration findings"
          actions={
            <div className="flex gap-2">
              <button
                onClick={() => { setScanModalOpen(true); setScanResult(null); setScanAssetId('') }}
                className="btn-primary text-sm flex items-center gap-2"
              >
                <Search className="w-4 h-4" />
                Run Vuln Scan
              </button>
              <select
                value={filters.severity || ''}
                onChange={(e) => setFilters({ severity: e.target.value || undefined })}
                className="btn-secondary text-sm"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select
                value={filters.status || ''}
                onChange={(e) => setFilters({ status: e.target.value || undefined })}
                className="btn-secondary text-sm"
              >
                <option value="">All Status</option>
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="fixed">Fixed</option>
                <option value="accepted">Accepted</option>
              </select>
              <select
                value={filters.category || ''}
                onChange={(e) => setFilters({ category: e.target.value || undefined })}
                className="btn-secondary text-sm"
              >
                <option value="">All Categories</option>
                <option value="vuln">Vulnerability</option>
                <option value="misconfig">Misconfiguration</option>
                <option value="exposure">Exposure</option>
                <option value="info">Informational</option>
              </select>
            </div>
          }
        />
      )}

      <DataTable
        columns={columns}
        data={findings}
        loading={loading}
        onRowClick={(finding) => navigate(`/findings/${finding.id}`)}
        emptyMessage="No findings yet. Run a vulnerability scan to detect issues."
      />

      <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} />

      <Modal
        open={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
        title="Run Vulnerability Scan"
        footer={
          !scanResult && (
            <button
              onClick={handleScan}
              disabled={scanLoading}
              className="btn-primary text-sm disabled:opacity-50 flex items-center gap-2"
            >
              {scanLoading && <Loader2 className="w-4 h-4 animate-spin" />}
              {scanLoading ? 'Scanning...' : 'Start Scan'}
            </button>
          )
        }
      >
        {!scanResult ? (
          <div className="space-y-4">
            <p className="text-sm text-gray-600">
              Scan assets for HTTP, TLS, SSH, and DNS vulnerabilities.
            </p>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Target Asset (optional)</label>
              <select
                value={scanAssetId}
                onChange={(e) => setScanAssetId(e.target.value)}
                className="w-full btn-secondary text-sm"
              >
                <option value="">All assets</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.hostname || a.ip_address} ({a.zone})
                  </option>
                ))}
              </select>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {scanResult.status === 'error' ? (
              <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                <p className="text-sm text-red-700 font-medium">Scan failed. Check backend logs.</p>
              </div>
            ) : (
              <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                <p className="text-sm text-green-700 font-medium mb-3">Scan Complete</p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="text-center">
                    <p className="text-2xl font-bold text-green-700">{scanResult.findings_created}</p>
                    <p className="text-xs text-green-600">Findings Created</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-yellow-700">{scanResult.findings_duplicate}</p>
                    <p className="text-xs text-yellow-600">Duplicates Skipped</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-red-700">{scanResult.errors}</p>
                    <p className="text-xs text-red-600">Errors</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-gray-700">{scanResult.total_assets}</p>
                    <p className="text-xs text-gray-600">Assets Scanned</p>
                  </div>
                </div>
              </div>
            )}
            <button
              onClick={() => setScanModalOpen(false)}
              className="btn-secondary text-sm w-full"
            >
              Close
            </button>
          </div>
        )}
      </Modal>
    </div>
  )
}
