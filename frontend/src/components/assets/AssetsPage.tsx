import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import DataTable from '../common/DataTable'
import Pagination from '../common/Pagination'
import Badge from '../common/Badge'
import { useAssetStore } from '../../stores/assetStore'
import { assetsApi, discoveryApi, threatsApi, vulnScanApi } from '../../api/endpoints'
import { formatRelativeTime } from '../../utils/format'
import type { Asset } from '../../types'
import { Loader2, Radar, Zap, Search, CheckCircle, RefreshCw, Trash2, AlertTriangle } from 'lucide-react'

export default function AssetsPage() {
  const navigate = useNavigate()
  const { assets, total, page, pageSize, loading, filters, fetchAssets, setFilters, setPage, deleteAsset } = useAssetStore()

  // Discovery modal state
  const [discoveryOpen, setDiscoveryOpen] = useState(false)
  const [discoveryCidr, setDiscoveryCidr] = useState('')
  const [gatewayLoading, setGatewayLoading] = useState(false)
  const [discoveryLoading, setDiscoveryLoading] = useState(false)
  const [discoveryResult, setDiscoveryResult] = useState<any>(null)
  // Post-discovery workflow
  const [threatLoading, setThreatLoading] = useState(false)
  const [threatResult, setThreatResult] = useState<any>(null)
  const [vulnLoading, setVulnLoading] = useState(false)
  const [vulnResult, setVulnResult] = useState<any>(null)

  // Refresh modal state
  const [refreshOpen, setRefreshOpen] = useState(false)
  const [refreshCidr, setRefreshCidr] = useState('')
  const [refreshGatewayLoading, setRefreshGatewayLoading] = useState(false)
  const [refreshLoading, setRefreshLoading] = useState(false)
  const [refreshResult, setRefreshResult] = useState<any>(null)

  // Delete modal state
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [deleteTargetAsset, setDeleteTargetAsset] = useState<Asset | null>(null)
  const [deletePreview, setDeletePreview] = useState<any>(null)
  const [deleteLoading, setDeleteLoading] = useState(false)

  useEffect(() => {
    fetchAssets()
  }, [])

  const openDiscoveryModal = async () => {
    setDiscoveryOpen(true)
    setDiscoveryResult(null)
    setThreatResult(null)
    setVulnResult(null)
    setDiscoveryCidr('')
    setGatewayLoading(true)
    try {
      const res = await assetsApi.detectGateway()
      const data = res.data as any
      if (data.cidr) setDiscoveryCidr(data.cidr)
    } catch { /* empty */ }
    setGatewayLoading(false)
  }

  const startDiscovery = async () => {
    if (!discoveryCidr) return
    setDiscoveryLoading(true)
    setDiscoveryResult(null)
    setThreatResult(null)
    setVulnResult(null)
    try {
      const res = await discoveryApi.discover({ subnet: discoveryCidr })
      setDiscoveryResult(res.data)
      fetchAssets()
    } catch (err: any) {
      setDiscoveryResult({ status: 'error', error: err.message })
    }
    setDiscoveryLoading(false)
  }

  const runThreatModeling = async () => {
    setThreatLoading(true)
    setThreatResult(null)
    try {
      const res = await threatsApi.generate({})
      setThreatResult(res.data)
    } catch (err: any) {
      setThreatResult({ status: 'error', error: err.message })
    }
    setThreatLoading(false)
  }

  const runVulnScan = async () => {
    setVulnLoading(true)
    setVulnResult(null)
    try {
      const res = await vulnScanApi.scan({})
      setVulnResult(res.data)
    } catch (err: any) {
      setVulnResult({ status: 'error', error: err.message })
    }
    setVulnLoading(false)
  }

  // Refresh Assets
  const openRefreshModal = async () => {
    setRefreshOpen(true)
    setRefreshResult(null)
    setRefreshCidr('')
    setRefreshGatewayLoading(true)
    try {
      const res = await assetsApi.detectGateway()
      const data = res.data as any
      if (data.cidr) setRefreshCidr(data.cidr)
    } catch { /* empty */ }
    setRefreshGatewayLoading(false)
  }

  const startRefresh = async () => {
    if (!refreshCidr) return
    setRefreshLoading(true)
    setRefreshResult(null)
    try {
      const res = await discoveryApi.discover({ subnet: refreshCidr })
      setRefreshResult(res.data)
      fetchAssets()
    } catch (err: any) {
      setRefreshResult({ status: 'error', error: err.message })
    }
    setRefreshLoading(false)
  }

  // Row-level delete
  const openRowDelete = async (asset: Asset, e: React.MouseEvent) => {
    e.stopPropagation()
    setDeleteTargetAsset(asset)
    setDeleteModalOpen(true)
    setDeletePreview(null)
    try {
      const res = await assetsApi.deletePreview(asset.id)
      setDeletePreview(res.data)
    } catch {
      setDeletePreview({ findings: '?', threats: '?', risks: '?', mitre_mappings: '?', vulnerabilities: '?' })
    }
  }

  const confirmDelete = async () => {
    if (!deleteTargetAsset) return
    setDeleteLoading(true)
    try {
      await deleteAsset(deleteTargetAsset.id)
      setDeleteModalOpen(false)
      setDeleteTargetAsset(null)
    } catch { /* empty */ }
    setDeleteLoading(false)
  }

  const columns = [
    {
      key: 'ip_address',
      header: 'IP Address',
      render: (asset: Asset) => (
        <span className="font-mono text-sm">{asset.ip_address}</span>
      ),
    },
    {
      key: 'hostname',
      header: 'Hostname',
      render: (asset: Asset) => asset.hostname || '-',
    },
    {
      key: 'asset_type',
      header: 'Type',
      render: (asset: Asset) => (
        <span className="capitalize">{asset.asset_type}</span>
      ),
    },
    {
      key: 'zone',
      header: 'Zone',
      render: (asset: Asset) => (
        <Badge variant="info">{asset.zone.toUpperCase()}</Badge>
      ),
    },
    {
      key: 'criticality',
      header: 'Criticality',
      render: (asset: Asset) => (
        <Badge variant={asset.criticality as any}>{asset.criticality}</Badge>
      ),
    },
    {
      key: 'vendor',
      header: 'Vendor',
      render: (asset: Asset) => asset.vendor || '-',
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      render: (asset: Asset) => formatRelativeTime(asset.last_seen),
    },
    {
      key: 'actions',
      header: '',
      render: (asset: Asset) => (
        <button
          onClick={(e) => openRowDelete(asset, e)}
          className="p-1.5 text-gray-400 hover:text-red-600 rounded hover:bg-red-50 transition-colors"
          title="Delete asset"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      ),
    },
  ]

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Network asset inventory"
        actions={
          <div className="flex gap-2">
            <button
              onClick={openRefreshModal}
              className="btn-secondary text-sm flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh Assets
            </button>
            <button
              onClick={openDiscoveryModal}
              className="btn-primary text-sm flex items-center gap-2"
            >
              <Radar className="w-4 h-4" />
              Discover Assets
            </button>
            <select
              value={filters.zone || ''}
              onChange={(e) => setFilters({ zone: e.target.value || undefined })}
              className="btn-secondary text-sm"
            >
              <option value="">All Zones</option>
              <option value="lan">LAN</option>
              <option value="iot">IoT</option>
              <option value="guest">Guest</option>
              <option value="dmz">DMZ</option>
            </select>
            <select
              value={filters.criticality || ''}
              onChange={(e) => setFilters({ criticality: e.target.value || undefined })}
              className="btn-secondary text-sm"
            >
              <option value="">All Criticality</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        }
      />

      <DataTable
        columns={columns}
        data={assets}
        loading={loading}
        onRowClick={(asset) => navigate(`/assets/${asset.id}`)}
        emptyMessage="No assets found. Run a discovery scan to find network assets."
      />

      <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} />

      {/* Discovery Modal */}
      {discoveryOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto">
            <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
              <Radar className="w-5 h-5 text-brand-600" />
              Discover Assets
            </h3>

            {/* CIDR Input */}
            <div className="mb-4">
              <label className="block text-xs font-medium text-gray-700 mb-1">Target CIDR</label>
              <div className="flex gap-2">
                <input
                  value={discoveryCidr}
                  onChange={(e) => setDiscoveryCidr(e.target.value)}
                  className="flex-1 px-3 py-2 border rounded-lg text-sm font-mono"
                  placeholder="e.g., 192.168.1.0/24"
                  disabled={discoveryLoading}
                />
                {gatewayLoading && <Loader2 className="w-5 h-5 animate-spin text-gray-400 self-center" />}
              </div>
              <p className="text-xs text-gray-400 mt-1">Auto-detected from default gateway. Edit if needed.</p>
            </div>

            {/* Start button */}
            {!discoveryResult && (
              <button
                onClick={startDiscovery}
                disabled={discoveryLoading || !discoveryCidr}
                className="btn-primary text-sm w-full flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {discoveryLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
                {discoveryLoading ? 'Scanning...' : 'Start Discovery'}
              </button>
            )}

            {/* Discovery Results */}
            {discoveryResult && (
              <div className="mt-4 space-y-4">
                {discoveryResult.status === 'error' ? (
                  <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                    <p className="text-sm text-red-700 font-medium">Discovery failed</p>
                    <p className="text-xs text-red-600 mt-1">{discoveryResult.error}</p>
                  </div>
                ) : (
                  <>
                    <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                      <p className="text-sm text-green-700 font-medium mb-3">Discovery Complete</p>
                      <div className="grid grid-cols-3 gap-3">
                        <div className="text-center">
                          <p className="text-2xl font-bold text-green-700">{discoveryResult.hosts_discovered ?? discoveryResult.total_hosts ?? 0}</p>
                          <p className="text-xs text-green-600">Hosts Found</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-blue-700">{discoveryResult.assets_created ?? 0}</p>
                          <p className="text-xs text-blue-600">Assets Created</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-gray-700">{discoveryResult.assets_updated ?? 0}</p>
                          <p className="text-xs text-gray-600">Assets Updated</p>
                        </div>
                      </div>
                      {discoveryResult.hosts && discoveryResult.hosts.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-green-200">
                          <p className="text-xs font-medium text-green-700 mb-1">Discovered IPs:</p>
                          <div className="flex flex-wrap gap-1">
                            {discoveryResult.hosts.slice(0, 20).map((ip: string) => (
                              <span key={ip} className="font-mono text-xs bg-green-100 px-1.5 py-0.5 rounded">{ip}</span>
                            ))}
                            {discoveryResult.hosts.length > 20 && (
                              <span className="text-xs text-green-600">+{discoveryResult.hosts.length - 20} more</span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Next Steps Workflow */}
                    <div className="border rounded-lg p-4">
                      <h4 className="text-sm font-semibold text-gray-700 mb-3">Next Steps</h4>
                      <div className="space-y-3">
                        {/* Model Threats */}
                        <div className="flex items-center gap-3">
                          <button
                            onClick={runThreatModeling}
                            disabled={threatLoading || !!threatResult}
                            className="btn-secondary text-xs flex items-center gap-2 disabled:opacity-50 shrink-0"
                          >
                            {threatLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : threatResult ? <CheckCircle className="w-3.5 h-3.5 text-green-500" /> : <Zap className="w-3.5 h-3.5" />}
                            Model Threats
                          </button>
                          {threatResult && (
                            <span className="text-xs text-gray-600">
                              {threatResult.status === 'error'
                                ? 'Failed'
                                : `${threatResult.threats_created ?? 0} threats created`}
                            </span>
                          )}
                        </div>

                        {/* Run Vuln Scan */}
                        <div className="flex items-center gap-3">
                          <button
                            onClick={runVulnScan}
                            disabled={vulnLoading || !!vulnResult}
                            className="btn-secondary text-xs flex items-center gap-2 disabled:opacity-50 shrink-0"
                          >
                            {vulnLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : vulnResult ? <CheckCircle className="w-3.5 h-3.5 text-green-500" /> : <Search className="w-3.5 h-3.5" />}
                            Run Vuln Scan
                          </button>
                          {vulnResult && (
                            <span className="text-xs text-gray-600">
                              {vulnResult.status === 'error'
                                ? 'Failed'
                                : `${vulnResult.findings_created ?? 0} findings created`}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Close */}
            <div className="flex justify-end mt-6">
              <button onClick={() => setDiscoveryOpen(false)} className="btn-secondary text-sm">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Refresh Modal */}
      {refreshOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6">
            <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
              <RefreshCw className="w-5 h-5 text-brand-600" />
              Refresh Assets
            </h3>

            <p className="text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-lg p-3 mb-4">
              This will re-scan the network and update existing assets with current information.
            </p>

            <div className="mb-4">
              <label className="block text-xs font-medium text-gray-700 mb-1">Target CIDR</label>
              <div className="flex gap-2">
                <input
                  value={refreshCidr}
                  onChange={(e) => setRefreshCidr(e.target.value)}
                  className="flex-1 px-3 py-2 border rounded-lg text-sm font-mono"
                  placeholder="e.g., 192.168.1.0/24"
                  disabled={refreshLoading}
                />
                {refreshGatewayLoading && <Loader2 className="w-5 h-5 animate-spin text-gray-400 self-center" />}
              </div>
              <p className="text-xs text-gray-400 mt-1">Auto-detected from default gateway. Edit if needed.</p>
            </div>

            {!refreshResult && (
              <button
                onClick={startRefresh}
                disabled={refreshLoading || !refreshCidr}
                className="btn-primary text-sm w-full flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {refreshLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                {refreshLoading ? 'Scanning...' : 'Start Refresh'}
              </button>
            )}

            {refreshResult && (
              <div className="mt-4">
                {refreshResult.status === 'error' ? (
                  <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                    <p className="text-sm text-red-700 font-medium">Refresh failed</p>
                    <p className="text-xs text-red-600 mt-1">{refreshResult.error}</p>
                  </div>
                ) : (
                  <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                    <p className="text-sm text-green-700 font-medium mb-3">Refresh Complete</p>
                    <div className="grid grid-cols-3 gap-3">
                      <div className="text-center">
                        <p className="text-2xl font-bold text-green-700">{refreshResult.hosts_discovered ?? refreshResult.total_hosts ?? 0}</p>
                        <p className="text-xs text-green-600">Hosts Found</p>
                      </div>
                      <div className="text-center">
                        <p className="text-2xl font-bold text-blue-700">{refreshResult.assets_created ?? 0}</p>
                        <p className="text-xs text-blue-600">New Assets</p>
                      </div>
                      <div className="text-center">
                        <p className="text-2xl font-bold text-gray-700">{refreshResult.assets_updated ?? 0}</p>
                        <p className="text-xs text-gray-600">Updated</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end mt-6">
              <button onClick={() => setRefreshOpen(false)} className="btn-secondary text-sm">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModalOpen && deleteTargetAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-600" />
              </div>
              <h3 className="font-semibold text-lg">Delete Asset</h3>
            </div>

            <p className="text-sm text-gray-600 mb-4">
              This will permanently delete <strong>{deleteTargetAsset.hostname || deleteTargetAsset.ip_address}</strong> and all linked records:
            </p>

            {deletePreview ? (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4 space-y-1">
                <p className="text-sm text-red-700"><strong>{deletePreview.findings}</strong> findings</p>
                <p className="text-sm text-red-700"><strong>{deletePreview.threats}</strong> threats</p>
                <p className="text-sm text-red-700"><strong>{deletePreview.risks}</strong> risks</p>
                <p className="text-sm text-red-700"><strong>{deletePreview.mitre_mappings}</strong> MITRE mappings</p>
                <p className="text-sm text-red-700"><strong>{deletePreview.vulnerabilities}</strong> vulnerabilities</p>
              </div>
            ) : (
              <div className="flex items-center gap-2 mb-4 text-sm text-gray-500">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading linked records...
              </div>
            )}

            <p className="text-xs text-red-500 mb-4">This action cannot be undone.</p>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => { setDeleteModalOpen(false); setDeleteTargetAsset(null) }}
                disabled={deleteLoading}
                className="btn-secondary text-sm"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                disabled={deleteLoading || !deletePreview}
                className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-50 flex items-center gap-2"
              >
                {deleteLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                Delete Everything
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
