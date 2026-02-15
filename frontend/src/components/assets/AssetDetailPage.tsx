import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { useAssetStore } from '../../stores/assetStore'
import { assetsApi } from '../../api/endpoints'
import { formatDate } from '../../utils/format'
import { ArrowLeft, Trash2, RefreshCw, Loader2, AlertTriangle } from 'lucide-react'

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { selectedAsset: asset, loading, fetchAsset, deleteAsset } = useAssetStore()

  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [deletePreview, setDeletePreview] = useState<any>(null)
  const [deleteLoading, setDeleteLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    if (id) fetchAsset(id)
  }, [id])

  const openDeleteModal = async () => {
    if (!id) return
    setDeleteModalOpen(true)
    setDeletePreview(null)
    try {
      const res = await assetsApi.deletePreview(id)
      setDeletePreview(res.data)
    } catch {
      setDeletePreview({ findings: '?', threats: '?', risks: '?', mitre_mappings: '?', vulnerabilities: '?' })
    }
  }

  const confirmDelete = async () => {
    if (!id) return
    setDeleteLoading(true)
    try {
      await deleteAsset(id)
      navigate('/assets')
    } catch {
      setDeleteLoading(false)
    }
  }

  const handleRefresh = async () => {
    if (!id) return
    setRefreshing(true)
    try {
      await assetsApi.fingerprint({ asset_id: id })
      await fetchAsset(id)
    } catch { /* empty */ }
    setRefreshing(false)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
      </div>
    )
  }

  if (!asset) {
    return <div className="text-center py-12 text-gray-500">Asset not found</div>
  }

  return (
    <div>
      <button onClick={() => navigate('/assets')} className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 mb-4">
        <ArrowLeft className="w-4 h-4" /> Back to Assets
      </button>

      <PageHeader
        title={asset.hostname || asset.ip_address}
        description={`${asset.asset_type} in ${asset.zone} zone`}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="btn-secondary text-sm flex items-center gap-2"
            >
              {refreshing ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
              Refresh
            </button>
            <button
              onClick={openDeleteModal}
              className="px-3 py-2 text-sm font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete Asset
            </button>
            <Badge variant={asset.criticality as any}>{asset.criticality}</Badge>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="font-semibold mb-4">Network Information</h3>
          <dl className="space-y-3">
            {[
              ['IP Address', asset.ip_address],
              ['MAC Address', asset.mac_address || '-'],
              ['Hostname', asset.hostname || '-'],
              ['Vendor', asset.vendor || '-'],
              ['OS', asset.os_guess || '-'],
            ].map(([label, value]) => (
              <div key={label} className="flex justify-between">
                <dt className="text-sm text-gray-500">{label}</dt>
                <dd className="text-sm font-medium font-mono">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="card p-6">
          <h3 className="font-semibold mb-4">Classification</h3>
          <dl className="space-y-3">
            {[
              ['Type', asset.asset_type],
              ['Zone', asset.zone],
              ['Owner', asset.owner || '-'],
              ['Update Capability', asset.update_capability],
              ['First Seen', formatDate(asset.first_seen)],
              ['Last Seen', formatDate(asset.last_seen)],
            ].map(([label, value]) => (
              <div key={label} className="flex justify-between">
                <dt className="text-sm text-gray-500">{label}</dt>
                <dd className="text-sm font-medium">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        {asset.exposure && Object.keys(asset.exposure).length > 0 && (
          <div className="card p-6">
            <h3 className="font-semibold mb-4">Exposure</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(asset.exposure).map(([key, val]) => (
                <Badge key={key} variant={val ? 'high' : 'success'}>
                  {key}: {val ? 'Yes' : 'No'}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {asset.tags && asset.tags.length > 0 && (
          <div className="card p-6">
            <h3 className="font-semibold mb-4">Tags</h3>
            <div className="flex flex-wrap gap-2">
              {asset.tags.map((tag: string) => (
                <Badge key={tag} variant="info">{tag}</Badge>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-600" />
              </div>
              <h3 className="font-semibold text-lg">Delete Asset</h3>
            </div>

            <p className="text-sm text-gray-600 mb-4">
              This will permanently delete <strong>{asset.hostname || asset.ip_address}</strong> and all linked records:
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
                onClick={() => setDeleteModalOpen(false)}
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
