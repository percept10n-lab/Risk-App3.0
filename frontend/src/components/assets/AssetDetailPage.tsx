import { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { useAssetStore } from '../../stores/assetStore'
import { formatDate } from '../../utils/format'
import { ArrowLeft } from 'lucide-react'

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { selectedAsset: asset, loading, fetchAsset } = useAssetStore()

  useEffect(() => {
    if (id) fetchAsset(id)
  }, [id])

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
          <Badge variant={asset.criticality as any}>{asset.criticality}</Badge>
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
    </div>
  )
}
