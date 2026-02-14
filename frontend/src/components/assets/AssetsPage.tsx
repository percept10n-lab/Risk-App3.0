import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import DataTable from '../common/DataTable'
import Pagination from '../common/Pagination'
import Badge from '../common/Badge'
import { useAssetStore } from '../../stores/assetStore'
import { formatRelativeTime } from '../../utils/format'
import type { Asset } from '../../types'

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
]

export default function AssetsPage() {
  const navigate = useNavigate()
  const { assets, total, page, pageSize, loading, filters, fetchAssets, setFilters, setPage } = useAssetStore()

  useEffect(() => {
    fetchAssets()
  }, [])

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Network asset inventory"
        actions={
          <div className="flex gap-2">
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
    </div>
  )
}
