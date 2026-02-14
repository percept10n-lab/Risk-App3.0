import { useEffect } from 'react'
import PageHeader from '../common/PageHeader'
import DataTable from '../common/DataTable'
import Pagination from '../common/Pagination'
import Badge from '../common/Badge'
import { useFindingStore } from '../../stores/findingStore'
import { formatRelativeTime } from '../../utils/format'
import type { Finding } from '../../types'

const columns = [
  {
    key: 'severity',
    header: 'Severity',
    render: (f: Finding) => (
      <Badge variant={f.severity as any}>{f.severity}</Badge>
    ),
    className: 'w-24',
  },
  {
    key: 'title',
    header: 'Title',
    render: (f: Finding) => (
      <div>
        <p className="font-medium text-sm">{f.title}</p>
        <p className="text-xs text-gray-500 mt-0.5 truncate max-w-md">{f.description}</p>
      </div>
    ),
  },
  {
    key: 'category',
    header: 'Category',
    render: (f: Finding) => <span className="capitalize text-sm">{f.category}</span>,
  },
  {
    key: 'source_tool',
    header: 'Source',
    render: (f: Finding) => <span className="font-mono text-xs">{f.source_tool}</span>,
  },
  {
    key: 'status',
    header: 'Status',
    render: (f: Finding) => {
      const variant = f.status === 'open' ? 'high' : f.status === 'fixed' ? 'success' : 'info'
      return <Badge variant={variant}>{f.status}</Badge>
    },
  },
  {
    key: 'created_at',
    header: 'Found',
    render: (f: Finding) => formatRelativeTime(f.created_at),
  },
]

export default function FindingsPage() {
  const { findings, total, page, pageSize, loading, filters, fetchFindings, setFilters, setPage } = useFindingStore()

  useEffect(() => {
    fetchFindings()
  }, [])

  return (
    <div>
      <PageHeader
        title="Findings"
        description="Vulnerability and misconfiguration findings"
        actions={
          <div className="flex gap-2">
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

      <DataTable
        columns={columns}
        data={findings}
        loading={loading}
        emptyMessage="No findings yet. Run a vulnerability scan to detect issues."
      />

      <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} />
    </div>
  )
}
