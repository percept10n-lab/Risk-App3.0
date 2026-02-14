import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { GitCompare, AlertTriangle, Plus, Minus, ArrowRightLeft, RefreshCw, Database } from 'lucide-react'
import api from '../../api/client'

interface DriftChange {
  type: string
  zone: string
  severity: string
  description: string
  details: Record<string, any>
  baseline_id: string
  detected_at: string
}

interface BaselineInfo {
  id: string
  zone: string
  baseline_type: string
  asset_count: number
  created_at: string
  run_id: string | null
}

export default function DriftPage() {
  const [changes, setChanges] = useState<DriftChange[]>([])
  const [baselines, setBaselines] = useState<BaselineInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setLoading(true)
    try {
      const [changesRes, baselinesRes] = await Promise.allSettled([
        api.get('/drift/changes'),
        api.get('/drift/baselines'),
      ])
      if (changesRes.status === 'fulfilled') {
        setChanges(changesRes.value.data.changes || [])
      }
      if (baselinesRes.status === 'fulfilled') {
        setBaselines(baselinesRes.value.data.baselines || [])
      }
    } catch { /* empty */ }
    setLoading(false)
  }

  async function createBaseline(zone: string) {
    setCreating(true)
    try {
      await api.post('/drift/baseline', null, { params: { zone, baseline_type: 'full' } })
      await loadData()
    } catch { /* empty */ }
    setCreating(false)
  }

  const changeIcon = (type: string) => {
    switch (type) {
      case 'new_asset': return <Plus className="w-4 h-4 text-green-500" />
      case 'removed_asset': return <Minus className="w-4 h-4 text-red-500" />
      case 'new_ports': return <AlertTriangle className="w-4 h-4 text-orange-500" />
      case 'closed_ports': return <ArrowRightLeft className="w-4 h-4 text-blue-500" />
      case 'exposure_change': return <AlertTriangle className="w-4 h-4 text-red-500" />
      default: return <GitCompare className="w-4 h-4 text-gray-500" />
    }
  }

  const alertCount = changes.filter((c) => c.severity === 'critical' || c.severity === 'high').length

  return (
    <div>
      <PageHeader
        title="Drift Monitor"
        description="Track changes between assessment runs"
        actions={
          <div className="flex gap-2">
            <button onClick={loadData} className="btn-secondary flex items-center gap-2">
              <RefreshCw className="w-4 h-4" /> Refresh
            </button>
            <button onClick={() => createBaseline('lan')} disabled={creating} className="btn-primary flex items-center gap-2">
              <Database className="w-4 h-4" /> {creating ? 'Creating...' : 'New Baseline (LAN)'}
            </button>
          </div>
        }
      />

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold">{baselines.length}</p>
          <p className="text-xs text-gray-500">Baselines</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold">{changes.length}</p>
          <p className="text-xs text-gray-500">Total Changes</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-red-600">{alertCount}</p>
          <p className="text-xs text-gray-500">High/Critical Alerts</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold">{new Set(baselines.map((b) => b.zone)).size}</p>
          <p className="text-xs text-gray-500">Zones Tracked</p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Changes */}
          <div className="lg:col-span-2">
            <div className="card">
              <div className="px-6 py-4 border-b">
                <h3 className="font-semibold">Detected Changes</h3>
              </div>
              {changes.length === 0 ? (
                <div className="p-8 text-center text-gray-500 text-sm">
                  <GitCompare className="w-10 h-10 mx-auto mb-3 text-gray-300" />
                  <p>No changes detected since last baseline.</p>
                  <p className="mt-1">Run a new assessment and compare against the baseline.</p>
                </div>
              ) : (
                <div className="divide-y max-h-[500px] overflow-y-auto">
                  {changes.map((change, idx) => (
                    <div key={idx} className="p-4 hover:bg-gray-50 flex items-start gap-3">
                      {changeIcon(change.type)}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <Badge variant={change.severity as any}>{change.severity}</Badge>
                          <span className="text-xs text-gray-400 capitalize">{change.type.replace(/_/g, ' ')}</span>
                          <span className="text-xs text-gray-400">| {change.zone}</span>
                        </div>
                        <p className="text-sm">{change.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Baselines */}
          <div>
            <div className="card">
              <div className="px-4 py-3 border-b">
                <h3 className="font-semibold text-sm">Baseline History</h3>
              </div>
              {baselines.length === 0 ? (
                <div className="p-6 text-center text-gray-400 text-sm">
                  No baselines created yet.
                </div>
              ) : (
                <div className="divide-y">
                  {baselines.map((b) => (
                    <div key={b.id} className="p-3">
                      <div className="flex items-center justify-between">
                        <Badge variant="info">{b.zone}</Badge>
                        <span className="text-xs text-gray-400">{b.baseline_type}</span>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">{b.asset_count} assets</p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        {b.created_at ? new Date(b.created_at).toLocaleString() : '-'}
                      </p>
                    </div>
                  ))}
                </div>
              )}
              <div className="p-3 border-t">
                <div className="flex gap-2">
                  <button onClick={() => createBaseline('lan')} disabled={creating} className="btn-secondary text-xs flex-1">
                    LAN
                  </button>
                  <button onClick={() => createBaseline('iot')} disabled={creating} className="btn-secondary text-xs flex-1">
                    IoT
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
