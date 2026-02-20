import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import {
  GitCompare, AlertTriangle, Plus, Minus, ArrowRightLeft, RefreshCw,
  Database, Shield, ChevronDown, ChevronRight, Bell, CheckCircle2,
} from 'lucide-react'
import { driftApi } from '../../api/endpoints'

interface DriftChange {
  type: string
  zone: string
  severity: string
  description: string
  details: Record<string, any>
  baseline_id: string
  detected_at: string
}

interface DriftAlert {
  severity: string
  zone: string
  description: string
  change_type: string
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

const ZONES = ['all', 'lan', 'iot', 'guest', 'dmz'] as const

export default function DriftPage({ embedded }: { embedded?: boolean }) {
  const [changes, setChanges] = useState<DriftChange[]>([])
  const [alerts, setAlerts] = useState<DriftAlert[]>([])
  const [baselines, setBaselines] = useState<BaselineInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [zoneFilter, setZoneFilter] = useState<string>('all')
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())
  const [showBaselineForm, setShowBaselineForm] = useState(false)
  const [newBaseline, setNewBaseline] = useState({ zone: 'lan', baseline_type: 'full' })

  useEffect(() => {
    loadData()
  }, [zoneFilter])

  async function loadData() {
    setLoading(true)
    const params = zoneFilter !== 'all' ? { zone: zoneFilter } : undefined
    try {
      const [changesRes, alertsRes, baselinesRes] = await Promise.allSettled([
        driftApi.changes(params),
        driftApi.alerts(params),
        driftApi.baselines(params),
      ])
      if (changesRes.status === 'fulfilled') {
        setChanges(changesRes.value.data.changes || [])
      }
      if (alertsRes.status === 'fulfilled') {
        setAlerts(alertsRes.value.data.alerts || [])
      }
      if (baselinesRes.status === 'fulfilled') {
        setBaselines(baselinesRes.value.data.baselines || [])
      }
    } catch (err: any) { console.error('Failed to load drift data:', err.message) }
    setLoading(false)
  }

  async function createBaseline() {
    setCreating(true)
    try {
      await driftApi.createBaseline({
        zone: newBaseline.zone,
        baseline_type: newBaseline.baseline_type,
      })
      setShowBaselineForm(false)
      await loadData()
    } catch (err: any) { console.error('Failed to create baseline:', err.message) }
    setCreating(false)
  }

  function toggleRow(idx: number) {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
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

  const severityBorder = (severity: string) => {
    switch (severity) {
      case 'critical': return 'border-l-4 border-l-red-500'
      case 'high': return 'border-l-4 border-l-orange-500'
      case 'medium': return 'border-l-4 border-l-yellow-500'
      default: return 'border-l-4 border-l-blue-300'
    }
  }

  const criticalAlerts = alerts.filter((a) => a.severity === 'critical' || a.severity === 'high')
  const driftStatus = criticalAlerts.length > 0 ? 'ALERT' : changes.length > 0 ? 'DRIFTED' : 'STABLE'

  const statusBadge = () => {
    switch (driftStatus) {
      case 'ALERT': return <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-100 text-red-700">ALERT</span>
      case 'DRIFTED': return <span className="px-3 py-1 rounded-full text-xs font-bold bg-yellow-100 text-yellow-700">DRIFTED</span>
      case 'STABLE': return <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-100 text-green-700">STABLE</span>
    }
  }

  const baselineAge = (created: string) => {
    if (!created) return '-'
    const diff = Date.now() - new Date(created).getTime()
    const hours = Math.floor(diff / 3600000)
    if (hours < 1) return 'just now'
    if (hours < 24) return `${hours}h ago`
    return `${Math.floor(hours / 24)}d ago`
  }

  // Group changes by date
  const groupedChanges: Record<string, DriftChange[]> = {}
  changes.forEach((c) => {
    const date = c.detected_at ? new Date(c.detected_at).toLocaleDateString() : 'Unknown'
    if (!groupedChanges[date]) groupedChanges[date] = []
    groupedChanges[date].push(c)
  })

  return (
    <div>
      {!embedded && (
        <PageHeader
          title="Drift Monitor"
          description="Track changes between assessment runs"
          actions={
            <div className="flex items-center gap-3">
              {statusBadge()}
              <button onClick={loadData} className="btn-secondary flex items-center gap-2">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
            </div>
          }
        />
      )}

      {/* Alert Banner */}
      {criticalAlerts.length > 0 && (
        <div className="mb-6 p-4 rounded-lg bg-red-50 border border-red-200">
          <div className="flex items-center gap-2 text-red-700 font-medium mb-2">
            <Bell className="w-5 h-5" />
            {criticalAlerts.length} Critical/High Alert{criticalAlerts.length > 1 ? 's' : ''}
          </div>
          <div className="space-y-1">
            {criticalAlerts.slice(0, 5).map((a, i) => (
              <div key={i} className="flex items-center gap-2 text-sm text-red-600">
                <Badge variant={a.severity as any}>{a.severity}</Badge>
                <span>{a.description}</span>
                <span className="text-red-400 text-xs">({a.zone})</span>
              </div>
            ))}
            {criticalAlerts.length > 5 && (
              <p className="text-xs text-red-400">+{criticalAlerts.length - 5} more...</p>
            )}
          </div>
        </div>
      )}

      {/* Summary cards + Zone filter */}
      <div className="flex items-center gap-4 mb-6">
        <div className="grid grid-cols-4 gap-4 flex-1">
          <div className="card p-4 flex items-center gap-3">
            <Database className="w-8 h-8 text-brand-500" />
            <div>
              <p className="text-2xl font-bold">{baselines.length}</p>
              <p className="text-xs text-gray-500">Baselines</p>
            </div>
          </div>
          <div className="card p-4 flex items-center gap-3">
            <GitCompare className="w-8 h-8 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{changes.length}</p>
              <p className="text-xs text-gray-500">Changes</p>
            </div>
          </div>
          <div className="card p-4 flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-red-500" />
            <div>
              <p className="text-2xl font-bold text-red-600">{criticalAlerts.length}</p>
              <p className="text-xs text-gray-500">Alerts</p>
            </div>
          </div>
          <div className="card p-4 flex items-center gap-3">
            <Shield className="w-8 h-8 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{new Set(baselines.map((b) => b.zone)).size}</p>
              <p className="text-xs text-gray-500">Zones</p>
            </div>
          </div>
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">Zone Filter</label>
          <select
            value={zoneFilter}
            onChange={(e) => setZoneFilter(e.target.value)}
            className="px-3 py-2 border rounded-lg text-sm"
          >
            {ZONES.map((z) => (
              <option key={z} value={z}>{z === 'all' ? 'All Zones' : z.toUpperCase()}</option>
            ))}
          </select>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Changes Timeline */}
          <div className="lg:col-span-2">
            <div className="card">
              <div className="px-6 py-4 border-b flex items-center justify-between">
                <h3 className="font-semibold">Changes Timeline</h3>
                <span className="text-xs text-gray-400">{changes.length} total</span>
              </div>
              {changes.length === 0 ? (
                <div className="p-8 text-center text-gray-500 text-sm">
                  <CheckCircle2 className="w-10 h-10 mx-auto mb-3 text-green-300" />
                  <p>No changes detected since last baseline.</p>
                  <p className="mt-1 text-gray-400">Run a new assessment and compare against the baseline.</p>
                </div>
              ) : (
                <div className="max-h-[600px] overflow-y-auto">
                  {Object.entries(groupedChanges).map(([date, dateChanges]) => (
                    <div key={date}>
                      <div className="px-6 py-2 bg-gray-50 text-xs font-medium text-gray-500 sticky top-0">
                        {date}
                      </div>
                      <div className="divide-y">
                        {dateChanges.map((change, idx) => {
                          const globalIdx = changes.indexOf(change)
                          const isExpanded = expandedRows.has(globalIdx)
                          const hasDetails = change.details && Object.keys(change.details).length > 0
                          return (
                            <div key={idx} className={`${severityBorder(change.severity)}`}>
                              <div
                                className={`p-4 flex items-start gap-3 hover:bg-gray-50 ${hasDetails ? 'cursor-pointer' : ''}`}
                                onClick={() => hasDetails && toggleRow(globalIdx)}
                              >
                                {changeIcon(change.type)}
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-0.5">
                                    <Badge variant={change.severity as any}>{change.severity}</Badge>
                                    <span className="text-xs text-gray-400 capitalize">{change.type.replace(/_/g, ' ')}</span>
                                    <Badge variant="info">{change.zone}</Badge>
                                  </div>
                                  <p className="text-sm">{change.description}</p>
                                </div>
                                {hasDetails && (
                                  isExpanded
                                    ? <ChevronDown className="w-4 h-4 text-gray-400 shrink-0 mt-1" />
                                    : <ChevronRight className="w-4 h-4 text-gray-400 shrink-0 mt-1" />
                                )}
                              </div>
                              {isExpanded && hasDetails && (
                                <div className="px-12 pb-4">
                                  <div className="bg-gray-50 rounded-lg p-3 text-xs space-y-1">
                                    {Object.entries(change.details).map(([k, v]) => (
                                      <div key={k} className="flex gap-2">
                                        <span className="text-gray-500 font-medium min-w-[100px]">{k}:</span>
                                        <span className="text-gray-700 font-mono">
                                          {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right: Baseline Management */}
          <div>
            <div className="card">
              <div className="px-4 py-3 border-b flex items-center justify-between">
                <h3 className="font-semibold text-sm">Baseline Management</h3>
                <button
                  onClick={() => setShowBaselineForm(!showBaselineForm)}
                  className="text-xs text-brand-600 hover:text-brand-800 font-medium"
                >
                  {showBaselineForm ? 'Cancel' : '+ New Baseline'}
                </button>
              </div>

              {/* Inline Create Form */}
              {showBaselineForm && (
                <div className="p-4 border-b bg-gray-50 space-y-3">
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">Zone</label>
                    <select
                      value={newBaseline.zone}
                      onChange={(e) => setNewBaseline({ ...newBaseline, zone: e.target.value })}
                      className="w-full px-2 py-1.5 border rounded text-sm"
                    >
                      {['lan', 'iot', 'guest', 'dmz'].map((z) => (
                        <option key={z} value={z}>{z.toUpperCase()}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">Type</label>
                    <select
                      value={newBaseline.baseline_type}
                      onChange={(e) => setNewBaseline({ ...newBaseline, baseline_type: e.target.value })}
                      className="w-full px-2 py-1.5 border rounded text-sm"
                    >
                      <option value="full">Full</option>
                      <option value="ports_only">Ports Only</option>
                      <option value="services_only">Services Only</option>
                    </select>
                  </div>
                  <button
                    onClick={createBaseline}
                    disabled={creating}
                    className="btn-primary text-xs w-full flex items-center justify-center gap-2"
                  >
                    <Database className="w-3 h-3" />
                    {creating ? 'Creating...' : 'Create Baseline'}
                  </button>
                </div>
              )}

              {/* Baseline List */}
              {baselines.length === 0 ? (
                <div className="p-6 text-center text-gray-400 text-sm">
                  No baselines created yet.
                </div>
              ) : (
                <div className="divide-y max-h-[400px] overflow-y-auto">
                  {baselines.map((b) => (
                    <div key={b.id} className="p-3 hover:bg-gray-50">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <Badge variant="info">{b.zone}</Badge>
                          <span className="text-xs text-gray-400">{b.baseline_type}</span>
                        </div>
                        <span className="text-xs text-gray-400">{baselineAge(b.created_at)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">{b.asset_count} assets</span>
                        <span className="text-xs text-gray-400 font-mono">
                          {b.created_at ? new Date(b.created_at).toLocaleDateString() : '-'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="p-3 border-t">
                <button
                  onClick={loadData}
                  className="btn-secondary text-xs w-full flex items-center justify-center gap-2"
                >
                  <RefreshCw className="w-3 h-3" /> Refresh Baselines
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
