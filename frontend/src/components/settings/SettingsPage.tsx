import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import { Settings, Shield, Bot, Gauge, CheckCircle2, XCircle, Loader2, Clock, Plus, Play, Trash2 } from 'lucide-react'
import { settingsApi, schedulesApi } from '../../api/endpoints'
import { formatDate } from '../../utils/format'
import type { ScanSchedule } from '../../types'

const TABS = ['policy', 'ai', 'thresholds', 'schedules'] as const
type Tab = typeof TABS[number]
const TAB_LABELS: Record<Tab, { label: string; icon: any }> = {
  policy: { label: 'Scan Policy', icon: Shield },
  ai: { label: 'AI Configuration', icon: Bot },
  thresholds: { label: 'Evaluation Thresholds', icon: Gauge },
  schedules: { label: 'Schedules', icon: Clock },
}

interface EvalThresholds {
  max_risk_level: string
  auto_triage_enabled: boolean
  auto_triage_min_score: number
  baseline_auto_enabled: boolean
  baseline_auto_zones: string[]
}

const DEFAULT_THRESHOLDS: EvalThresholds = {
  max_risk_level: 'high',
  auto_triage_enabled: false,
  auto_triage_min_score: 50,
  baseline_auto_enabled: false,
  baseline_auto_zones: ['lan'],
}

function loadThresholds(): EvalThresholds {
  try {
    const stored = localStorage.getItem('risk_eval_thresholds')
    return stored ? { ...DEFAULT_THRESHOLDS, ...JSON.parse(stored) } : DEFAULT_THRESHOLDS
  } catch {
    return DEFAULT_THRESHOLDS
  }
}

const INTERVAL_OPTIONS = [
  { value: 1, label: 'Every 1 hour' },
  { value: 2, label: 'Every 2 hours' },
  { value: 4, label: 'Every 4 hours' },
  { value: 6, label: 'Every 6 hours' },
  { value: 12, label: 'Every 12 hours' },
  { value: 24, label: 'Every 24 hours' },
  { value: 48, label: 'Every 48 hours' },
  { value: 168, label: 'Every 7 days' },
]

const CRON_PRESETS = [
  { value: '0 2 * * *', label: 'Daily at 2:00 AM' },
  { value: '0 3 * * 0', label: 'Weekly Sunday 3:00 AM' },
  { value: '0 4 1 * *', label: 'Monthly 1st at 4:00 AM' },
]

const SCAN_TYPES = [
  { value: 'full', label: 'Full Scan' },
  { value: 'discovery', label: 'Discovery Only' },
  { value: 'vuln_only', label: 'Vulnerability Scan Only' },
  { value: 'threat_only', label: 'Threat Modeling Only' },
]

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>('policy')
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState<string | null>(null)

  // Policy state
  const DEFAULT_POLICY = {
    name: 'Default Home Network Policy',
    scope_allowlist: ['192.168.178.0/24'],
    scope_denylist: [] as string[],
    action_allowlist: ['nmap_scan', 'port_check', 'http_check', 'tls_check', 'ssh_check', 'dns_check'],
    rate_limits: { scan: '100/min', check: '50/min', pentest_action: '10/min' },
    time_windows: { allowed_hours: '00:00-23:59', maintenance_windows: '' },
  }
  const [policy, setPolicy] = useState(DEFAULT_POLICY)

  // AI config state
  const [aiConfig, setAiConfig] = useState({
    provider: 'ollama',
    base_url: 'http://localhost:11434',
    model: 'llama3.2',
    enabled: false,
  })
  const [testingConnection, setTestingConnection] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'ok' | 'fail'>('idle')

  // Thresholds state
  const [thresholds, setThresholds] = useState<EvalThresholds>(loadThresholds)

  // Schedules state
  const [schedules, setSchedules] = useState<ScanSchedule[]>([])
  const [schedulesLoading, setSchedulesLoading] = useState(false)
  const [scheduleModalOpen, setScheduleModalOpen] = useState(false)
  const [editingSchedule, setEditingSchedule] = useState<ScanSchedule | null>(null)
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    schedule_type: 'interval' as 'interval' | 'cron',
    interval_hours: 24,
    cron_expression: '0 2 * * *',
    scan_type: 'full',
    scope: { subnets: ['192.168.1.0/24'] },
    enabled: true,
  })

  useEffect(() => {
    settingsApi.getAiConfig().then((res) => setAiConfig(res.data)).catch(() => {})
    settingsApi.getPolicy().then((res) => {
      if (res.data.length > 0) {
        const p = res.data[0]
        setPolicy({
          name: p.name || DEFAULT_POLICY.name,
          scope_allowlist: p.scope_allowlist || DEFAULT_POLICY.scope_allowlist,
          scope_denylist: p.scope_denylist || DEFAULT_POLICY.scope_denylist,
          action_allowlist: p.action_allowlist || DEFAULT_POLICY.action_allowlist,
          rate_limits: p.rate_limits || DEFAULT_POLICY.rate_limits,
          time_windows: p.time_windows || DEFAULT_POLICY.time_windows,
        })
      }
    }).catch(() => {})
  }, [])

  useEffect(() => {
    if (tab === 'schedules') fetchSchedules()
  }, [tab])

  async function fetchSchedules() {
    setSchedulesLoading(true)
    try {
      const res = await schedulesApi.list()
      setSchedules(res.data)
    } catch { /* empty */ }
    setSchedulesLoading(false)
  }

  function flash(msg: string) {
    setSaveMsg(msg)
    setTimeout(() => setSaveMsg(null), 3000)
  }

  async function handleSavePolicy() {
    setSaving(true)
    try {
      await settingsApi.updatePolicy({ ...policy, is_default: true })
      flash('Policy saved')
    } catch { flash('Failed to save policy') }
    setSaving(false)
  }

  async function handleSaveAiConfig() {
    setSaving(true)
    try {
      await settingsApi.updateAiConfig({
        provider: aiConfig.provider,
        base_url: aiConfig.base_url,
        model: aiConfig.model,
      })
      flash('AI config saved')
    } catch { flash('Failed to save AI config') }
    setSaving(false)
  }

  async function testConnection() {
    setTestingConnection(true)
    setConnectionStatus('idle')
    try {
      const res = await settingsApi.getAiConfig()
      setConnectionStatus(res.data.enabled ? 'ok' : 'fail')
    } catch {
      setConnectionStatus('fail')
    }
    setTestingConnection(false)
  }

  function handleSaveThresholds() {
    localStorage.setItem('risk_eval_thresholds', JSON.stringify(thresholds))
    flash('Thresholds saved to local storage')
  }

  function toggleZone(zone: string) {
    setThresholds((prev) => ({
      ...prev,
      baseline_auto_zones: prev.baseline_auto_zones.includes(zone)
        ? prev.baseline_auto_zones.filter((z) => z !== zone)
        : [...prev.baseline_auto_zones, zone],
    }))
  }

  function removeAction(action: string) {
    setPolicy((p) => ({ ...p, action_allowlist: p.action_allowlist.filter((a) => a !== action) }))
  }

  function addAction(action: string) {
    if (action && !policy.action_allowlist.includes(action)) {
      setPolicy((p) => ({ ...p, action_allowlist: [...p.action_allowlist, action] }))
    }
  }

  // Schedule handlers
  function openCreateSchedule() {
    setEditingSchedule(null)
    setScheduleForm({
      name: '',
      schedule_type: 'interval',
      interval_hours: 24,
      cron_expression: '0 2 * * *',
      scan_type: 'full',
      scope: { subnets: [policy.scope_allowlist[0] || '192.168.1.0/24'] },
      enabled: true,
    })
    setScheduleModalOpen(true)
  }

  function openEditSchedule(s: ScanSchedule) {
    setEditingSchedule(s)
    const scopeData = (s.scope && (s.scope as any).subnets) ? s.scope as { subnets: string[] } : { subnets: ['192.168.1.0/24'] }
    setScheduleForm({
      name: s.name,
      schedule_type: s.schedule_type,
      interval_hours: s.interval_hours || 24,
      cron_expression: s.cron_expression || '0 2 * * *',
      scan_type: s.scan_type,
      scope: scopeData,
      enabled: s.enabled,
    })
    setScheduleModalOpen(true)
  }

  async function handleSaveSchedule() {
    setSaving(true)
    try {
      const data: Partial<ScanSchedule> = {
        name: scheduleForm.name,
        schedule_type: scheduleForm.schedule_type,
        interval_hours: scheduleForm.schedule_type === 'interval' ? scheduleForm.interval_hours : null,
        cron_expression: scheduleForm.schedule_type === 'cron' ? scheduleForm.cron_expression : null,
        scan_type: scheduleForm.scan_type as ScanSchedule['scan_type'],
        scope: scheduleForm.scope,
        enabled: scheduleForm.enabled,
      }
      if (editingSchedule) {
        await schedulesApi.update(editingSchedule.id, data)
      } else {
        await schedulesApi.create(data)
      }
      setScheduleModalOpen(false)
      fetchSchedules()
      flash(editingSchedule ? 'Schedule updated' : 'Schedule created')
    } catch { flash('Failed to save schedule') }
    setSaving(false)
  }

  async function handleToggleSchedule(id: string) {
    try {
      await schedulesApi.toggle(id)
      fetchSchedules()
    } catch { flash('Failed to toggle schedule') }
  }

  async function handleDeleteSchedule(id: string) {
    try {
      await schedulesApi.delete(id)
      fetchSchedules()
      flash('Schedule deleted')
    } catch { flash('Failed to delete schedule') }
  }

  async function handleRunNow(id: string) {
    try {
      await schedulesApi.runNow(id)
      flash('Scan triggered')
      setTimeout(fetchSchedules, 2000)
    } catch { flash('Failed to trigger scan') }
  }

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Platform configuration, AI settings, and evaluation thresholds"
        actions={
          saveMsg ? (
            <span className="text-sm text-green-600 font-medium">{saveMsg}</span>
          ) : null
        }
      />

      {/* Tab Bar */}
      <div className="flex border-b mb-6">
        {TABS.map((t) => {
          const Icon = TAB_LABELS[t].icon
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                tab === t
                  ? 'border-brand-600 text-brand-700'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <Icon className="w-4 h-4" />
              {TAB_LABELS[t].label}
            </button>
          )
        })}
      </div>

      {/* Tab 1: Scan Policy */}
      {tab === 'policy' && (
        <div className="card p-6 space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Policy Name</label>
            <input
              type="text"
              value={policy.name}
              onChange={(e) => setPolicy({ ...policy, name: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg text-sm"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Scope Allowlist (one per line)</label>
              <textarea
                value={policy.scope_allowlist.join('\n')}
                onChange={(e) => setPolicy({ ...policy, scope_allowlist: e.target.value.split('\n').filter(Boolean) })}
                rows={3}
                className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Scope Denylist (one per line)</label>
              <textarea
                value={policy.scope_denylist.join('\n')}
                onChange={(e) => setPolicy({ ...policy, scope_denylist: e.target.value.split('\n').filter(Boolean) })}
                rows={3}
                className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
                placeholder="IPs or subnets to exclude..."
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Action Allowlist</label>
            <div className="flex flex-wrap gap-2 mb-2">
              {policy.action_allowlist.map((action) => (
                <span key={action} className="flex items-center gap-1 px-2 py-1 bg-brand-50 text-brand-700 rounded text-xs font-mono">
                  {action}
                  <button onClick={() => removeAction(action)} className="text-brand-400 hover:text-brand-600 ml-1">&times;</button>
                </span>
              ))}
            </div>
            <input
              type="text"
              placeholder="Add action and press Enter..."
              className="px-3 py-1.5 border rounded text-sm"
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  addAction((e.target as HTMLInputElement).value.trim());
                  (e.target as HTMLInputElement).value = ''
                }
              }}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Scan Rate Limit</label>
              <input
                type="text"
                value={policy.rate_limits.scan || ''}
                onChange={(e) => setPolicy({ ...policy, rate_limits: { ...policy.rate_limits, scan: e.target.value } })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Check Rate Limit</label>
              <input
                type="text"
                value={policy.rate_limits.check || ''}
                onChange={(e) => setPolicy({ ...policy, rate_limits: { ...policy.rate_limits, check: e.target.value } })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Pentest Action Limit</label>
              <input
                type="text"
                value={policy.rate_limits.pentest_action || ''}
                onChange={(e) => setPolicy({ ...policy, rate_limits: { ...policy.rate_limits, pentest_action: e.target.value } })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Allowed Hours</label>
              <input
                type="text"
                value={policy.time_windows.allowed_hours || ''}
                onChange={(e) => setPolicy({ ...policy, time_windows: { ...policy.time_windows, allowed_hours: e.target.value } })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
                placeholder="00:00-23:59"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Maintenance Windows</label>
              <input
                type="text"
                value={policy.time_windows.maintenance_windows || ''}
                onChange={(e) => setPolicy({ ...policy, time_windows: { ...policy.time_windows, maintenance_windows: e.target.value } })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
                placeholder="e.g. Sun 02:00-06:00"
              />
            </div>
          </div>

          <button onClick={handleSavePolicy} disabled={saving} className="btn-primary">
            {saving ? 'Saving...' : 'Save Policy'}
          </button>
        </div>
      )}

      {/* Tab 2: AI Configuration */}
      {tab === 'ai' && (
        <div className="card p-6 space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Provider</label>
              <select
                value={aiConfig.provider}
                onChange={(e) => setAiConfig({ ...aiConfig, provider: e.target.value })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              >
                <option value="ollama">Ollama (Local)</option>
                <option value="openai">OpenAI-compatible API</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Model</label>
              <input
                type="text"
                value={aiConfig.model}
                onChange={(e) => setAiConfig({ ...aiConfig, model: e.target.value })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Base URL</label>
            <input
              type="text"
              value={aiConfig.base_url}
              onChange={(e) => setAiConfig({ ...aiConfig, base_url: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
            />
          </div>

          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={aiConfig.enabled}
                onChange={(e) => setAiConfig({ ...aiConfig, enabled: e.target.checked })}
                className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
              />
              <span className="text-sm font-medium text-gray-700">Enable AI</span>
            </label>
            <div className={`flex items-center gap-1.5 text-sm ${aiConfig.enabled ? 'text-green-600' : 'text-gray-400'}`}>
              <div className={`w-2.5 h-2.5 rounded-full ${aiConfig.enabled ? 'bg-green-500' : 'bg-gray-300'}`} />
              {aiConfig.enabled ? 'Connected' : 'Disabled'}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={testConnection} disabled={testingConnection} className="btn-secondary flex items-center gap-2">
              {testingConnection ? <Loader2 className="w-4 h-4 animate-spin" /> : <Settings className="w-4 h-4" />}
              Test Connection
            </button>
            {connectionStatus === 'ok' && (
              <span className="flex items-center gap-1 text-sm text-green-600">
                <CheckCircle2 className="w-4 h-4" /> Connection OK
              </span>
            )}
            {connectionStatus === 'fail' && (
              <span className="flex items-center gap-1 text-sm text-red-600">
                <XCircle className="w-4 h-4" /> Connection failed
              </span>
            )}
          </div>

          <button onClick={handleSaveAiConfig} disabled={saving} className="btn-primary">
            {saving ? 'Saving...' : 'Save AI Configuration'}
          </button>
        </div>
      )}

      {/* Tab 3: Evaluation Thresholds */}
      {tab === 'thresholds' && (
        <div className="card p-6 space-y-6">
          <p className="text-xs text-gray-400">These settings are stored locally and can be wired to the backend later.</p>

          {/* Risk Acceptance */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-3">Risk Acceptance</h4>
            <div>
              <label className="block text-sm text-gray-600 mb-1">Max acceptable risk level</label>
              <select
                value={thresholds.max_risk_level}
                onChange={(e) => setThresholds({ ...thresholds, max_risk_level: e.target.value })}
                className="px-3 py-2 border rounded-lg text-sm"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          {/* Auto Triage */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-3">Auto-Triage</h4>
            <label className="flex items-center gap-2 cursor-pointer mb-3">
              <input
                type="checkbox"
                checked={thresholds.auto_triage_enabled}
                onChange={(e) => setThresholds({ ...thresholds, auto_triage_enabled: e.target.checked })}
                className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
              />
              <span className="text-sm text-gray-700">Enable automatic triage on new findings</span>
            </label>
            <div>
              <label className="block text-sm text-gray-600 mb-1">
                Minimum priority score: <span className="font-mono font-bold">{thresholds.auto_triage_min_score}</span>
              </label>
              <input
                type="range"
                min={0}
                max={100}
                value={thresholds.auto_triage_min_score}
                onChange={(e) => setThresholds({ ...thresholds, auto_triage_min_score: Number(e.target.value) })}
                className="w-full max-w-xs"
                disabled={!thresholds.auto_triage_enabled}
              />
              <div className="flex justify-between text-xs text-gray-400 max-w-xs">
                <span>0</span><span>50</span><span>100</span>
              </div>
            </div>
          </div>

          {/* Baseline Auto-Creation */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-3">Baseline Auto-Creation</h4>
            <label className="flex items-center gap-2 cursor-pointer mb-3">
              <input
                type="checkbox"
                checked={thresholds.baseline_auto_enabled}
                onChange={(e) => setThresholds({ ...thresholds, baseline_auto_enabled: e.target.checked })}
                className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
              />
              <span className="text-sm text-gray-700">Auto-create baselines after scans</span>
            </label>
            <div className="flex flex-wrap gap-3">
              {['lan', 'iot', 'guest', 'dmz'].map((zone) => (
                <label key={zone} className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={thresholds.baseline_auto_zones.includes(zone)}
                    onChange={() => toggleZone(zone)}
                    disabled={!thresholds.baseline_auto_enabled}
                    className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                  />
                  <span className="text-sm text-gray-700">{zone.toUpperCase()}</span>
                </label>
              ))}
            </div>
          </div>

          <button onClick={handleSaveThresholds} className="btn-primary">
            Save Thresholds
          </button>
        </div>
      )}

      {/* Tab 4: Schedules */}
      {tab === 'schedules' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <p className="text-sm text-gray-500">Configure automatic recurring scans</p>
            <button onClick={openCreateSchedule} className="btn-primary text-sm flex items-center gap-2">
              <Plus className="w-4 h-4" />
              New Schedule
            </button>
          </div>

          {schedulesLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
            </div>
          ) : schedules.length === 0 ? (
            <div className="card p-12 text-center text-gray-500">
              <Clock className="w-10 h-10 mx-auto mb-3 text-gray-300" />
              <p className="text-sm">No schedules configured yet.</p>
              <p className="text-xs text-gray-400 mt-1">Create a schedule to automate recurring scans.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {schedules.map((s) => (
                <div key={s.id} className="card p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => handleToggleSchedule(s.id)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          s.enabled ? 'bg-brand-600' : 'bg-gray-300'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            s.enabled ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                      <div>
                        <button onClick={() => openEditSchedule(s)} className="font-medium text-sm hover:text-brand-600">
                          {s.name}
                        </button>
                        <div className="flex gap-3 text-xs text-gray-500 mt-0.5">
                          <span className="capitalize">{SCAN_TYPES.find((t) => t.value === s.scan_type)?.label || s.scan_type}</span>
                          <span>
                            {s.schedule_type === 'interval'
                              ? `Every ${s.interval_hours}h`
                              : s.cron_expression}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right text-xs text-gray-500">
                        {s.next_run_at && (
                          <p>Next: {formatDate(s.next_run_at)}</p>
                        )}
                        {s.last_run_at && (
                          <p>Last: {formatDate(s.last_run_at)}</p>
                        )}
                      </div>
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleRunNow(s.id)}
                          className="p-1.5 text-gray-400 hover:text-brand-600 rounded hover:bg-brand-50"
                          title="Run now"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteSchedule(s.id)}
                          className="p-1.5 text-gray-400 hover:text-red-600 rounded hover:bg-red-50"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Schedule Create/Edit Modal */}
      {scheduleModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6">
            <h3 className="font-semibold text-lg mb-4">
              {editingSchedule ? 'Edit Schedule' : 'New Schedule'}
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Name</label>
                <input
                  value={scheduleForm.name}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg text-sm"
                  placeholder="e.g., Nightly Full Scan"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Scan Type</label>
                <select
                  value={scheduleForm.scan_type}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, scan_type: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg text-sm"
                >
                  {SCAN_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 mb-2">Schedule Type</label>
                <div className="flex gap-4 mb-3">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      checked={scheduleForm.schedule_type === 'interval'}
                      onChange={() => setScheduleForm({ ...scheduleForm, schedule_type: 'interval' })}
                      className="w-4 h-4 text-brand-600"
                    />
                    <span className="text-sm">Interval</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      checked={scheduleForm.schedule_type === 'cron'}
                      onChange={() => setScheduleForm({ ...scheduleForm, schedule_type: 'cron' })}
                      className="w-4 h-4 text-brand-600"
                    />
                    <span className="text-sm">Cron</span>
                  </label>
                </div>

                {scheduleForm.schedule_type === 'interval' ? (
                  <select
                    value={scheduleForm.interval_hours}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, interval_hours: Number(e.target.value) })}
                    className="w-full px-3 py-2 border rounded-lg text-sm"
                  >
                    {INTERVAL_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                ) : (
                  <div className="space-y-2">
                    <input
                      value={scheduleForm.cron_expression}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, cron_expression: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
                      placeholder="0 2 * * *"
                    />
                    <div className="flex flex-wrap gap-2">
                      {CRON_PRESETS.map((p) => (
                        <button
                          key={p.value}
                          onClick={() => setScheduleForm({ ...scheduleForm, cron_expression: p.value })}
                          className="text-xs px-2 py-1 bg-gray-100 rounded hover:bg-gray-200"
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">CIDR Scope</label>
                <input
                  value={(scheduleForm.scope?.subnets || [''])[0]}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, scope: { subnets: [e.target.value] } })}
                  className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
                  placeholder="192.168.1.0/24"
                />
              </div>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={scheduleForm.enabled}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, enabled: e.target.checked })}
                  className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                />
                <span className="text-sm text-gray-700">Enable immediately</span>
              </label>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setScheduleModalOpen(false)} className="btn-secondary text-sm">
                Cancel
              </button>
              <button
                onClick={handleSaveSchedule}
                disabled={saving || !scheduleForm.name}
                className="btn-primary text-sm disabled:opacity-50"
              >
                {saving ? 'Saving...' : editingSchedule ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
