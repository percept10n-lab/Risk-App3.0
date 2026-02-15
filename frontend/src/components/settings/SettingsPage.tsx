import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import { Settings, Shield, Bot, Gauge, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { settingsApi } from '../../api/endpoints'

const TABS = ['policy', 'ai', 'thresholds'] as const
type Tab = typeof TABS[number]
const TAB_LABELS: Record<Tab, { label: string; icon: any }> = {
  policy: { label: 'Scan Policy', icon: Shield },
  ai: { label: 'AI Configuration', icon: Bot },
  thresholds: { label: 'Evaluation Thresholds', icon: Gauge },
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
    </div>
  )
}
