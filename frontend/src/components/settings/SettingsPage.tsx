import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import api from '../../api/client'

export default function SettingsPage() {
  const [policy, setPolicy] = useState({
    name: 'Default Home Network Policy',
    scope_allowlist: ['192.168.0.0/16', '10.0.0.0/8'],
    scope_denylist: [] as string[],
    rate_limits: { scan: '100/min', check: '50/min' },
    time_windows: { allowed_hours: '00:00-23:59' },
  })
  const [aiConfig, setAiConfig] = useState({
    provider: 'ollama',
    base_url: 'http://localhost:11434',
    model: 'llama3.2',
    enabled: false,
  })

  useEffect(() => {
    api.get('/settings/ai-config').then((res) => setAiConfig(res.data)).catch(() => {})
    api.get('/settings/policy').then((res) => {
      if (res.data.length > 0) {
        setPolicy(res.data[0])
      }
    }).catch(() => {})
  }, [])

  const handleSavePolicy = async () => {
    await api.put('/settings/policy', { ...policy, is_default: true })
  }

  return (
    <div>
      <PageHeader title="Settings" description="Platform configuration and policies" />

      <div className="space-y-6">
        <div className="card p-6">
          <h3 className="text-lg font-semibold mb-4">Scan Policy</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Policy Name</label>
              <input
                type="text"
                value={policy.name}
                onChange={(e) => setPolicy({ ...policy, name: e.target.value })}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              />
            </div>
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
                rows={2}
                className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
                placeholder="IPs or subnets to exclude..."
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
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
                <label className="block text-sm font-medium text-gray-700 mb-1">Allowed Hours</label>
                <input
                  type="text"
                  value={policy.time_windows.allowed_hours || ''}
                  onChange={(e) => setPolicy({ ...policy, time_windows: { ...policy.time_windows, allowed_hours: e.target.value } })}
                  className="w-full px-3 py-2 border rounded-lg text-sm"
                />
              </div>
            </div>
            <button onClick={handleSavePolicy} className="btn-primary">Save Policy</button>
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-semibold mb-4">AI Configuration</h3>
          <div className="space-y-4">
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
              <label className="block text-sm font-medium text-gray-700 mb-1">Base URL</label>
              <input
                type="text"
                value={aiConfig.base_url}
                onChange={(e) => setAiConfig({ ...aiConfig, base_url: e.target.value })}
                className="w-full px-3 py-2 border rounded-lg text-sm font-mono"
              />
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
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${aiConfig.enabled ? 'bg-green-500' : 'bg-gray-300'}`} />
              <span className="text-sm">{aiConfig.enabled ? 'AI Connected' : 'AI Not Connected'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
