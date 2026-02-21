import { useModuleStore, MODULE_IDS, MODULE_META } from '../../stores/moduleStore'
import { Bug, Crosshair, PlayCircle, Shield, FileText } from 'lucide-react'
import type { ModuleId } from '../../stores/moduleStore'

const MODULE_ICONS: Record<ModuleId, any> = {
  findings: Bug,
  threats: Crosshair,
  operations: PlayCircle,
  risks: Shield,
  reports: FileText,
}

export default function ModulesTab() {
  const { enabledModules, toggleModule, enableAll, disableAll } = useModuleStore()
  const enabledCount = MODULE_IDS.filter((id) => enabledModules[id]).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">
          <span className="font-medium text-gray-700">{enabledCount}</span> of {MODULE_IDS.length} modules enabled
        </p>
        <div className="flex gap-2">
          <button onClick={enableAll} className="btn-secondary text-sm">
            Enable All
          </button>
          <button onClick={disableAll} className="btn-secondary text-sm">
            Disable All
          </button>
        </div>
      </div>

      <div className="grid gap-3">
        {MODULE_IDS.map((id) => {
          const Icon = MODULE_ICONS[id]
          const meta = MODULE_META[id]
          const enabled = enabledModules[id]

          return (
            <div
              key={id}
              className={`card p-4 flex items-center justify-between transition-colors ${
                enabled ? 'border-brand-200 bg-brand-50/30' : ''
              }`}
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${enabled ? 'bg-brand-100 text-brand-600' : 'bg-gray-100 text-gray-400'}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">{meta.label}</p>
                  <p className="text-xs text-gray-500">{meta.description}</p>
                </div>
              </div>

              <button
                onClick={() => toggleModule(id)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  enabled ? 'bg-brand-600' : 'bg-gray-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    enabled ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          )
        })}
      </div>

      <p className="text-xs text-gray-400">
        Core sections (AI Copilot, Dashboard, Assets, Settings) are always visible.
        Enable modules above to unlock additional capabilities in the sidebar.
      </p>
    </div>
  )
}
