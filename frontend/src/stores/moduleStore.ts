import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const MODULE_IDS = ['findings', 'threats', 'operations', 'risks', 'reports'] as const
export type ModuleId = typeof MODULE_IDS[number]

export const MODULE_META: Record<ModuleId, { label: string; description: string }> = {
  findings: { label: 'Findings & Vulns', description: 'Vulnerability management, CVE tracking, and finding triage' },
  threats: { label: 'Threat Analysis', description: 'Threat intelligence, MITRE ATT&CK mapping, and threat modeling' },
  operations: { label: 'Operations', description: 'Scan workflows, nmap operations, pentesting, and drift detection' },
  risks: { label: 'Risks', description: 'Risk register, scoring, and risk acceptance tracking' },
  reports: { label: 'Reports', description: 'PDF/HTML report generation and export' },
}

interface ModuleState {
  enabledModules: Record<ModuleId, boolean>
  toggleModule: (id: ModuleId) => void
  enableAll: () => void
  disableAll: () => void
}

const allFalse = Object.fromEntries(MODULE_IDS.map((id) => [id, false])) as Record<ModuleId, boolean>
const allTrue = Object.fromEntries(MODULE_IDS.map((id) => [id, true])) as Record<ModuleId, boolean>

export const useModuleStore = create<ModuleState>()(
  persist(
    (set) => ({
      enabledModules: { ...allFalse },
      toggleModule: (id) =>
        set((state) => ({
          enabledModules: { ...state.enabledModules, [id]: !state.enabledModules[id] },
        })),
      enableAll: () => set({ enabledModules: { ...allTrue } }),
      disableAll: () => set({ enabledModules: { ...allFalse } }),
    }),
    { name: 'risk_modules' },
  ),
)
