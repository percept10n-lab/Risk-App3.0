import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/common/Layout'
import DashboardPage from './components/dashboard/DashboardPage'
import AssetsPage from './components/assets/AssetsPage'
import AssetDetailPage from './components/assets/AssetDetailPage'
import FindingsConsolidatedPage from './components/findings/FindingsConsolidatedPage'
import FindingDetailPage from './components/findings/FindingDetailPage'
import ThreatsConsolidatedPage from './components/threats/ThreatsConsolidatedPage'
import OperationsPage from './components/operations/OperationsPage'
import RisksPage from './components/risks/RisksPage'
import ReportsPage from './components/reports/ReportsPage'
import CopilotHubPage from './components/copilot/CopilotHubPage'
import SettingsPage from './components/settings/SettingsPage'
import { useModuleStore } from './stores/moduleStore'
import type { ModuleId } from './stores/moduleStore'

function RedirectWithTab({ to, tab }: { to: string; tab: string }) {
  return <Navigate to={`${to}?tab=${tab}`} replace />
}

function ModuleGuard({ moduleId, children }: { moduleId: ModuleId; children: React.ReactNode }) {
  const enabled = useModuleStore((s) => s.enabledModules[moduleId])
  if (!enabled) return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        {/* Core routes — always accessible */}
        <Route path="/" element={<CopilotHubPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/assets/:id" element={<AssetDetailPage />} />
        <Route path="/settings" element={<SettingsPage />} />

        {/* Module-gated routes */}
        <Route path="/findings" element={<ModuleGuard moduleId="findings"><FindingsConsolidatedPage /></ModuleGuard>} />
        <Route path="/findings/:id" element={<ModuleGuard moduleId="findings"><FindingDetailPage /></ModuleGuard>} />
        <Route path="/threats" element={<ModuleGuard moduleId="threats"><ThreatsConsolidatedPage /></ModuleGuard>} />
        <Route path="/operations" element={<ModuleGuard moduleId="operations"><OperationsPage /></ModuleGuard>} />
        <Route path="/risks" element={<ModuleGuard moduleId="risks"><RisksPage /></ModuleGuard>} />
        <Route path="/reports" element={<ModuleGuard moduleId="reports"><ReportsPage /></ModuleGuard>} />

        {/* Backward-compatible redirects (also gated) */}
        <Route path="/copilot" element={<Navigate to="/" replace />} />
        <Route path="/vulnmgmt" element={<ModuleGuard moduleId="findings"><RedirectWithTab to="/findings" tab="vuln-mgmt" /></ModuleGuard>} />
        <Route path="/intel" element={<ModuleGuard moduleId="threats"><RedirectWithTab to="/threats" tab="intel" /></ModuleGuard>} />
        <Route path="/mitre" element={<ModuleGuard moduleId="threats"><RedirectWithTab to="/threats" tab="mitre" /></ModuleGuard>} />
        <Route path="/workflow" element={<ModuleGuard moduleId="operations"><RedirectWithTab to="/operations" tab="workflow" /></ModuleGuard>} />
        <Route path="/pentest" element={<ModuleGuard moduleId="operations"><RedirectWithTab to="/operations" tab="pentest" /></ModuleGuard>} />
        <Route path="/nmap" element={<ModuleGuard moduleId="operations"><RedirectWithTab to="/operations" tab="nmap" /></ModuleGuard>} />
        <Route path="/drift" element={<ModuleGuard moduleId="operations"><RedirectWithTab to="/operations" tab="drift" /></ModuleGuard>} />
      </Route>
    </Routes>
  )
}
