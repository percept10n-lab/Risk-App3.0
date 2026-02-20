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

function RedirectWithTab({ to, tab }: { to: string; tab: string }) {
  return <Navigate to={`${to}?tab=${tab}`} replace />
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        {/* Main routes */}
        <Route path="/" element={<CopilotHubPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/assets/:id" element={<AssetDetailPage />} />
        <Route path="/findings" element={<FindingsConsolidatedPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/threats" element={<ThreatsConsolidatedPage />} />
        <Route path="/operations" element={<OperationsPage />} />
        <Route path="/risks" element={<RisksPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/settings" element={<SettingsPage />} />

        {/* Backward-compatible redirects */}
        <Route path="/copilot" element={<Navigate to="/" replace />} />
        <Route path="/vulnmgmt" element={<RedirectWithTab to="/findings" tab="vuln-mgmt" />} />
        <Route path="/intel" element={<RedirectWithTab to="/threats" tab="intel" />} />
        <Route path="/mitre" element={<RedirectWithTab to="/threats" tab="mitre" />} />
        <Route path="/workflow" element={<RedirectWithTab to="/operations" tab="workflow" />} />
        <Route path="/pentest" element={<RedirectWithTab to="/operations" tab="pentest" />} />
        <Route path="/nmap" element={<RedirectWithTab to="/operations" tab="nmap" />} />
        <Route path="/drift" element={<RedirectWithTab to="/operations" tab="drift" />} />
      </Route>
    </Routes>
  )
}
