import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/common/Layout'
import DashboardPage from './components/dashboard/DashboardPage'
import AssetsPage from './components/assets/AssetsPage'
import AssetDetailPage from './components/assets/AssetDetailPage'
import FindingsPage from './components/findings/FindingsPage'
import FindingDetailPage from './components/findings/FindingDetailPage'
import ThreatsPage from './components/threats/ThreatsPage'
import RisksPage from './components/risks/RisksPage'
import MitrePage from './components/mitre/MitrePage'
import WorkflowPage from './components/workflow/WorkflowPage'
import PentestPage from './components/pentest/PentestPage'
import NmapPage from './components/nmap/NmapPage'
import VulnMgmtPage from './components/vulnmgmt/VulnMgmtPage'
import ReportsPage from './components/reports/ReportsPage'
import CopilotPage from './components/copilot/CopilotPage'
import DriftPage from './components/drift/DriftPage'
import SettingsPage from './components/settings/SettingsPage'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/assets/:id" element={<AssetDetailPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/threats" element={<ThreatsPage />} />
        <Route path="/risks" element={<RisksPage />} />
        <Route path="/mitre" element={<MitrePage />} />
        <Route path="/workflow" element={<WorkflowPage />} />
        <Route path="/pentest" element={<PentestPage />} />
        <Route path="/nmap" element={<NmapPage />} />
        <Route path="/vulnmgmt" element={<VulnMgmtPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/copilot" element={<CopilotPage />} />
        <Route path="/drift" element={<DriftPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  )
}
