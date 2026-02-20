import { useSearchParams } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import WorkflowPage from '../workflow/WorkflowPage'
import PentestPage from '../pentest/PentestPage'
import NmapPage from '../nmap/NmapPage'
import DriftPage from '../drift/DriftPage'
import { PlayCircle, Swords, Radar, GitCompare } from 'lucide-react'

const tabs = [
  { id: 'workflow', label: 'Workflow', icon: PlayCircle },
  { id: 'pentest', label: 'Pentest', icon: Swords },
  { id: 'nmap', label: 'Nmap Scanner', icon: Radar },
  { id: 'drift', label: 'Drift Monitor', icon: GitCompare },
]

export default function OperationsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'workflow'

  function setTab(tab: string) {
    setSearchParams(tab === 'workflow' ? {} : { tab }, { replace: true })
  }

  return (
    <div>
      <PageHeader
        title="Operations"
        description="Workflow execution, penetration testing, scanning, and drift monitoring"
      />

      <div className="flex gap-1 mb-6 border-b border-gray-200">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-brand-600 text-brand-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'workflow' && <WorkflowPage embedded />}
      {activeTab === 'pentest' && <PentestPage embedded />}
      {activeTab === 'nmap' && <NmapPage embedded />}
      {activeTab === 'drift' && <DriftPage embedded />}
    </div>
  )
}
