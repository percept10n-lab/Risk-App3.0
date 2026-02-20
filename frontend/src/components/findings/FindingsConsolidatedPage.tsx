import { useSearchParams } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import FindingsPage from './FindingsPage'
import VulnMgmtPage from '../vulnmgmt/VulnMgmtPage'
import { AlertTriangle, Bug } from 'lucide-react'

const tabs = [
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'vuln-mgmt', label: 'Vuln Management', icon: Bug },
]

export default function FindingsConsolidatedPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'findings'

  function setTab(tab: string) {
    setSearchParams(tab === 'findings' ? {} : { tab }, { replace: true })
  }

  return (
    <div>
      <PageHeader
        title="Findings & Vulnerabilities"
        description="Vulnerability findings and lifecycle management"
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

      {activeTab === 'findings' && <FindingsPage embedded />}
      {activeTab === 'vuln-mgmt' && <VulnMgmtPage embedded />}
    </div>
  )
}
