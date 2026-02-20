import { useSearchParams } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import ThreatsPage from './ThreatsPage'
import IntelPage from '../intel/IntelPage'
import MitrePage from '../mitre/MitrePage'
import { Crosshair, Newspaper, Target } from 'lucide-react'

const tabs = [
  { id: 'threats', label: 'Threats', icon: Crosshair },
  { id: 'intel', label: 'Threat Intel', icon: Newspaper },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: Target },
]

export default function ThreatsConsolidatedPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'threats'

  function setTab(tab: string) {
    setSearchParams(tab === 'threats' ? {} : { tab }, { replace: true })
  }

  return (
    <div>
      <PageHeader
        title="Threat Analysis"
        description="Threat modeling, intelligence, and MITRE ATT&CK mapping"
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

      {activeTab === 'threats' && <ThreatsPage embedded />}
      {activeTab === 'intel' && <IntelPage embedded />}
      {activeTab === 'mitre' && <MitrePage embedded />}
    </div>
  )
}
