import { useNavigate } from 'react-router-dom'
import {
  FileSearch, Shield, Crosshair, AlertTriangle, Map, Server,
  ArrowRight, CheckCircle2, TrendingUp,
} from 'lucide-react'

interface PipelineResults {
  findings_created?: number
  total_findings?: number
  assets_imported?: number
  assets_updated?: number
  steps?: {
    vuln_assessment?: { new_findings?: number; total_findings?: number; skipped?: boolean }
    threat_modeling?: { threats_created?: number; total_threats?: number; skipped?: boolean }
    mitre_mapping?: { mappings_created?: number; skipped?: boolean }
    risk_analysis?: { risks_created?: number; risks_updated?: number; skipped?: boolean }
    [key: string]: any
  }
}

interface NmapResultsSummaryProps {
  results: PipelineResults
}

export default function NmapResultsSummary({ results }: NmapResultsSummaryProps) {
  const navigate = useNavigate()
  const steps = results.steps || {}

  const stats = [
    {
      label: 'Assets Imported',
      value: (results.assets_imported || 0) + (results.assets_updated || 0),
      sub: results.assets_imported ? `${results.assets_imported} new, ${results.assets_updated || 0} updated` : undefined,
      icon: Server,
      color: 'text-blue-600 bg-blue-50',
    },
    {
      label: 'Findings Created',
      value: results.total_findings || 0,
      sub: results.findings_created ? `${results.findings_created} new` : undefined,
      icon: FileSearch,
      color: 'text-amber-600 bg-amber-50',
    },
    {
      label: 'Threats Generated',
      value: steps.threat_modeling?.threats_created || 0,
      sub: steps.threat_modeling?.skipped ? 'Skipped' : undefined,
      icon: Crosshair,
      color: 'text-red-600 bg-red-50',
    },
    {
      label: 'Risks Identified',
      value: (steps.risk_analysis?.risks_created || 0) + (steps.risk_analysis?.risks_updated || 0),
      sub: steps.risk_analysis?.skipped ? 'Skipped' : undefined,
      icon: AlertTriangle,
      color: 'text-purple-600 bg-purple-50',
    },
  ]

  const navLinks = [
    { path: '/assets', label: 'View Assets', icon: Server, color: 'bg-blue-500 hover:bg-blue-600', desc: 'Imported and updated assets' },
    { path: '/findings', label: 'View Findings', icon: FileSearch, color: 'bg-amber-500 hover:bg-amber-600', desc: 'Scan findings and vulnerabilities' },
    { path: '/threats', label: 'View Threats', icon: Crosshair, color: 'bg-red-500 hover:bg-red-600', desc: 'Generated threat scenarios' },
    { path: '/risks', label: 'View Risks & Treatment', icon: AlertTriangle, color: 'bg-purple-500 hover:bg-purple-600', desc: 'Risk analysis and treatment plans' },
    { path: '/threats?tab=mitre', label: 'MITRE ATT&CK Map', icon: Map, color: 'bg-emerald-500 hover:bg-emerald-600', desc: 'ATT&CK technique mappings' },
  ]

  return (
    <div className="space-y-6">
      {/* Completion Banner */}
      <div className="flex items-center gap-3 p-4 bg-green-50 border border-green-200 rounded-lg">
        <CheckCircle2 className="w-6 h-6 text-green-600 shrink-0" />
        <div>
          <p className="text-sm font-semibold text-green-800">Pipeline Complete</p>
          <p className="text-xs text-green-600">All stages finished. Review results below.</p>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map(stat => (
          <div key={stat.label} className="card p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${stat.color}`}>
                <stat.icon className="w-4 h-4" />
              </div>
            </div>
            <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
            <p className="text-xs text-gray-500">{stat.label}</p>
            {stat.sub && <p className="text-xs text-gray-400 mt-0.5">{stat.sub}</p>}
          </div>
        ))}
      </div>

      {/* Navigation Grid */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <TrendingUp className="w-4 h-4 text-gray-500" />
          <h3 className="text-sm font-semibold text-gray-700">Explore Results</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {navLinks.map(link => (
            <button
              key={link.path}
              onClick={() => navigate(link.path)}
              className={`${link.color} text-white rounded-lg p-4 text-left transition-all hover:shadow-lg group`}
            >
              <div className="flex items-center justify-between mb-2">
                <link.icon className="w-5 h-5" />
                <ArrowRight className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <p className="text-sm font-semibold">{link.label}</p>
              <p className="text-xs opacity-80">{link.desc}</p>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
