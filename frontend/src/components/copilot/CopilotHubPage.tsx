import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import AgentChat from './AgentChat'
import CopilotPage from './CopilotPage'
import {
  Bot,
  LayoutDashboard,
  Monitor,
  Bug,
  Crosshair,
  PlayCircle,
  Shield,
  FileText,
  MessageSquare,
  Wrench,
  Loader2,
} from 'lucide-react'
import api from '../../api/client'

interface QuickStats {
  total_assets: number
  total_findings: number
  total_risks: number
  total_threats: number
  findings_by_severity: Record<string, number>
}

const quickNavItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', countKey: null },
  { to: '/assets', icon: Monitor, label: 'Assets', countKey: 'total_assets' as const },
  { to: '/findings', icon: Bug, label: 'Findings', countKey: 'total_findings' as const },
  { to: '/threats', icon: Crosshair, label: 'Threats', countKey: 'total_threats' as const },
  { to: '/operations', icon: PlayCircle, label: 'Operations', countKey: null },
  { to: '/risks', icon: Shield, label: 'Risks', countKey: 'total_risks' as const },
  { to: '/reports', icon: FileText, label: 'Reports', countKey: null },
]

export default function CopilotHubPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<QuickStats | null>(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'agent' | 'workflow'>('agent')

  useEffect(() => {
    async function loadStats() {
      try {
        const [assetsRes, findingsRes, risksRes, threatsRes] = await Promise.allSettled([
          api.get('/assets', { params: { page_size: 1 } }),
          api.get('/findings/stats'),
          api.get('/risks/stats'),
          api.get('/threats/stats'),
        ])
        setStats({
          total_assets: assetsRes.status === 'fulfilled' ? assetsRes.value.data.total : 0,
          total_findings: findingsRes.status === 'fulfilled' ? findingsRes.value.data.total : 0,
          total_risks: risksRes.status === 'fulfilled' ? risksRes.value.data.total : 0,
          total_threats: threatsRes.status === 'fulfilled' ? threatsRes.value.data.total : 0,
          findings_by_severity: findingsRes.status === 'fulfilled' ? findingsRes.value.data.by_severity || {} : {},
        })
      } catch {
        setStats({ total_assets: 0, total_findings: 0, total_risks: 0, total_threats: 0, findings_by_severity: {} })
      } finally {
        setStatsLoading(false)
      }
    }
    loadStats()
  }, [])

  const securityScore = stats ? computeSecurityScore(stats) : null

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand-600 flex items-center justify-center">
            <Bot className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">AI Defense Copilot</h1>
            <p className="text-sm text-gray-500">Security analysis hub — chat, navigate, and take action</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Left Panel: Quick Nav + Security Posture */}
        <div className="xl:col-span-3 space-y-6">
          {/* Quick Navigation */}
          <div className="card p-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Quick Navigation</h3>
            <div className="space-y-1">
              {quickNavItems.map((item) => {
                const count = item.countKey && stats ? (stats as any)[item.countKey] : null
                return (
                  <button
                    key={item.to}
                    onClick={() => navigate(item.to)}
                    className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-left text-sm hover:bg-gray-50 transition-colors group"
                  >
                    <item.icon className="w-4 h-4 text-gray-400 group-hover:text-brand-600" />
                    <span className="flex-1 text-gray-700 group-hover:text-gray-900">{item.label}</span>
                    {count != null && (
                      <span className="text-xs font-medium text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">
                        {count}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Security Posture */}
          <div className="card p-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Security Posture</h3>
            {statsLoading ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
              </div>
            ) : (
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <span className="text-3xl font-bold text-gray-900">{securityScore}</span>
                  <span className="text-sm text-gray-400">/100</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2.5 mb-4">
                  <div
                    className={`h-2.5 rounded-full transition-all ${
                      (securityScore ?? 0) >= 70 ? 'bg-green-500' :
                      (securityScore ?? 0) >= 40 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${securityScore ?? 0}%` }}
                  />
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Critical/High Findings</span>
                    <span className="font-medium text-gray-700">
                      {(stats?.findings_by_severity?.critical ?? 0) + (stats?.findings_by_severity?.high ?? 0)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Total Threats</span>
                    <span className="font-medium text-gray-700">{stats?.total_threats ?? 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Open Risks</span>
                    <span className="font-medium text-gray-700">{stats?.total_risks ?? 0}</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Smart Actions */}
          <div className="card p-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Smart Actions</h3>
            <div className="space-y-2">
              <button
                onClick={() => setActiveTab('workflow')}
                className="w-full text-left px-3 py-2.5 rounded-lg text-sm bg-brand-50 text-brand-700 hover:bg-brand-100 transition-colors"
              >
                Triage Findings
              </button>
              <button
                onClick={() => navigate('/operations?tab=workflow')}
                className="w-full text-left px-3 py-2.5 rounded-lg text-sm bg-gray-50 text-gray-700 hover:bg-gray-100 transition-colors"
              >
                Start Workflow
              </button>
              <button
                onClick={() => navigate('/reports')}
                className="w-full text-left px-3 py-2.5 rounded-lg text-sm bg-gray-50 text-gray-700 hover:bg-gray-100 transition-colors"
              >
                Generate Report
              </button>
            </div>
          </div>
        </div>

        {/* Right Panel: Agent Chat + Workflow */}
        <div className="xl:col-span-9">
          <CopilotPage embedded />
        </div>
      </div>
    </div>
  )
}

function computeSecurityScore(stats: QuickStats): number {
  const critHigh = (stats.findings_by_severity?.critical ?? 0) + (stats.findings_by_severity?.high ?? 0)
  const medium = stats.findings_by_severity?.medium ?? 0
  const threats = stats.total_threats
  const risks = stats.total_risks

  let score = 100
  score -= critHigh * 8
  score -= medium * 3
  score -= threats * 2
  score -= risks * 4
  return Math.max(0, Math.min(100, score))
}
