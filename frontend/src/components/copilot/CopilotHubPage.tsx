import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
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
  Loader2,
} from 'lucide-react'
import api from '../../api/client'

interface QuickStats {
  total_assets: number
  total_findings: number
  total_risks: number
  total_threats: number
  findings_by_severity: Record<string, number>
  findings_by_status: Record<string, number>
  risks_by_level: Record<string, number>
  risks_by_status: Record<string, number>
}

interface ScoreBreakdown {
  total: number
  remediation: number
  severityProfile: number
  riskTreatment: number
  exposure: number
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
        const fd = findingsRes.status === 'fulfilled' ? findingsRes.value.data : {}
        const rd = risksRes.status === 'fulfilled' ? risksRes.value.data : {}
        setStats({
          total_assets: assetsRes.status === 'fulfilled' ? assetsRes.value.data.total : 0,
          total_findings: fd.total ?? 0,
          total_risks: rd.total ?? 0,
          total_threats: threatsRes.status === 'fulfilled' ? threatsRes.value.data.total : 0,
          findings_by_severity: fd.by_severity || {},
          findings_by_status: fd.by_status || {},
          risks_by_level: rd.by_level || {},
          risks_by_status: rd.by_status || {},
        })
      } catch {
        setStats({ total_assets: 0, total_findings: 0, total_risks: 0, total_threats: 0, findings_by_severity: {}, findings_by_status: {}, risks_by_level: {}, risks_by_status: {} })
      } finally {
        setStatsLoading(false)
      }
    }
    loadStats()
  }, [])

  const scoreBreakdown = stats ? computeSecurityScore(stats) : null
  const securityScore = scoreBreakdown?.total ?? null

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
                {scoreBreakdown && (
                  <div className="space-y-2 text-xs">
                    <ScoreRow label="Remediation" score={scoreBreakdown.remediation} max={40} />
                    <ScoreRow label="Severity Profile" score={scoreBreakdown.severityProfile} max={25} />
                    <ScoreRow label="Risk Treatment" score={scoreBreakdown.riskTreatment} max={25} />
                    <ScoreRow label="Exposure" score={scoreBreakdown.exposure} max={10} />
                  </div>
                )}
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

function ScoreRow({ label, score, max }: { label: string; score: number; max: number }) {
  const pct = max > 0 ? (score / max) * 100 : 0
  return (
    <div className="flex items-center gap-2">
      <span className="text-gray-500 w-28 truncate">{label}</span>
      <div className="flex-1 bg-gray-100 rounded-full h-1.5">
        <div
          className={`h-1.5 rounded-full ${pct >= 70 ? 'bg-green-500' : pct >= 40 ? 'bg-yellow-500' : 'bg-red-400'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="font-medium text-gray-600 w-10 text-right">{score}/{max}</span>
    </div>
  )
}

/**
 * Multi-dimensional security posture score (0-100).
 *
 * Dimensions:
 *  1. Remediation Rate (0-40): % of findings resolved, weighted by severity
 *  2. Severity Profile   (0-25): How benign the open finding mix is
 *  3. Risk Treatment     (0-25): % of risks treated/monitoring, weighted by level
 *  4. Exposure Density   (0-10): Findings-per-asset ratio (fewer = better)
 *
 * A network with no findings/risks scores 100 (nothing found = clean).
 */
function computeSecurityScore(stats: QuickStats): ScoreBreakdown {
  // ── 1. Remediation Rate (40 pts) ──────────────────────────────
  // What fraction of findings have been resolved?
  // Weighted: resolving a critical finding counts more than resolving a low one.
  const sev = stats.findings_by_severity ?? {}
  const st = stats.findings_by_status ?? {}
  const totalFindings = stats.total_findings

  let remediation = 40 // perfect if nothing to remediate
  if (totalFindings > 0) {
    const resolved = (st.fixed ?? 0) + (st.verified ?? 0) + (st.accepted ?? 0) + (st.exception ?? 0)
    const resolvedRate = resolved / totalFindings

    // Weight by severity: unresolved critical/high findings are worse
    const openCrit = Math.max(0, (sev.critical ?? 0) - (resolved > 0 ? resolved * ((sev.critical ?? 0) / totalFindings) : 0))
    const openHigh = Math.max(0, (sev.high ?? 0) - (resolved > 0 ? resolved * ((sev.high ?? 0) / totalFindings) : 0))
    const sevPenalty = totalFindings > 0
      ? ((openCrit + openHigh) / totalFindings) * 0.3 // up to 30% extra penalty
      : 0

    remediation = Math.round(40 * Math.max(0, resolvedRate - sevPenalty))
  }

  // ── 2. Severity Profile (25 pts) ──────────────────────────────
  // Of open (unresolved) findings, what's the severity mix?
  // All low/info = 25, all critical = 0
  let severityProfile = 25
  const openFindings = (st.open ?? 0) + (st.in_progress ?? 0)
  if (openFindings > 0) {
    const weights: Record<string, number> = { critical: 1.0, high: 0.7, medium: 0.35, low: 0.1, info: 0 }
    let weightedSum = 0
    for (const [level, count] of Object.entries(sev)) {
      // Estimate open count for this severity proportionally
      const openRatio = openFindings / totalFindings
      const estOpen = (count ?? 0) * openRatio
      weightedSum += estOpen * (weights[level] ?? 0)
    }
    // Normalize: weightedSum / openFindings gives avg severity (0-1)
    const avgSeverity = weightedSum / openFindings
    severityProfile = Math.round(25 * (1 - avgSeverity))
  }

  // ── 3. Risk Treatment (25 pts) ──────────────────────────────
  // What fraction of risks are in treated/monitoring state?
  const rl = stats.risks_by_level ?? {}
  const rs = stats.risks_by_status ?? {}
  const totalRisks = stats.total_risks

  let riskTreatment = 25
  if (totalRisks > 0) {
    const treated = (rs.treated ?? 0) + (rs.monitoring ?? 0)
    const treatedRate = treated / totalRisks

    // Penalty for untreated critical/high risks
    const untreatedCritHigh = Math.max(0, ((rl.critical ?? 0) + (rl.high ?? 0)) - treated * (((rl.critical ?? 0) + (rl.high ?? 0)) / totalRisks))
    const riskSevPenalty = untreatedCritHigh / totalRisks * 0.3

    riskTreatment = Math.round(25 * Math.max(0, treatedRate - riskSevPenalty))
  }

  // ── 4. Exposure Density (10 pts) ──────────────────────────────
  // Open findings per asset. Fewer = better.
  // 0 findings/asset = 10, ≥10 findings/asset = 0
  let exposure = 10
  if (stats.total_assets > 0 && openFindings > 0) {
    const density = openFindings / stats.total_assets
    // Scale: 0 → 10pts, 10+ → 0pts (linear)
    exposure = Math.round(10 * Math.max(0, 1 - density / 10))
  }

  const total = Math.max(0, Math.min(100, remediation + severityProfile + riskTreatment + exposure))

  return { total, remediation, severityProfile, riskTreatment, exposure }
}
