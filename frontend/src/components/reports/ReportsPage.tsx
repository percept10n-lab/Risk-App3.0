import { useEffect, useState } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import {
  FileText, Download, Loader2, CheckCircle2, AlertTriangle,
  Shield, Bug, Activity, Crosshair, Eye, FileDown,
} from 'lucide-react'
import { reportsApi } from '../../api/endpoints'

interface GeneratedReport {
  type: string
  actualType?: string
  status: 'generating' | 'done' | 'error'
  reportId?: string
  error?: string
  note?: string
}

interface SummaryData {
  total_assets: number
  total_findings: number
  total_risks: number
  total_threats: number
  severity_breakdown: Record<string, number>
  risk_breakdown: Record<string, number>
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
  info: 'bg-gray-300',
}

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
}

function getPosture(risk_breakdown: Record<string, number>): { label: string; color: string } {
  if ((risk_breakdown['critical'] || 0) > 0) return { label: 'CRITICAL', color: 'bg-red-600 text-white' }
  if ((risk_breakdown['high'] || 0) > 0) return { label: 'HIGH', color: 'bg-orange-500 text-white' }
  if ((risk_breakdown['medium'] || 0) > 0) return { label: 'MEDIUM', color: 'bg-yellow-400 text-gray-900' }
  if ((risk_breakdown['low'] || 0) > 0) return { label: 'LOW', color: 'bg-blue-400 text-white' }
  return { label: 'HEALTHY', color: 'bg-green-500 text-white' }
}

function BreakdownBar({ data, colorMap }: { data: Record<string, number>; colorMap: Record<string, string> }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0)
  if (total === 0) return <div className="h-3 rounded-full bg-gray-100" />
  const ordered = Object.keys(colorMap).filter((k) => (data[k] || 0) > 0)
  return (
    <div className="flex rounded-full overflow-hidden h-3">
      {ordered.map((key) => (
        <div
          key={key}
          className={colorMap[key]}
          style={{ width: `${((data[key] || 0) / total) * 100}%` }}
          title={`${key}: ${data[key]}`}
        />
      ))}
    </div>
  )
}

export default function ReportsPage() {
  const [reports, setReports] = useState<GeneratedReport[]>([])
  const [generating, setGenerating] = useState<string | null>(null)
  const [summary, setSummary] = useState<SummaryData | null>(null)
  const [summaryLoading, setSummaryLoading] = useState(true)

  useEffect(() => {
    reportsApi.summary()
      .then((res) => setSummary(res.data))
      .catch(() => {})
      .finally(() => setSummaryLoading(false))
  }, [])

  const handleGenerate = async (type: string) => {
    setGenerating(type)
    setReports((prev) => [...prev.filter((r) => r.type !== type), { type, status: 'generating' }])
    try {
      const res = await reportsApi.generate({ report_type: type })
      if (res.data?.status === 'error') {
        setReports((prev) =>
          prev.map((r) => (r.type === type ? { ...r, status: 'error', error: res.data.error || 'Generation failed' } : r))
        )
      } else {
        const reportId = res.data?.report_id || res.data?.id
        const actualType = res.data?.report_type || type
        const note = res.data?.note
        setReports((prev) =>
          prev.map((r) => (r.type === type ? { ...r, status: 'done', reportId, actualType, note } : r))
        )
      }
    } catch (err: any) {
      setReports((prev) =>
        prev.map((r) => (r.type === type ? { ...r, status: 'error', error: err.response?.data?.detail || err.message } : r))
      )
    }
    setGenerating(null)
  }

  const handleDownload = async (reportId: string, type: string, actualType?: string) => {
    try {
      const res = await reportsApi.download(reportId)
      const effectiveType = actualType || type
      const mimeTypes: Record<string, string> = {
        html: 'text/html', pdf: 'application/pdf', json: 'application/json', csv: 'text/csv',
      }
      const blob = new Blob([res.data], { type: mimeTypes[effectiveType] || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = effectiveType === 'html' ? 'html' : effectiveType === 'csv' ? 'csv' : effectiveType === 'pdf' ? 'pdf' : 'json'
      a.download = `security-report.${ext}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) { console.error('Failed to download report:', err.message) }
  }

  const handlePreview = async (reportId: string) => {
    try {
      const res = await reportsApi.download(reportId)
      const blob = new Blob([res.data], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      window.open(url, '_blank')
    } catch (err: any) { console.error('Failed to preview report:', err.message) }
  }

  const reportTypes = [
    {
      type: 'html', title: 'HTML Report',
      desc: 'Interactive web-based report with full evidence, risk matrix, and findings detail.',
      icon: FileText, color: 'bg-brand-50 text-brand-600',
    },
    {
      type: 'pdf', title: 'PDF Report',
      desc: 'Printable report suitable for stakeholders and compliance documentation.',
      icon: FileDown, color: 'bg-red-50 text-red-600',
    },
    {
      type: 'json', title: 'JSON Export',
      desc: 'Machine-readable export with assets, findings, risks, MITRE mappings, and audit trail.',
      icon: Download, color: 'bg-green-50 text-green-600',
    },
    {
      type: 'csv', title: 'CSV Export',
      desc: 'Spreadsheet-friendly exports of findings, risks, and assets for further analysis.',
      icon: Download, color: 'bg-purple-50 text-purple-600',
    },
  ]

  const metricCards = summary
    ? [
        { label: 'Total Assets', value: summary.total_assets, icon: Activity, color: 'text-brand-600 bg-brand-50' },
        { label: 'Total Findings', value: summary.total_findings, icon: Bug, color: 'text-orange-600 bg-orange-50' },
        { label: 'Total Risks', value: summary.total_risks, icon: Shield, color: 'text-red-600 bg-red-50' },
        { label: 'Total Threats', value: summary.total_threats, icon: Crosshair, color: 'text-purple-600 bg-purple-50' },
      ]
    : []

  const posture = summary ? getPosture(summary.risk_breakdown) : null

  return (
    <div>
      <PageHeader title="Reports" description="Executive summary and report generation" />

      {/* Executive Summary */}
      <div className="card p-6 mb-8">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold">Executive Summary</h2>
          {posture && (
            <span className={`px-3 py-1 rounded-full text-xs font-bold ${posture.color}`}>
              {posture.label}
            </span>
          )}
        </div>

        {summaryLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-5 h-5 animate-spin text-brand-500" />
          </div>
        ) : summary ? (
          <>
            {/* Metric cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {metricCards.map((m) => (
                <div key={m.label} className="flex items-center gap-3 p-3 rounded-xl bg-gray-50">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${m.color}`}>
                    <m.icon className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-2xl font-bold">{m.value}</div>
                    <div className="text-xs text-gray-500">{m.label}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Breakdowns */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">Finding Severity</span>
                  <span className="text-xs text-gray-400">{summary.total_findings} total</span>
                </div>
                <BreakdownBar data={summary.severity_breakdown} colorMap={SEVERITY_COLORS} />
                <div className="flex flex-wrap gap-3 mt-2">
                  {Object.entries(SEVERITY_COLORS).map(([key, color]) => {
                    const count = summary.severity_breakdown[key] || 0
                    if (count === 0) return null
                    return (
                      <span key={key} className="flex items-center gap-1.5 text-xs text-gray-600">
                        <span className={`w-2.5 h-2.5 rounded-full ${color}`} />
                        {key} ({count})
                      </span>
                    )
                  })}
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">Risk Levels</span>
                  <span className="text-xs text-gray-400">{summary.total_risks} total</span>
                </div>
                <BreakdownBar data={summary.risk_breakdown} colorMap={RISK_COLORS} />
                <div className="flex flex-wrap gap-3 mt-2">
                  {Object.entries(RISK_COLORS).map(([key, color]) => {
                    const count = summary.risk_breakdown[key] || 0
                    if (count === 0) return null
                    return (
                      <span key={key} className="flex items-center gap-1.5 text-xs text-gray-600">
                        <span className={`w-2.5 h-2.5 rounded-full ${color}`} />
                        {key} ({count})
                      </span>
                    )
                  })}
                </div>
              </div>
            </div>
          </>
        ) : (
          <p className="text-sm text-gray-500 text-center py-4">Unable to load summary data.</p>
        )}
      </div>

      {/* Report Generation */}
      <h2 className="text-lg font-semibold mb-4">Generate Reports</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {reportTypes.map((r) => {
          const existing = reports.find((rep) => rep.type === r.type)
          return (
            <div key={r.type} className="card p-6">
              <div className={`w-12 h-12 rounded-xl ${r.color} flex items-center justify-center mb-4`}>
                <r.icon className="w-6 h-6" />
              </div>
              <h3 className="font-semibold">{r.title}</h3>
              <p className="text-sm text-gray-500 mt-1 mb-4">{r.desc}</p>

              {existing?.status === 'done' && existing.reportId ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm text-green-600">
                    <CheckCircle2 className="w-4 h-4" /> Report generated
                  </div>
                  {existing.note && (
                    <div className="flex items-center gap-1.5 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span>{existing.note}</span>
                    </div>
                  )}
                  <button
                    onClick={() => handleDownload(existing.reportId!, r.type, existing.actualType)}
                    className="btn-primary w-full flex items-center justify-center gap-2"
                  >
                    <Download className="w-4 h-4" /> Download {existing.actualType && existing.actualType !== r.type ? `(${existing.actualType.toUpperCase()})` : ''}
                  </button>
                  {(r.type === 'html' || existing.actualType === 'html') && (
                    <button
                      onClick={() => handlePreview(existing.reportId!)}
                      className="btn-secondary w-full flex items-center justify-center gap-2"
                    >
                      <Eye className="w-4 h-4" /> Preview
                    </button>
                  )}
                </div>
              ) : existing?.status === 'error' ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm text-red-600">
                    <AlertTriangle className="w-4 h-4" /> Generation failed
                  </div>
                  <button
                    onClick={() => handleGenerate(r.type)}
                    className="btn-secondary w-full"
                  >
                    Retry
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => handleGenerate(r.type)}
                  disabled={generating === r.type}
                  className="btn-primary w-full flex items-center justify-center gap-2"
                >
                  {generating === r.type ? (
                    <><Loader2 className="w-4 h-4 animate-spin" /> Generating...</>
                  ) : (
                    'Generate'
                  )}
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
