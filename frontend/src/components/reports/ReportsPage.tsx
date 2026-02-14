import { useState } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { FileText, Download, Loader2, CheckCircle2, AlertTriangle } from 'lucide-react'
import api from '../../api/client'

interface GeneratedReport {
  type: string
  status: 'generating' | 'done' | 'error'
  reportId?: string
  error?: string
}

export default function ReportsPage() {
  const [reports, setReports] = useState<GeneratedReport[]>([])
  const [generating, setGenerating] = useState<string | null>(null)

  const handleGenerate = async (type: string) => {
    setGenerating(type)
    setReports((prev) => [...prev.filter((r) => r.type !== type), { type, status: 'generating' }])
    try {
      const res = await api.post('/reports/generate', { report_type: type })
      const reportId = res.data?.report_id || res.data?.id
      setReports((prev) =>
        prev.map((r) => (r.type === type ? { ...r, status: 'done', reportId } : r))
      )
    } catch (err: any) {
      setReports((prev) =>
        prev.map((r) => (r.type === type ? { ...r, status: 'error', error: err.message } : r))
      )
    }
    setGenerating(null)
  }

  const handleDownload = async (reportId: string, type: string) => {
    try {
      const res = await api.get(`/reports/${reportId}/download`, { responseType: 'blob' })
      const blob = new Blob([res.data])
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `security-report.${type === 'html' ? 'html' : type === 'pdf' ? 'pdf' : 'json'}`
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* empty */ }
  }

  const reportTypes = [
    {
      type: 'html', title: 'HTML Report',
      desc: 'Interactive web-based report with full evidence, risk matrix, and findings detail.',
      icon: FileText, color: 'bg-brand-50 text-brand-600',
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

  return (
    <div>
      <PageHeader title="Reports" description="Generate and download security assessment reports" />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
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
                  <button
                    onClick={() => handleDownload(existing.reportId!, r.type)}
                    className="btn-primary w-full flex items-center justify-center gap-2"
                  >
                    <Download className="w-4 h-4" /> Download
                  </button>
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
