import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import { ArrowLeft, Loader2 } from 'lucide-react'
import api from '../../api/client'

interface FindingContext {
  finding: {
    id: string; title: string; severity: string; status: string; category: string;
    description: string; remediation: string | null; cwe_id: string | null;
    raw_output_snippet: string | null; source_tool: string; source_check: string;
    cve_ids: string[] | null; exploitability_score: number | null;
    created_at: string; updated_at: string;
  }
  asset: {
    id: string; hostname: string | null; ip_address: string; asset_type: string;
    zone: string; criticality: string; vendor: string | null; os_guess: string | null;
  } | null
  mitre_mappings: Array<{
    id: string; technique_id: string; technique_name: string;
    tactic: string; confidence: number; source: string;
  }>
  risks: Array<{
    id: string; scenario: string; risk_level: string;
    likelihood: string; impact: string;
  }>
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [data, setData] = useState<FindingContext | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    api.get(`/findings/${id}/context`)
      .then((res) => setData(res.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-brand-500" />
      </div>
    )
  }

  if (!data) {
    return <div className="text-center py-12 text-gray-500">Finding not found</div>
  }

  const { finding, asset, mitre_mappings, risks } = data

  return (
    <div>
      <button onClick={() => navigate('/findings')} className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 mb-4">
        <ArrowLeft className="w-4 h-4" /> Back to Findings
      </button>

      <PageHeader
        title={finding.title}
        description={`${finding.category} finding from ${finding.source_tool}`}
        actions={
          <div className="flex items-center gap-2">
            <Badge variant={finding.severity as any}>{finding.severity}</Badge>
            <Badge variant={finding.status === 'open' ? 'high' : finding.status === 'fixed' ? 'success' : 'info'}>{finding.status}</Badge>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Description */}
        <div className="card p-6">
          <h3 className="font-semibold mb-3">Description</h3>
          <p className="text-sm text-gray-700 whitespace-pre-wrap">{finding.description || 'No description available.'}</p>
        </div>

        {/* Asset Info */}
        {asset && (
          <div className="card p-6">
            <h3 className="font-semibold mb-3">Asset</h3>
            <dl className="space-y-2">
              {[
                ['Hostname', asset.hostname || '-'],
                ['IP Address', asset.ip_address],
                ['Type', asset.asset_type],
                ['Zone', asset.zone],
                ['Criticality', asset.criticality],
                ['Vendor', asset.vendor || '-'],
                ['OS', asset.os_guess || '-'],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between">
                  <dt className="text-sm text-gray-500">{label}</dt>
                  <dd className="text-sm font-medium">{value}</dd>
                </div>
              ))}
            </dl>
            <button
              onClick={() => navigate(`/assets/${asset.id}`)}
              className="mt-3 text-sm text-brand-600 hover:text-brand-800 font-medium"
            >
              View Asset Details
            </button>
          </div>
        )}

        {/* Remediation */}
        {finding.remediation && (
          <div className="card p-6">
            <h3 className="font-semibold mb-3">Remediation</h3>
            <p className="text-sm text-gray-700 whitespace-pre-wrap">{finding.remediation}</p>
          </div>
        )}

        {/* CWE / CVE */}
        {(finding.cwe_id || (finding.cve_ids && finding.cve_ids.length > 0)) && (
          <div className="card p-6">
            <h3 className="font-semibold mb-3">References</h3>
            {finding.cwe_id && (
              <div className="mb-2">
                <span className="text-sm text-gray-500">CWE: </span>
                <Badge variant="info">{finding.cwe_id}</Badge>
              </div>
            )}
            {finding.cve_ids && finding.cve_ids.length > 0 && (
              <div>
                <span className="text-sm text-gray-500">CVEs: </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {finding.cve_ids.map((cve: string) => (
                    <Badge key={cve} variant="high">{cve}</Badge>
                  ))}
                </div>
              </div>
            )}
            {finding.exploitability_score != null && (
              <div className="mt-2">
                <span className="text-sm text-gray-500">Exploitability: </span>
                <span className="text-sm font-bold">{finding.exploitability_score}/10</span>
              </div>
            )}
          </div>
        )}

        {/* Evidence */}
        {finding.raw_output_snippet && (
          <div className="card p-6 lg:col-span-2">
            <h3 className="font-semibold mb-3">Evidence</h3>
            <pre className="bg-gray-900 text-green-400 p-4 rounded-lg text-xs overflow-x-auto max-h-64 overflow-y-auto">
              {finding.raw_output_snippet}
            </pre>
          </div>
        )}

        {/* MITRE Mappings */}
        {mitre_mappings.length > 0 && (
          <div className="card p-6">
            <h3 className="font-semibold mb-3">MITRE ATT&CK Techniques ({mitre_mappings.length})</h3>
            <div className="space-y-2">
              {mitre_mappings.map((m) => (
                <div key={m.id} className="flex items-center gap-2 p-2 bg-gray-50 rounded-lg">
                  <span className="font-mono text-xs text-brand-600">{m.technique_id}</span>
                  <span className="text-sm font-medium flex-1">{m.technique_name}</span>
                  <Badge variant="info">{m.tactic}</Badge>
                  <span className="text-xs text-gray-500">{Math.round(m.confidence * 100)}%</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Risk Scenarios */}
        {risks.length > 0 && (
          <div className="card p-6">
            <h3 className="font-semibold mb-3">Risk Scenarios ({risks.length})</h3>
            <div className="space-y-2">
              {risks.map((r) => (
                <div key={r.id} className="p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant={r.risk_level as any}>{r.risk_level}</Badge>
                    <span className="text-xs text-gray-500">L: {r.likelihood} / I: {r.impact}</span>
                  </div>
                  <p className="text-sm text-gray-700">{r.scenario}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
