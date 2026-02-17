import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import api from '../../api/client'
import { Download, X, Loader2 } from 'lucide-react'

interface EnrichedMapping {
  id: string
  technique_id: string
  technique_name: string
  tactic: string
  confidence: number
  source: string
  finding_id: string | null
  finding_title: string | null
  finding_severity: string | null
  finding_status: string | null
  asset_id: string | null
  asset_hostname: string | null
  asset_ip: string | null
  threat_id: string | null
  threat_title: string | null
  is_exploitable: boolean
}

interface TechniqueGroup {
  technique_id: string
  technique_name: string
  tactic: string
  max_confidence: number
  is_exploitable: boolean
  findings: Array<{ id: string; title: string; severity: string; status: string }>
  assets: Array<{ id: string; hostname: string | null; ip: string }>
  mappings: EnrichedMapping[]
}

const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

export default function MitrePage() {
  const [mappings, setMappings] = useState<EnrichedMapping[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueGroup | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    async function load() {
      try {
        const res = await api.get('/mitre/mappings/enriched', { params: { page_size: 500 } })
        setMappings(res.data.items || [])
      } catch (err: any) { console.error('Failed to load MITRE mappings:', err.message) }
      setLoading(false)
    }
    load()
  }, [])

  const handleExport = async () => {
    try {
      const res = await api.get('/mitre/layer-export')
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'attack-navigator-layer.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) { console.error('Failed to export navigator layer:', err.message) }
  }

  // Group mappings by technique_id
  const techniqueMap = new Map<string, TechniqueGroup>()
  for (const m of mappings) {
    let group = techniqueMap.get(m.technique_id)
    if (!group) {
      group = {
        technique_id: m.technique_id,
        technique_name: m.technique_name,
        tactic: m.tactic,
        max_confidence: 0,
        is_exploitable: false,
        findings: [],
        assets: [],
        mappings: [],
      }
      techniqueMap.set(m.technique_id, group)
    }
    group.max_confidence = Math.max(group.max_confidence, m.confidence)
    if (m.is_exploitable) group.is_exploitable = true
    group.mappings.push(m)
    if (m.finding_id && m.finding_title && !group.findings.some((f) => f.id === m.finding_id)) {
      group.findings.push({ id: m.finding_id, title: m.finding_title, severity: m.finding_severity || 'info', status: m.finding_status || 'open' })
    }
    if (m.asset_id && m.asset_ip && !group.assets.some((a) => a.id === m.asset_id)) {
      group.assets.push({ id: m.asset_id, hostname: m.asset_hostname, ip: m.asset_ip })
    }
  }

  const techniques = Array.from(techniqueMap.values())

  const groupedByTactic = TACTICS.reduce<Record<string, TechniqueGroup[]>>((acc, tactic) => {
    acc[tactic] = techniques.filter((t) => t.tactic === tactic)
    return acc
  }, {})

  const exploitableCount = techniques.filter((t) => t.is_exploitable).length

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK Mapping"
        description="Technique mappings enriched with findings and assets"
        actions={
          <button onClick={handleExport} className="btn-primary flex items-center gap-2">
            <Download className="w-4 h-4" /> Export Navigator Layer
          </button>
        }
      />

      {/* Legend */}
      {!loading && mappings.length > 0 && (
        <div className="flex items-center gap-6 mb-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded border-2 border-red-500 bg-red-50" />
            <span className="text-gray-600">Actively exploitable ({exploitableCount})</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded border-2 border-gray-300 bg-gray-50" />
            <span className="text-gray-600">Mapped ({techniques.length - exploitableCount})</span>
          </div>
          <span className="text-gray-400">|</span>
          <span className="text-gray-500">{techniques.length} unique techniques from {mappings.length} mappings</span>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-4 border-brand-200 border-t-brand-600 rounded-full" />
        </div>
      ) : mappings.length === 0 ? (
        <div className="card p-8 text-center text-gray-500">
          No MITRE ATT&CK mappings yet. Mappings are created during vulnerability scanning and threat modeling.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {TACTICS.filter((t) => groupedByTactic[t]?.length > 0).map((tactic) => (
            <div key={tactic} className="card">
              <div className="px-4 py-3 bg-gray-900 text-white rounded-t-xl">
                <h3 className="text-sm font-medium">{tactic}</h3>
                <p className="text-xs text-gray-300">{groupedByTactic[tactic].length} techniques</p>
              </div>
              <div className="p-3 space-y-2">
                {groupedByTactic[tactic].map((tech) => (
                  <div
                    key={tech.technique_id}
                    className={`p-2 rounded-lg text-sm cursor-pointer transition-colors hover:shadow-sm ${
                      tech.is_exploitable
                        ? 'bg-red-50 border border-red-300 hover:bg-red-100'
                        : 'bg-gray-50 border border-transparent hover:bg-gray-100'
                    }`}
                    onClick={() => setSelectedTechnique(tech)}
                  >
                    <p className="font-mono text-xs text-brand-600">{tech.technique_id}</p>
                    <p className="font-medium text-xs mt-0.5">{tech.technique_name}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-gray-500">{Math.round(tech.max_confidence * 100)}%</span>
                      <span className="text-xs text-gray-400">{tech.findings.length}F / {tech.assets.length}A</span>
                      {tech.is_exploitable && (
                        <span className="text-xs text-red-600 font-bold ml-auto">EXPLOITABLE</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setSelectedTechnique(null)}>
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-brand-600 font-bold">{selectedTechnique.technique_id}</span>
                  <span className="font-semibold">{selectedTechnique.technique_name}</span>
                </div>
                <div className="flex items-center gap-3 mt-1 text-sm text-gray-500">
                  <span>Tactic: {selectedTechnique.tactic}</span>
                  <span>Confidence: {Math.round(selectedTechnique.max_confidence * 100)}%</span>
                  {selectedTechnique.is_exploitable && (
                    <Badge variant="critical">Exploitable</Badge>
                  )}
                </div>
              </div>
              <button onClick={() => setSelectedTechnique(null)} className="text-gray-400 hover:text-gray-600">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="overflow-y-auto flex-1 p-6 space-y-6">
              {/* Linked Findings */}
              {selectedTechnique.findings.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 mb-2">Linked Findings ({selectedTechnique.findings.length})</h4>
                  <div className="space-y-2">
                    {selectedTechnique.findings.map((f) => (
                      <div
                        key={f.id}
                        className="flex items-center gap-3 p-2 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100 transition-colors"
                        onClick={() => { setSelectedTechnique(null); navigate(`/findings/${f.id}`) }}
                      >
                        <Badge variant={f.severity as any}>{f.severity}</Badge>
                        <span className="text-sm flex-1 truncate">{f.title}</span>
                        <Badge variant={f.status === 'open' ? 'high' : 'info'}>{f.status}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Affected Assets */}
              {selectedTechnique.assets.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 mb-2">Affected Assets ({selectedTechnique.assets.length})</h4>
                  <div className="space-y-2">
                    {selectedTechnique.assets.map((a) => (
                      <div
                        key={a.id}
                        className="flex items-center gap-3 p-2 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100 transition-colors"
                        onClick={() => { setSelectedTechnique(null); navigate(`/assets/${a.id}`) }}
                      >
                        <span className="text-sm font-medium">{a.hostname || a.ip}</span>
                        <span className="text-xs text-gray-400 font-mono">{a.ip}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
