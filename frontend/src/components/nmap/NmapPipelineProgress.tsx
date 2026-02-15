import { CheckCircle2, Loader2, XCircle, Circle, Scan, Import, FileSearch, Shield, Crosshair, Map, AlertTriangle } from 'lucide-react'

export type StepStatus = 'pending' | 'running' | 'completed' | 'error'

export interface PipelineStep {
  id: string
  label: string
  status: StepStatus
  detail?: string
}

interface NmapPipelineProgressProps {
  steps: PipelineStep[]
}

const STEP_ICONS: Record<string, React.ElementType> = {
  nmap_scan: Scan,
  asset_import: Import,
  store_findings: FileSearch,
  vuln_assessment: Shield,
  threat_modeling: Crosshair,
  mitre_mapping: Map,
  risk_analysis: AlertTriangle,
}

function StepIcon({ stepId, status }: { stepId: string; status: StepStatus }) {
  if (status === 'running') {
    return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
  }
  if (status === 'completed') {
    return <CheckCircle2 className="w-5 h-5 text-green-500" />
  }
  if (status === 'error') {
    return <XCircle className="w-5 h-5 text-red-500" />
  }

  const Icon = STEP_ICONS[stepId] || Circle
  return <Icon className="w-5 h-5 text-gray-400" />
}

const STATUS_RING: Record<StepStatus, string> = {
  pending: 'border-gray-300 bg-gray-50',
  running: 'border-blue-400 bg-blue-50 ring-2 ring-blue-200',
  completed: 'border-green-400 bg-green-50',
  error: 'border-red-400 bg-red-50',
}

const LINE_COLOR: Record<StepStatus, string> = {
  pending: 'bg-gray-300',
  running: 'bg-blue-300',
  completed: 'bg-green-400',
  error: 'bg-red-300',
}

export default function NmapPipelineProgress({ steps }: NmapPipelineProgressProps) {
  return (
    <div className="w-full overflow-x-auto">
      <div className="flex items-start justify-between min-w-[600px] px-2">
        {steps.map((step, i) => (
          <div key={step.id} className="flex items-start flex-1">
            {/* Step circle + label */}
            <div className="flex flex-col items-center min-w-[80px]">
              <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center ${STATUS_RING[step.status]}`}>
                <StepIcon stepId={step.id} status={step.status} />
              </div>
              <span className={`text-xs font-medium mt-1.5 text-center leading-tight ${
                step.status === 'completed' ? 'text-green-700' :
                step.status === 'running' ? 'text-blue-700' :
                step.status === 'error' ? 'text-red-700' :
                'text-gray-500'
              }`}>
                {step.label}
              </span>
              {step.detail && (
                <span className="text-[10px] text-gray-400 mt-0.5 text-center max-w-[100px] truncate">
                  {step.detail}
                </span>
              )}
            </div>

            {/* Connecting line */}
            {i < steps.length - 1 && (
              <div className="flex-1 flex items-center pt-5 px-1">
                <div className={`h-0.5 w-full rounded ${
                  step.status === 'completed'
                    ? LINE_COLOR.completed
                    : step.status === 'error'
                    ? LINE_COLOR.error
                    : LINE_COLOR.pending
                }`} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export const DEFAULT_PIPELINE_STEPS: PipelineStep[] = [
  { id: 'nmap_scan', label: 'Nmap Scan', status: 'pending' },
  { id: 'asset_import', label: 'Asset Import', status: 'pending' },
  { id: 'store_findings', label: 'Findings', status: 'pending' },
  { id: 'vuln_assessment', label: 'Vuln Scan', status: 'pending' },
  { id: 'threat_modeling', label: 'Threats', status: 'pending' },
  { id: 'mitre_mapping', label: 'MITRE Map', status: 'pending' },
  { id: 'risk_analysis', label: 'Risk Analysis', status: 'pending' },
]
