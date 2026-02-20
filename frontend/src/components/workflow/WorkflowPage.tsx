import { useEffect, useState, useRef, useCallback, useMemo } from 'react'
import PageHeader from '../common/PageHeader'
import Badge from '../common/Badge'
import NmapConsole from '../nmap/NmapConsole'
import { useRunStore } from '../../stores/runStore'
import { useAssetStore } from '../../stores/assetStore'
import { Play, Pause, Square, CheckCircle2, Circle, Loader2, AlertTriangle, Network, Server, Globe, Search, X } from 'lucide-react'

type WorkflowMode = 'cidr' | 'existing' | 'ip'

const STEPS = [
  { key: 'discovery', label: 'Asset Discovery', description: 'Scan network for devices' },
  { key: 'fingerprinting', label: 'Fingerprinting', description: 'Identify services and OS' },
  { key: 'vuln_scanning', label: 'Vulnerability Scanning', description: 'Check for known vulnerabilities' },
  { key: 'exploit_analysis', label: 'Exploit Analysis', description: 'Assess exploitability of findings' },
  { key: 'mitre_mapping', label: 'MITRE Mapping', description: 'Map findings & threats to ATT&CK' },
  { key: 'risk_analysis', label: 'Risk Analysis', description: 'Calculate risk levels (ISO 27005)' },
  { key: 'baseline', label: 'Baseline Snapshot', description: 'Create drift detection baseline' },
]

interface WsMessage {
  type: string
  message?: string
  step?: string
  timestamp?: string
  steps_completed?: string[]
}

export default function WorkflowPage({ embedded }: { embedded?: boolean }) {
  const { runs, activeRun, loading, polling, error, fetchRuns, createRun, pauseRun, resumeRun, cancelRun, stopPolling } = useRunStore()
  const { assets, fetchAssets } = useAssetStore()
  const [mode, setMode] = useState<WorkflowMode>('cidr')
  const [subnet, setSubnet] = useState('192.168.178.0/24')
  const [ipInput, setIpInput] = useState('')
  const [selectedAssetIds, setSelectedAssetIds] = useState<Set<string>>(new Set())
  const [assetSearch, setAssetSearch] = useState('')
  const [showAssetPicker, setShowAssetPicker] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [consoleLines, setConsoleLines] = useState<string[]>([])
  const [wsConnected, setWsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const pickerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchRuns()
    fetchAssets()
    return () => {
      stopPolling()
      wsRef.current?.close()
    }
  }, [])

  // Close WS when run finishes
  useEffect(() => {
    if (activeRun && ['completed', 'failed', 'cancelled'].includes(activeRun.status)) {
      wsRef.current?.close()
    }
  }, [activeRun?.status])

  const connectWebSocket = useCallback((runId: string) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = import.meta.env.VITE_API_URL
      ? new URL(import.meta.env.VITE_API_URL).host
      : window.location.host
    const wsUrl = `${protocol}//${host}/api/ws/runs/${runId}`

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setWsConnected(true)
      setConsoleLines(prev => [...prev, '[Connected to live pipeline output]'])
    }

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data)
        handleWsMessage(msg)
      } catch {
        // ignore parse errors
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
    }

    ws.onerror = () => {
      setWsConnected(false)
    }
  }, [])

  const handleWsMessage = useCallback((msg: WsMessage) => {
    const ts = msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()
    const text = msg.message || ''

    switch (msg.type) {
      case 'pipeline_start':
        setConsoleLines(prev => [...prev, `[${ts}] ${text}`])
        break
      case 'step_start':
        setConsoleLines(prev => [...prev, `[${ts}] >> ${text}`])
        break
      case 'step_complete':
        setConsoleLines(prev => [...prev, `[${ts}]    ${text}`])
        break
      case 'step_detail':
        setConsoleLines(prev => [...prev, `[${ts}]      ${text}`])
        break
      case 'step_warning':
        setConsoleLines(prev => [...prev, `[${ts}] ${text}`])
        break
      case 'pipeline_complete':
        setConsoleLines(prev => [...prev, '', `[${ts}] ${text}`, '[Pipeline finished]'])
        break
      case 'error':
        setConsoleLines(prev => [...prev, '', `[${ts}] ERROR: ${text}`])
        break
      case 'pong':
        break
      default:
        if (text) setConsoleLines(prev => [...prev, `[${ts}] ${text}`])
    }
  }, [])

  // Close asset picker on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        setShowAssetPicker(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const filteredAssets = useMemo(() => {
    if (!assetSearch) return assets
    const q = assetSearch.toLowerCase()
    return assets.filter(
      (a) =>
        a.ip_address?.toLowerCase().includes(q) ||
        a.hostname?.toLowerCase().includes(q) ||
        a.zone?.toLowerCase().includes(q)
    )
  }, [assets, assetSearch])

  const toggleAsset = (id: string) => {
    setSelectedAssetIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const selectAllFiltered = () => {
    setSelectedAssetIds((prev) => {
      const next = new Set(prev)
      filteredAssets.forEach((a) => next.add(a.id))
      return next
    })
  }

  const deselectAll = () => setSelectedAssetIds(new Set())

  const validateSubnet = (value: string): string | null => {
    const match = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/)
    if (!match) return 'Invalid IP address or CIDR notation'
    for (let i = 1; i <= 4; i++) {
      const octet = parseInt(match[i])
      if (octet < 0 || octet > 255) return `Invalid octet: ${match[i]}`
    }
    if (match[6] !== undefined) {
      const prefix = parseInt(match[6])
      if (prefix < 0 || prefix > 32) return `Invalid prefix length: /${match[6]}`
    }
    return null
  }

  const handleNewRun = async () => {
    if (mode === 'cidr') {
      const err = validateSubnet(subnet)
      if (err) {
        setValidationError(err)
        return
      }
      setValidationError(null)
      setConsoleLines([`$ Starting assessment pipeline on ${subnet}`, ''])
      wsRef.current?.close()
      const run = await createRun({ scope: { subnets: [subnet] } })
      if (run?.id) connectWebSocket(run.id)
    } else if (mode === 'existing') {
      if (selectedAssetIds.size === 0) {
        setValidationError('Select at least one asset from the list.')
        return
      }
      setValidationError(null)
      setShowAssetPicker(false)
      setConsoleLines([`$ Starting assessment pipeline using ${selectedAssetIds.size} selected assets`, ''])
      wsRef.current?.close()
      const run = await createRun({
        scope: { asset_ids: [...selectedAssetIds] },
        skip_steps: ['discovery'],
      })
      if (run?.id) connectWebSocket(run.id)
    } else {
      // IP mode
      const ips = ipInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      if (ips.length === 0) {
        setValidationError('Enter at least one IP address.')
        return
      }
      // Validate each IP
      for (const ip of ips) {
        const err = validateSubnet(ip)
        if (err) {
          setValidationError(`Invalid IP "${ip}": ${err}`)
          return
        }
      }
      setValidationError(null)

      // Match IPs to existing assets
      const matchedIds: string[] = []
      const unmatchedIps: string[] = []
      for (const ip of ips) {
        const found = assets.find((a) => a.ip_address === ip)
        if (found) {
          matchedIds.push(found.id)
        } else {
          unmatchedIps.push(ip)
        }
      }

      if (unmatchedIps.length > 0) {
        // Discover unknown IPs as /32 subnets
        const subnets = unmatchedIps.map((ip) => (ip.includes('/') ? ip : `${ip}/32`))
        setConsoleLines([`$ Starting assessment pipeline — discovering ${unmatchedIps.join(', ')}${matchedIds.length ? ` + ${matchedIds.length} known assets` : ''}`, ''])
        wsRef.current?.close()
        const scope: Record<string, any> = { subnets }
        if (matchedIds.length) scope.asset_ids = matchedIds
        const run = await createRun({ scope })
        if (run?.id) connectWebSocket(run.id)
      } else {
        // All IPs matched existing assets
        setConsoleLines([`$ Starting assessment pipeline using ${matchedIds.length} existing assets`, ''])
        wsRef.current?.close()
        const run = await createRun({
          scope: { asset_ids: matchedIds },
          skip_steps: ['discovery'],
        })
        if (run?.id) connectWebSocket(run.id)
      }
    }
  }

  const getStepStatus = (stepKey: string) => {
    if (!activeRun) return 'pending'
    if (activeRun.steps_completed?.includes(stepKey)) return 'completed'
    if (activeRun.current_step === stepKey && activeRun.status === 'running') return 'active'
    if (activeRun.current_step === stepKey && activeRun.status === 'failed') return 'failed'
    return 'pending'
  }

  const isRunning = activeRun && ['running', 'pending'].includes(activeRun.status)
  const showConsole = consoleLines.length > 0 || isRunning

  return (
    <div>
      {!embedded && (
        <PageHeader
          title="Workflow Runner"
          description="Execute and monitor assessment workflows"
          actions={
            <div className="flex items-center gap-3">
              <div className="flex rounded-lg border border-gray-300 overflow-hidden">
                <button
                  onClick={() => { setMode('cidr'); setShowAssetPicker(false) }}
                  className={`flex items-center gap-1.5 px-3 py-2 text-sm ${mode === 'cidr' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
                  disabled={!!isRunning}
                >
                  <Network className="w-3.5 h-3.5" /> CIDR
                </button>
                <button
                  onClick={() => { setMode('existing'); setShowAssetPicker(true) }}
                  className={`flex items-center gap-1.5 px-3 py-2 text-sm border-l ${mode === 'existing' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
                  disabled={!!isRunning}
                >
                  <Server className="w-3.5 h-3.5" /> Existing{selectedAssetIds.size > 0 ? ` (${selectedAssetIds.size})` : ` (${assets.length})`}
                </button>
                <button
                  onClick={() => { setMode('ip'); setShowAssetPicker(false) }}
                  className={`flex items-center gap-1.5 px-3 py-2 text-sm border-l ${mode === 'ip' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
                  disabled={!!isRunning}
                >
                  <Globe className="w-3.5 h-3.5" /> IP
                </button>
              </div>
              {mode === 'cidr' && (
                <input
                  type="text"
                  value={subnet}
                  onChange={(e) => { setSubnet(e.target.value); setValidationError(null) }}
                  placeholder="192.168.178.0/24"
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm w-44"
                  disabled={!!isRunning}
                />
              )}
              {mode === 'ip' && (
                <input
                  type="text"
                  value={ipInput}
                  onChange={(e) => { setIpInput(e.target.value); setValidationError(null) }}
                  placeholder="192.168.178.1, 10.0.0.5"
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm w-56"
                  disabled={!!isRunning}
                />
              )}
              <button
                onClick={handleNewRun}
                disabled={loading || !!isRunning}
                className="btn-primary flex items-center gap-2"
              >
                <Play className="w-4 h-4" /> New Assessment Run
              </button>
            </div>
          }
        />
      )}

      {embedded && (
        <div className="flex items-center gap-3 mb-4">
          <div className="flex rounded-lg border border-gray-300 overflow-hidden">
            <button
              onClick={() => { setMode('cidr'); setShowAssetPicker(false) }}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 text-sm ${mode === 'cidr' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
              disabled={!!isRunning}
            >
              <Network className="w-3.5 h-3.5" /> CIDR
            </button>
            <button
              onClick={() => { setMode('existing'); setShowAssetPicker(true) }}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 text-sm border-l ${mode === 'existing' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
              disabled={!!isRunning}
            >
              <Server className="w-3.5 h-3.5" /> Existing{selectedAssetIds.size > 0 ? ` (${selectedAssetIds.size})` : ` (${assets.length})`}
            </button>
            <button
              onClick={() => { setMode('ip'); setShowAssetPicker(false) }}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 text-sm border-l ${mode === 'ip' ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
              disabled={!!isRunning}
            >
              <Globe className="w-3.5 h-3.5" /> IP
            </button>
          </div>
          {mode === 'cidr' && (
            <input
              type="text"
              value={subnet}
              onChange={(e) => { setSubnet(e.target.value); setValidationError(null) }}
              placeholder="192.168.178.0/24"
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm w-44"
              disabled={!!isRunning}
            />
          )}
          {mode === 'ip' && (
            <input
              type="text"
              value={ipInput}
              onChange={(e) => { setIpInput(e.target.value); setValidationError(null) }}
              placeholder="192.168.178.1, 10.0.0.5"
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm w-56"
              disabled={!!isRunning}
            />
          )}
          <button
            onClick={handleNewRun}
            disabled={loading || !!isRunning}
            className="btn-primary flex items-center gap-2"
          >
            <Play className="w-4 h-4" /> New Assessment Run
          </button>
        </div>
      )}

      {/* Asset Picker Dropdown for Existing mode */}
      {mode === 'existing' && showAssetPicker && !isRunning && (
        <div ref={pickerRef} className="mb-4 card border border-gray-200 overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                value={assetSearch}
                onChange={(e) => setAssetSearch(e.target.value)}
                placeholder="Filter by IP, hostname, or zone..."
                className="w-full pl-9 pr-8 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
              {assetSearch && (
                <button onClick={() => setAssetSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
            <button onClick={selectAllFiltered} className="text-xs text-brand-600 hover:text-brand-700 font-medium whitespace-nowrap">
              Select All
            </button>
            <span className="text-gray-300">|</span>
            <button onClick={deselectAll} className="text-xs text-gray-500 hover:text-gray-700 font-medium whitespace-nowrap">
              None
            </button>
            <span className="text-xs text-gray-400 whitespace-nowrap">
              {selectedAssetIds.size} selected
            </span>
          </div>
          <div className="max-h-64 overflow-y-auto divide-y divide-gray-100">
            {filteredAssets.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-gray-500">
                {assets.length === 0 ? 'No assets discovered yet.' : 'No assets match your filter.'}
              </div>
            ) : (
              filteredAssets.map((asset) => (
                <label
                  key={asset.id}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={selectedAssetIds.has(asset.id)}
                    onChange={() => toggleAsset(asset.id)}
                    className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                  />
                  <span className="font-mono text-sm text-gray-800">{asset.ip_address}</span>
                  {asset.hostname && (
                    <span className="text-sm text-gray-500">— {asset.hostname}</span>
                  )}
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">
                    {asset.zone}
                  </span>
                </label>
              ))
            )}
          </div>
        </div>
      )}

      {validationError && (
        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-yellow-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> {validationError}
        </div>
      )}

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="card p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-semibold">Workflow Steps</h3>
              {polling && (
                <span className="text-xs text-brand-500 flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" /> Live updating
                </span>
              )}
            </div>
            <div className="space-y-4">
              {STEPS.map((step, idx) => {
                const status = getStepStatus(step.key)
                return (
                  <div key={step.key} className="flex items-start gap-4">
                    <div className="flex flex-col items-center">
                      {status === 'completed' ? (
                        <CheckCircle2 className="w-8 h-8 text-green-500" />
                      ) : status === 'active' ? (
                        <Loader2 className="w-8 h-8 text-brand-500 animate-spin" />
                      ) : status === 'failed' ? (
                        <AlertTriangle className="w-8 h-8 text-red-500" />
                      ) : (
                        <Circle className="w-8 h-8 text-gray-300" />
                      )}
                      {idx < STEPS.length - 1 && (
                        <div className={`w-0.5 h-8 mt-1 ${status === 'completed' ? 'bg-green-300' : 'bg-gray-200'}`} />
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{step.label}</p>
                        {status === 'active' && <Badge variant="info">Running</Badge>}
                        {status === 'completed' && <Badge variant="success">Completed</Badge>}
                        {status === 'failed' && <Badge variant="critical">Failed</Badge>}
                      </div>
                      <p className="text-sm text-gray-500 mt-0.5">{step.description}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        <div>
          <div className="card p-6">
            <h3 className="font-semibold mb-4">Run Controls</h3>
            {activeRun ? (
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-500">Run ID</p>
                  <p className="font-mono text-sm">{activeRun.id.slice(0, 8)}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Status</p>
                  <p className="font-medium capitalize">{activeRun.status}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Current Step</p>
                  <p className="font-medium">
                    {activeRun.status === 'completed' ? 'All steps completed' :
                     activeRun.current_step || 'Initializing...'}
                  </p>
                </div>
                {activeRun.steps_completed && activeRun.steps_completed.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-500">Progress</p>
                    <p className="font-medium">{activeRun.steps_completed.length} / {STEPS.length} steps</p>
                    <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                      <div
                        className="bg-brand-500 h-2 rounded-full transition-all duration-500"
                        style={{ width: `${(activeRun.steps_completed.length / STEPS.length) * 100}%` }}
                      />
                    </div>
                  </div>
                )}
                <div className="flex gap-2 pt-2">
                  {activeRun.status === 'running' && (
                    <button onClick={() => pauseRun(activeRun.id)} className="btn-secondary flex items-center gap-1">
                      <Pause className="w-4 h-4" /> Pause
                    </button>
                  )}
                  {activeRun.status === 'paused' && (
                    <button onClick={() => resumeRun(activeRun.id)} className="btn-primary flex items-center gap-1">
                      <Play className="w-4 h-4" /> Resume
                    </button>
                  )}
                  {['running', 'paused'].includes(activeRun.status) && (
                    <button onClick={() => cancelRun(activeRun.id)} className="btn-danger flex items-center gap-1">
                      <Square className="w-4 h-4" /> Cancel
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-4">
                <Play className="w-10 h-10 text-brand-400 mx-auto mb-3" />
                <p className="text-sm font-medium text-gray-700 mb-1">No active assessment</p>
                <p className="text-xs text-gray-500 mb-4">
                  {runs.length === 0
                    ? 'Start your first assessment to discover assets, find vulnerabilities, and analyze risks.'
                    : 'Start a new assessment run to scan your network.'}
                </p>
                <button
                  onClick={handleNewRun}
                  disabled={loading || !!isRunning}
                  className="btn-primary flex items-center gap-2 mx-auto"
                >
                  <Play className="w-4 h-4" /> Start Assessment
                </button>
              </div>
            )}
          </div>

          {showConsole && (
            <div className="mt-4">
              <NmapConsole lines={consoleLines} connected={wsConnected} />
            </div>
          )}

          <div className="card p-6 mt-4">
            <h3 className="font-semibold mb-4">Recent Runs</h3>
            {runs.length === 0 ? (
              <p className="text-sm text-gray-500">No previous runs</p>
            ) : (
              <div className="space-y-2">
                {runs.slice(0, 5).map((run) => (
                  <div key={run.id} className="flex items-center justify-between p-2 rounded-lg hover:bg-gray-50">
                    <div>
                      <p className="text-sm font-mono">{run.id.slice(0, 8)}</p>
                      <p className="text-xs text-gray-500">{run.triggered_by}</p>
                    </div>
                    <Badge variant={run.status === 'completed' ? 'success' : run.status === 'failed' ? 'critical' : 'info'}>
                      {run.status}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
