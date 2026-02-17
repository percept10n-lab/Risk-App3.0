import { useState, useEffect, useRef, useCallback } from 'react'
import PageHeader from '../common/PageHeader'
import NmapCommandBuilder from './NmapCommandBuilder'
import NmapConsole from './NmapConsole'
import NmapPipelineProgress, { DEFAULT_PIPELINE_STEPS, type PipelineStep } from './NmapPipelineProgress'
import NmapResultsSummary from './NmapResultsSummary'
import { nmapApi } from '../../api/endpoints'
import { RotateCcw, AlertCircle } from 'lucide-react'

type Phase = 'configure' | 'running' | 'completed' | 'error'

interface PipelineResult {
  hosts_discovered?: number
  assets_created?: number
  assets_updated?: number
  findings_created?: number
  threats_created?: number
  risks_created?: number
  [key: string]: unknown
}

interface WsMessage {
  type: string
  line?: string
  step?: string
  status?: string
  detail?: string
  result?: PipelineResult
  error?: string
}

export default function NmapPage() {
  const [phase, setPhase] = useState<Phase>('configure')
  const [runId, setRunId] = useState<string | null>(null)
  const [consoleLines, setConsoleLines] = useState<string[]>([])
  const [wsConnected, setWsConnected] = useState(false)
  const [pipelineSteps, setPipelineSteps] = useState<PipelineStep[]>(DEFAULT_PIPELINE_STEPS)
  const [pipelineResult, setPipelineResult] = useState<PipelineResult | null>(null)
  const [errorMessage, setErrorMessage] = useState('')
  const [autoPipeline, setAutoPipeline] = useState(true)
  const wsRef = useRef<WebSocket | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Clean up WS + polling on unmount
  useEffect(() => {
    return () => {
      wsRef.current?.close()
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const connectWebSocket = useCallback((rid: string) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = import.meta.env.VITE_API_URL
      ? new URL(import.meta.env.VITE_API_URL).host
      : window.location.host
    const wsUrl = `${protocol}//${host}/api/ws/runs/${rid}`

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setWsConnected(true)
      setConsoleLines(prev => [...prev, '[Connected to live output]'])
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        handleWsMessage(msg)
      } catch (err: any) {
        console.warn('Failed to parse WebSocket message:', err.message)
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
    }

    ws.onerror = () => {
      setWsConnected(false)
      // Fall back to polling
      startPolling(rid)
    }
  }, [])

  const handleWsMessage = useCallback((msg: WsMessage) => {
    switch (msg.type) {
      case 'nmap_output':
        setConsoleLines(prev => [...prev, msg.line || ''])
        break

      case 'pipeline_step':
        setPipelineSteps(prev =>
          prev.map(step =>
            step.id === msg.step
              ? { ...step, status: msg.status, detail: msg.detail }
              : step
          )
        )
        break

      case 'pipeline_complete':
        setPhase('completed')
        setPipelineResult(msg.result || {})
        // Mark any remaining pending steps as completed
        setPipelineSteps(prev =>
          prev.map(step => ({
            ...step,
            status: step.status === 'pending' ? 'completed' : step.status,
          }))
        )
        setConsoleLines(prev => [...prev, '', '[Pipeline complete]'])
        break

      case 'pipeline_error':
        setPhase('error')
        setErrorMessage(msg.error || 'Pipeline failed')
        setConsoleLines(prev => [...prev, '', `[ERROR] ${msg.error || 'Pipeline failed'}`])
        break

      case 'pong':
        break
    }
  }, [])

  const startPolling = useCallback((rid: string) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const res = await nmapApi.status(rid)
        const data = res.data
        if (data.status === 'completed') {
          setPhase('completed')
          setPipelineResult(data.result || {})
          setPipelineSteps(prev => prev.map(s => ({ ...s, status: 'completed' })))
          if (pollRef.current) clearInterval(pollRef.current)
        } else if (data.status === 'error') {
          setPhase('error')
          setErrorMessage(data.error || 'Pipeline failed')
          if (pollRef.current) clearInterval(pollRef.current)
        }
      } catch (err: any) {
        console.warn('Polling status check failed:', err.message)
      }
    }, 3000)
  }, [])

  const handleStart = async (target: string, nmapArgs: string, pipeline: boolean, timeout: number) => {
    setPhase('running')
    setConsoleLines([`$ nmap ${nmapArgs} ${target}`, ''])
    setPipelineSteps(
      pipeline
        ? DEFAULT_PIPELINE_STEPS.map(s => ({ ...s, status: 'pending' as const, detail: undefined }))
        : DEFAULT_PIPELINE_STEPS.slice(0, 3).map(s => ({ ...s, status: 'pending' as const, detail: undefined }))
    )
    setPipelineResult(null)
    setErrorMessage('')
    setAutoPipeline(pipeline)

    try {
      const res = await nmapApi.scan({
        target,
        nmap_args: nmapArgs,
        timeout,
        auto_pipeline: pipeline,
      })

      if (res.data.status === 'error') {
        setPhase('error')
        setErrorMessage(res.data.error || 'Failed to start scan')
        return
      }

      const rid = res.data.run_id
      setRunId(rid)
      connectWebSocket(rid)
      startPolling(rid)
    } catch (err: any) {
      setPhase('error')
      setErrorMessage(err.response?.data?.detail || err.message || 'Failed to start scan')
    }
  }

  const handleNewScan = () => {
    wsRef.current?.close()
    if (pollRef.current) clearInterval(pollRef.current)
    setPhase('configure')
    setRunId(null)
    setConsoleLines([])
    setWsConnected(false)
    setPipelineSteps(DEFAULT_PIPELINE_STEPS)
    setPipelineResult(null)
    setErrorMessage('')
  }

  return (
    <div>
      <PageHeader
        title="Nmap Scanner"
        description="Custom network scanning with autonomous risk pipeline"
        actions={
          phase !== 'configure' ? (
            <button onClick={handleNewScan} className="btn-secondary flex items-center gap-2 text-sm">
              <RotateCcw className="w-4 h-4" /> New Scan
            </button>
          ) : undefined
        }
      />

      {/* Configure Phase */}
      {phase === 'configure' && (
        <div className="card p-6">
          <NmapCommandBuilder onStart={handleStart} />
        </div>
      )}

      {/* Running Phase */}
      {phase === 'running' && (
        <div className="space-y-6">
          {autoPipeline && (
            <div className="card p-6">
              <NmapPipelineProgress steps={pipelineSteps} />
            </div>
          )}
          <NmapConsole lines={consoleLines} connected={wsConnected} />
        </div>
      )}

      {/* Completed Phase */}
      {phase === 'completed' && (
        <div className="space-y-6">
          {autoPipeline && (
            <div className="card p-6">
              <NmapPipelineProgress steps={pipelineSteps} />
            </div>
          )}
          <NmapConsole lines={consoleLines} connected={wsConnected} />
          {pipelineResult && <NmapResultsSummary results={pipelineResult} />}
        </div>
      )}

      {/* Error Phase */}
      {phase === 'error' && (
        <div className="space-y-6">
          <div className="flex items-start gap-3 p-4 bg-red-50 border border-red-200 rounded-lg">
            <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-red-800">Scan Failed</p>
              <p className="text-sm text-red-600 mt-1">{errorMessage}</p>
            </div>
          </div>
          {consoleLines.length > 0 && (
            <NmapConsole lines={consoleLines} connected={false} />
          )}
        </div>
      )}
    </div>
  )
}
