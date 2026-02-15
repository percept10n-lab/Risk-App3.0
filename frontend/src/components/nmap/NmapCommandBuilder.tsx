import { useState, useEffect, useMemo } from 'react'
import { useAssetStore } from '../../stores/assetStore'
import { ChevronDown, X, Terminal, Code2, Sliders } from 'lucide-react'

interface NmapCommandBuilderProps {
  onStart: (target: string, nmapArgs: string, autoPipeline: boolean, timeout: number) => void
  disabled?: boolean
}

const SCAN_TYPES = [
  { value: '-sT', label: 'TCP Connect (-sT)', desc: 'Full TCP handshake — reliable, no root needed' },
  { value: '-sS', label: 'SYN Stealth (-sS)', desc: 'Half-open scan — faster, requires root' },
  { value: '-sU', label: 'UDP (-sU)', desc: 'UDP port scan — slower but finds UDP services' },
  { value: '-sn', label: 'Ping Only (-sn)', desc: 'Host discovery only — no port scan' },
  { value: '-sA', label: 'ACK (-sA)', desc: 'ACK scan — map firewall rules' },
  { value: '-sX', label: 'Xmas (-sX)', desc: 'Xmas tree scan — sets FIN, PSH, URG flags' },
  { value: '-sF', label: 'FIN (-sF)', desc: 'FIN scan — stealthy, may bypass firewalls' },
  { value: '-sN', label: 'Null (-sN)', desc: 'Null scan — no flags set' },
]

const PORT_OPTIONS = [
  { value: '', label: 'Top 1000 (default)', args: '' },
  { value: '-F', label: 'Top 100 (Fast)', args: '-F' },
  { value: '-p-', label: 'All 65535 ports', args: '-p-' },
  { value: 'custom', label: 'Custom range', args: '' },
]

const TIMING_OPTIONS = [
  { value: '', label: 'Default (T3)', args: '' },
  { value: '-T0', label: 'T0 — Paranoid', args: '-T0' },
  { value: '-T1', label: 'T1 — Sneaky', args: '-T1' },
  { value: '-T2', label: 'T2 — Polite', args: '-T2' },
  { value: '-T3', label: 'T3 — Normal', args: '-T3' },
  { value: '-T4', label: 'T4 — Aggressive', args: '-T4' },
  { value: '-T5', label: 'T5 — Insane', args: '-T5' },
]

const SCRIPT_OPTIONS = [
  { value: '', label: 'None' },
  { value: 'default', label: 'Default' },
  { value: 'vuln', label: 'Vuln' },
  { value: 'safe', label: 'Safe' },
  { value: 'auth', label: 'Auth' },
  { value: 'discovery', label: 'Discovery' },
  { value: 'custom', label: 'Custom...' },
]

const VERBOSITY_OPTIONS = [
  { value: '', label: 'Normal' },
  { value: '-v', label: 'Verbose (-v)' },
  { value: '-vv', label: 'Very Verbose (-vv)' },
]

export default function NmapCommandBuilder({ onStart, disabled }: NmapCommandBuilderProps) {
  const { assets, fetchAssets } = useAssetStore()
  const [mode, setMode] = useState<'guided' | 'raw'>('guided')

  // Guided mode state
  const [selectedAssetId, setSelectedAssetId] = useState('')
  const [freeTarget, setFreeTarget] = useState('')
  const [scanType, setScanType] = useState('-sT')
  const [portOption, setPortOption] = useState('')
  const [customPorts, setCustomPorts] = useState('')
  const [timing, setTiming] = useState('')
  const [serviceDetect, setServiceDetect] = useState(false)
  const [osDetect, setOsDetect] = useState(false)
  const [traceroute, setTraceroute] = useState(false)
  const [scriptOption, setScriptOption] = useState('')
  const [customScript, setCustomScript] = useState('')
  const [verbosity, setVerbosity] = useState('')
  const [autoPipeline, setAutoPipeline] = useState(true)
  const [timeout, setTimeout] = useState(600)
  const [assetDropdownOpen, setAssetDropdownOpen] = useState(false)

  // Raw mode state
  const [rawArgs, setRawArgs] = useState('')

  useEffect(() => { fetchAssets() }, [])

  // Build target string
  const target = useMemo(() => {
    if (selectedAssetId) {
      const asset = assets.find(a => a.id === selectedAssetId)
      return asset?.ip_address || ''
    }
    return freeTarget.trim()
  }, [selectedAssetId, freeTarget, assets])

  // Build nmap args from guided mode
  const guidedArgs = useMemo(() => {
    const parts: string[] = []
    parts.push(scanType)

    if (portOption === 'custom' && customPorts.trim()) {
      parts.push(`-p ${customPorts.trim()}`)
    } else if (portOption && portOption !== 'custom') {
      parts.push(portOption)
    }

    if (timing) parts.push(timing)
    if (serviceDetect) parts.push('-sV')
    if (osDetect) parts.push('-O')
    if (traceroute) parts.push('--traceroute')

    if (scriptOption === 'custom' && customScript.trim()) {
      parts.push(`--script ${customScript.trim()}`)
    } else if (scriptOption && scriptOption !== 'custom') {
      parts.push(`--script ${scriptOption}`)
    }

    if (verbosity) parts.push(verbosity)

    return parts.join(' ')
  }, [scanType, portOption, customPorts, timing, serviceDetect, osDetect, traceroute, scriptOption, customScript, verbosity])

  // Sync raw args when switching modes
  useEffect(() => {
    if (mode === 'raw') {
      setRawArgs(guidedArgs)
    }
  }, [mode])

  const effectiveArgs = mode === 'guided' ? guidedArgs : rawArgs
  const commandPreview = `nmap ${effectiveArgs} ${target || '<target>'}`
  const canStart = !!target && !disabled

  const handleStart = () => {
    if (!canStart) return
    onStart(target, effectiveArgs, autoPipeline, timeout)
  }

  const selectedAsset = assets.find(a => a.id === selectedAssetId)

  return (
    <div className="space-y-6">
      {/* Mode Toggle */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setMode('guided')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'guided'
              ? 'bg-brand-100 text-brand-700 ring-1 ring-brand-300'
              : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          <Sliders className="w-4 h-4" /> Guided
        </button>
        <button
          onClick={() => setMode('raw')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'raw'
              ? 'bg-brand-100 text-brand-700 ring-1 ring-brand-300'
              : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          <Code2 className="w-4 h-4" /> Raw
        </button>
      </div>

      {mode === 'guided' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column */}
          <div className="space-y-4">
            {/* Target */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Target</label>
              <div className="space-y-2">
                {/* Asset picker */}
                <div className="relative">
                  <button
                    onClick={() => setAssetDropdownOpen(!assetDropdownOpen)}
                    className="w-full px-3 py-2 border rounded-lg text-sm text-left flex items-center justify-between focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                  >
                    <span className={selectedAsset ? 'text-gray-900' : 'text-gray-500'}>
                      {selectedAsset
                        ? `${selectedAsset.ip_address} (${selectedAsset.hostname || selectedAsset.id.slice(0, 8)})`
                        : 'Pick from assets...'}
                    </span>
                    <ChevronDown className="w-4 h-4 text-gray-400" />
                  </button>
                  {assetDropdownOpen && (
                    <div className="absolute z-20 mt-1 w-full bg-white border rounded-lg shadow-lg max-h-48 overflow-y-auto">
                      <button
                        onClick={() => { setSelectedAssetId(''); setAssetDropdownOpen(false) }}
                        className="w-full px-4 py-2 text-left text-sm text-gray-500 hover:bg-gray-50"
                      >
                        — None (use free target) —
                      </button>
                      {assets.map(asset => (
                        <button
                          key={asset.id}
                          onClick={() => { setSelectedAssetId(asset.id); setFreeTarget(''); setAssetDropdownOpen(false) }}
                          className="w-full px-4 py-2 text-left text-sm hover:bg-gray-50 flex items-center gap-2"
                        >
                          <span className="font-mono text-xs">{asset.ip_address}</span>
                          <span className="text-gray-500 truncate">{asset.hostname || ''}</span>
                        </button>
                      ))}
                      {assets.length === 0 && (
                        <div className="p-3 text-center text-gray-400 text-sm">No assets registered</div>
                      )}
                    </div>
                  )}
                </div>

                {/* Free target */}
                {!selectedAssetId && (
                  <div>
                    <input
                      type="text"
                      value={freeTarget}
                      onChange={e => setFreeTarget(e.target.value)}
                      placeholder="IP or CIDR (e.g. 192.168.178.1 or 192.168.178.0/24)"
                      className="w-full px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                    />
                    <p className="text-xs text-gray-400 mt-1">RFC 1918 private ranges only</p>
                  </div>
                )}

                {selectedAssetId && (
                  <button
                    onClick={() => setSelectedAssetId('')}
                    className="text-xs text-brand-600 hover:text-brand-800 flex items-center gap-1"
                  >
                    <X className="w-3 h-3" /> Clear selection
                  </button>
                )}
              </div>
            </div>

            {/* Scan Type */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Scan Type</label>
              <select
                value={scanType}
                onChange={e => setScanType(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              >
                {SCAN_TYPES.map(st => (
                  <option key={st.value} value={st.value}>{st.label}</option>
                ))}
              </select>
              <p className="text-xs text-gray-400 mt-1">
                {SCAN_TYPES.find(st => st.value === scanType)?.desc}
              </p>
            </div>

            {/* Ports */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Ports</label>
              <div className="space-y-2">
                {PORT_OPTIONS.map(po => (
                  <label key={po.value} className="flex items-center gap-2 text-sm cursor-pointer">
                    <input
                      type="radio"
                      name="portOption"
                      checked={portOption === po.value}
                      onChange={() => setPortOption(po.value)}
                      className="text-brand-600"
                    />
                    {po.label}
                  </label>
                ))}
                {portOption === 'custom' && (
                  <input
                    type="text"
                    value={customPorts}
                    onChange={e => setCustomPorts(e.target.value)}
                    placeholder="e.g. 22,80,443 or 1-1024"
                    className="w-full px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                  />
                )}
              </div>
            </div>

            {/* Timing */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Timing</label>
              <select
                value={timing}
                onChange={e => setTiming(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              >
                {TIMING_OPTIONS.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Right Column */}
          <div className="space-y-4">
            {/* Detection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Detection</label>
              <div className="space-y-2">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={serviceDetect}
                    onChange={e => setServiceDetect(e.target.checked)}
                    className="rounded text-brand-600"
                  />
                  Service Detection (-sV)
                </label>
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={osDetect}
                    onChange={e => setOsDetect(e.target.checked)}
                    className="rounded text-brand-600"
                  />
                  OS Detection (-O)
                </label>
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={traceroute}
                    onChange={e => setTraceroute(e.target.checked)}
                    className="rounded text-brand-600"
                  />
                  Traceroute (--traceroute)
                </label>
              </div>
            </div>

            {/* NSE Scripts */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">NSE Scripts</label>
              <select
                value={scriptOption}
                onChange={e => setScriptOption(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              >
                {SCRIPT_OPTIONS.map(s => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
              {scriptOption === 'custom' && (
                <input
                  type="text"
                  value={customScript}
                  onChange={e => setCustomScript(e.target.value)}
                  placeholder="e.g. http-title,ssl-cert"
                  className="w-full mt-2 px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
                />
              )}
            </div>

            {/* Verbosity */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Verbosity</label>
              <select
                value={verbosity}
                onChange={e => setVerbosity(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              >
                {VERBOSITY_OPTIONS.map(v => (
                  <option key={v.value} value={v.value}>{v.label}</option>
                ))}
              </select>
            </div>

            {/* Timeout */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Timeout (seconds)</label>
              <input
                type="number"
                value={timeout}
                onChange={e => setTimeout(Math.max(30, Math.min(3600, parseInt(e.target.value) || 600)))}
                min={30}
                max={3600}
                className="w-full px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              />
            </div>

            {/* Pipeline Toggle */}
            <div className="p-3 bg-purple-50 border border-purple-200 rounded-lg">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoPipeline}
                  onChange={e => setAutoPipeline(e.target.checked)}
                  className="rounded text-purple-600 mt-0.5"
                />
                <div>
                  <span className="text-sm font-medium text-purple-900">Run full risk pipeline after scan</span>
                  <p className="text-xs text-purple-600 mt-0.5">
                    Vuln Assessment, Threat Modeling, MITRE Mapping, Risk Analysis
                  </p>
                </div>
              </label>
            </div>
          </div>
        </div>
      ) : (
        /* Raw Mode */
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target</label>
            <input
              type="text"
              value={freeTarget || (selectedAsset?.ip_address ?? '')}
              onChange={e => { setFreeTarget(e.target.value); setSelectedAssetId('') }}
              placeholder="IP or CIDR (e.g. 192.168.178.1)"
              className="w-full px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Nmap Arguments</label>
            <textarea
              value={rawArgs}
              onChange={e => setRawArgs(e.target.value)}
              rows={3}
              placeholder="-sT -sV -p 22,80,443 --script vuln"
              className="w-full px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500 resize-none"
            />
            <p className="text-xs text-gray-400 mt-1">
              Enter nmap arguments directly. Do not include the target or output flags (-oX, -oN, etc.)
            </p>
          </div>

          <div className="flex items-center gap-6">
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Timeout</label>
              <input
                type="number"
                value={timeout}
                onChange={e => setTimeout(Math.max(30, Math.min(3600, parseInt(e.target.value) || 600)))}
                min={30}
                max={3600}
                className="w-32 px-3 py-2 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
              />
            </div>
            <label className="flex items-center gap-2 text-sm cursor-pointer mt-4">
              <input
                type="checkbox"
                checked={autoPipeline}
                onChange={e => setAutoPipeline(e.target.checked)}
                className="rounded text-purple-600"
              />
              Run full pipeline
            </label>
          </div>
        </div>
      )}

      {/* Command Preview */}
      <div className="bg-gray-950 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-2">
          <Terminal className="w-4 h-4 text-gray-400" />
          <span className="text-xs text-gray-400 font-medium uppercase tracking-wide">Command Preview</span>
        </div>
        <code className="text-green-400 text-sm font-mono break-all">$ {commandPreview}</code>
      </div>

      {/* Start Button */}
      <button
        onClick={handleStart}
        disabled={!canStart}
        className="btn-primary w-full py-3 text-base font-semibold flex items-center justify-center gap-2"
      >
        <Terminal className="w-5 h-5" />
        {autoPipeline ? 'Start Scan & Pipeline' : 'Start Scan'}
      </button>
    </div>
  )
}
