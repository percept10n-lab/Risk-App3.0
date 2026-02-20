import { useEffect, useRef } from 'react'
import { Wifi, WifiOff } from 'lucide-react'

interface NmapConsoleProps {
  lines: string[]
  connected: boolean
}

function colorClass(line: string): string {
  if (line.includes('ERROR') || line.includes('failed') || line.includes('FAIL')) return 'text-red-400'
  if (line.includes('WARNING') || line.includes('⚠')) return 'text-yellow-400'
  if (line.includes('✓') || line.includes('Complete') || line.includes('completed') || line.includes('finished') || line.includes('success')) return 'text-emerald-400'
  if (line.startsWith('[') && line.includes('] >>')) return 'text-cyan-400'
  if (line.startsWith('$')) return 'text-blue-400'
  return 'text-green-400'
}

export default function NmapConsole({ lines, connected }: NmapConsoleProps) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines.length])

  return (
    <div className="rounded-lg overflow-hidden border border-gray-800">
      {/* Header */}
      <div className="bg-gray-900 px-4 py-2 flex items-center justify-between">
        <span className="text-sm font-medium text-gray-300">Console Output</span>
        <div className="flex items-center gap-2">
          {connected ? (
            <>
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
              </span>
              <Wifi className="w-3.5 h-3.5 text-green-400" />
            </>
          ) : (
            <>
              <span className="h-2.5 w-2.5 rounded-full bg-gray-600" />
              <WifiOff className="w-3.5 h-3.5 text-gray-500" />
            </>
          )}
        </div>
      </div>

      {/* Terminal body */}
      <div className="bg-gray-950 p-4 font-mono text-sm h-96 overflow-y-auto">
        {lines.length === 0 ? (
          <span className="text-gray-600">Waiting for output...</span>
        ) : (
          lines.map((line, i) => (
            <div key={i} className={`whitespace-pre-wrap break-all leading-relaxed ${colorClass(line)}`}>
              {line}
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
