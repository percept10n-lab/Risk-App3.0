import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useThreatIntelStore } from '../../stores/threatIntelStore'
import {
  ChevronLeft, RefreshCw, CheckCircle2, XCircle, Clock,
  ExternalLink, Loader2, Server,
} from 'lucide-react'

function timeAgo(ts: string | null): string {
  if (!ts) return 'Never'
  const diff = Date.now() - new Date(ts).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export default function SourcesPage() {
  const { connectors, ingesting, fetchSources, runIngest, runSingleIngest } = useThreatIntelStore()

  useEffect(() => { fetchSources() }, [])

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/intel" className="text-gray-400 hover:text-gray-600"><ChevronLeft className="w-5 h-5" /></Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Sources</h1>
            <p className="text-sm text-gray-500">Connector status, provenance, and ingest health</p>
          </div>
        </div>
        <button onClick={runIngest} disabled={ingesting} className="btn-primary flex items-center gap-2 text-sm">
          <RefreshCw className={`w-4 h-4 ${ingesting ? 'animate-spin' : ''}`} />
          {ingesting ? 'Ingesting...' : 'Ingest All'}
        </button>
      </div>

      {connectors.length === 0 ? (
        <div className="bg-white border border-gray-200 rounded-xl p-16 text-center">
          <Server className="w-12 h-12 text-gray-300 mx-auto mb-3" />
          <p className="text-sm text-gray-500 font-medium">No connectors registered</p>
          <p className="text-xs text-gray-400 mt-1">Click "Ingest All" to initialize connectors and fetch data</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {connectors.map(c => {
            const isHealthy = c.last_success && !c.last_error
            const isFresh = c.last_success && (Date.now() - new Date(c.last_success).getTime()) < 6 * 3600 * 1000
            return (
              <div key={c.connector_name} className="bg-white border border-gray-200 rounded-xl shadow-sm p-5">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      isHealthy && isFresh ? 'bg-green-100' :
                      isHealthy ? 'bg-yellow-100' :
                      c.last_error ? 'bg-red-100' : 'bg-gray-100'
                    }`}>
                      {isHealthy ? (
                        <CheckCircle2 className={`w-5 h-5 ${isFresh ? 'text-green-600' : 'text-yellow-600'}`} />
                      ) : c.last_error ? (
                        <XCircle className="w-5 h-5 text-red-600" />
                      ) : (
                        <Clock className="w-5 h-5 text-gray-400" />
                      )}
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-gray-800">{c.display_name}</h3>
                      <span className="text-xs text-gray-400">{c.connector_name}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => runSingleIngest(c.connector_name)}
                    disabled={ingesting}
                    className="btn-secondary text-xs py-1 px-2 flex items-center gap-1"
                  >
                    <RefreshCw className={`w-3 h-3 ${ingesting ? 'animate-spin' : ''}`} /> Refresh
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-gray-50 rounded-lg p-3">
                    <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider">Last Success</span>
                    <p className={`text-sm font-medium mt-0.5 ${isHealthy ? 'text-green-600' : 'text-gray-500'}`}>
                      {timeAgo(c.last_success)}
                    </p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider">Last Attempt</span>
                    <p className="text-sm font-medium mt-0.5 text-gray-600">{timeAgo(c.last_attempt)}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider">Items Ingested</span>
                    <p className="text-sm font-medium mt-0.5 text-gray-800">{c.items_ingested.toLocaleString()}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider">Error Count</span>
                    <p className={`text-sm font-medium mt-0.5 ${c.error_count > 0 ? 'text-red-600' : 'text-gray-500'}`}>
                      {c.error_count}
                    </p>
                  </div>
                </div>

                {c.last_error && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-100 rounded-lg">
                    <span className="text-[10px] font-medium text-red-400 uppercase tracking-wider">Last Error</span>
                    <p className="text-xs text-red-600 mt-0.5 break-words">{c.last_error}</p>
                  </div>
                )}

                {c.source_url && (
                  <div className="mt-3 pt-3 border-t border-gray-100">
                    <a
                      href={c.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-brand-600 hover:text-brand-700 flex items-center gap-1"
                    >
                      {c.source_url} <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
