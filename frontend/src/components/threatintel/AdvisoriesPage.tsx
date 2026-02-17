import { useEffect, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { useThreatIntelStore } from '../../stores/threatIntelStore'
import Badge from '../common/Badge'
import {
  Search, ChevronLeft, ExternalLink, Copy, Loader2, Globe,
} from 'lucide-react'

export default function AdvisoriesPage() {
  const { advisoryList, advisoryTotal, loading, fetchAdvisories } = useThreatIntelStore()
  const [searchParams] = useSearchParams()
  const [search, setSearch] = useState(searchParams.get('search') || '')
  const [issuer, setIssuer] = useState(searchParams.get('issuer') || '')
  const [severity, setSeverity] = useState(searchParams.get('severity') || '')
  const [page, setPage] = useState(1)
  const pageSize = 50

  const doFetch = () => {
    const params: Record<string, any> = { page, page_size: pageSize }
    if (search) params.search = search
    if (issuer) params.issuer = issuer
    if (severity) params.severity = severity
    fetchAdvisories(params)
  }

  useEffect(() => { doFetch() }, [page, issuer, severity])
  useEffect(() => {
    const t = setTimeout(() => { setPage(1); doFetch() }, 300)
    return () => clearTimeout(t)
  }, [search])

  const totalPages = Math.ceil(advisoryTotal / pageSize)

  const copySummaries = () => {
    const text = advisoryList.map(a => `${a.advisory_id}: ${a.title}`).join('\n')
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/intel" className="text-gray-400 hover:text-gray-600"><ChevronLeft className="w-5 h-5" /></Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Advisories</h1>
            <p className="text-sm text-gray-500">{advisoryTotal.toLocaleString()} advisories from national/vendor sources</p>
          </div>
        </div>
        <button onClick={copySummaries} className="btn-secondary text-sm flex items-center gap-1">
          <Copy className="w-4 h-4" /> Copy Summaries
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white border border-gray-200 rounded-xl p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search advisory ID, title, or content..."
            className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
          />
        </div>
        <select
          value={issuer}
          onChange={e => { setIssuer(e.target.value); setPage(1) }}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
        >
          <option value="">All issuers</option>
          <option value="BSI">BSI</option>
          <option value="CERT-Bund">CERT-Bund</option>
          <option value="ENISA">ENISA</option>
        </select>
        <select
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* List */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
        {loading ? (
          <div className="flex items-center justify-center py-16"><Loader2 className="w-5 h-5 animate-spin text-gray-400" /></div>
        ) : advisoryList.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-gray-400">
            <Globe className="w-10 h-10 mb-2" />
            <p className="text-sm">No advisories found</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-50">
            {advisoryList.map(adv => (
              <div key={adv.id} className="px-5 py-4 hover:bg-gray-50">
                <div className="flex items-start gap-3">
                  <Badge variant={adv.severity === 'critical' ? 'critical' : adv.severity === 'high' ? 'high' : adv.severity === 'medium' ? 'medium' : 'low'}>
                    {adv.severity}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-semibold text-gray-800">{adv.title}</h3>
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-800">{adv.issuer}</span>
                      <code className="text-xs text-gray-400 font-mono">{adv.advisory_id}</code>
                    </div>
                    {adv.summary && (
                      <p className="text-sm text-gray-500 mt-1 line-clamp-2">{adv.summary}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2 flex-wrap">
                      {adv.cve_ids && adv.cve_ids.length > 0 && (
                        <div className="flex items-center gap-1">
                          {adv.cve_ids.slice(0, 5).map(cve => (
                            <Link
                              key={cve}
                              to={`/intel/vulnerabilities?search=${cve}`}
                              className="text-[10px] font-mono text-brand-600 hover:text-brand-800 bg-brand-50 px-1.5 py-0.5 rounded"
                            >
                              {cve}
                            </Link>
                          ))}
                          {adv.cve_ids.length > 5 && (
                            <span className="text-[10px] text-gray-400">+{adv.cve_ids.length - 5} more</span>
                          )}
                        </div>
                      )}
                      {adv.source_url && (
                        <a
                          href={adv.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-brand-600 hover:text-brand-700 flex items-center gap-1"
                        >
                          Source <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                      <span className="text-xs text-gray-400">
                        {adv.published_at ? new Date(adv.published_at).toLocaleDateString() : new Date(adv.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100">
            <span className="text-xs text-gray-500">Page {page} of {totalPages}</span>
            <div className="flex gap-2">
              <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="btn-secondary text-xs py-1 px-2">Prev</button>
              <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)} className="btn-secondary text-xs py-1 px-2">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
