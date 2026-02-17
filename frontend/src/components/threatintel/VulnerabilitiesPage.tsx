import { useEffect, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { useThreatIntelStore } from '../../stores/threatIntelStore'
import Badge from '../common/Badge'
import {
  Search, Filter, ChevronLeft, ChevronRight, ExternalLink,
  Copy, Loader2, Shield, ArrowUpDown,
} from 'lucide-react'

export default function VulnerabilitiesPage() {
  const { cveList, cveTotal, loading, fetchVulnerabilities } = useThreatIntelStore()
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState(searchParams.get('search') || '')
  const [page, setPage] = useState(1)
  const [kevOnly, setKevOnly] = useState(searchParams.get('kev_only') === 'true')
  const [minEpss, setMinEpss] = useState(searchParams.get('min_epss') || '')
  const [minCvss, setMinCvss] = useState(searchParams.get('min_cvss') || '')
  const [sortBy, setSortBy] = useState('urgency')
  const pageSize = 50

  const doFetch = () => {
    const params: Record<string, any> = { page, page_size: pageSize, sort_by: sortBy }
    if (search) params.search = search
    if (kevOnly) params.kev_only = true
    if (minEpss) params.min_epss = parseFloat(minEpss)
    if (minCvss) params.min_cvss = parseFloat(minCvss)
    fetchVulnerabilities(params)
  }

  useEffect(() => { doFetch() }, [page, kevOnly, sortBy])
  useEffect(() => {
    const t = setTimeout(() => { setPage(1); doFetch() }, 300)
    return () => clearTimeout(t)
  }, [search, minEpss, minCvss])

  const totalPages = Math.ceil(cveTotal / pageSize)

  const copyAllCves = () => {
    navigator.clipboard.writeText(cveList.map(c => c.cve_id).join('\n'))
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/intel" className="text-gray-400 hover:text-gray-600"><ChevronLeft className="w-5 h-5" /></Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Vulnerabilities</h1>
            <p className="text-sm text-gray-500">{cveTotal.toLocaleString()} CVEs in database</p>
          </div>
        </div>
        <button onClick={copyAllCves} className="btn-secondary text-sm flex items-center gap-1">
          <Copy className="w-4 h-4" /> Copy CVE List
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
            placeholder="Search CVE ID or description..."
            className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-500 focus:border-brand-500"
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-600">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={e => { setKevOnly(e.target.checked); setPage(1) }}
            className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
          />
          KEV only
        </label>
        <input
          type="text"
          value={minEpss}
          onChange={e => setMinEpss(e.target.value)}
          placeholder="Min EPSS (0-1)"
          className="w-28 px-3 py-2 border border-gray-300 rounded-lg text-sm"
        />
        <input
          type="text"
          value={minCvss}
          onChange={e => setMinCvss(e.target.value)}
          placeholder="Min CVSS (0-10)"
          className="w-28 px-3 py-2 border border-gray-300 rounded-lg text-sm"
        />
        <select
          value={sortBy}
          onChange={e => setSortBy(e.target.value)}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
        >
          <option value="urgency">Sort: Urgency</option>
          <option value="epss">Sort: EPSS</option>
          <option value="cvss">Sort: CVSS</option>
          <option value="kev_date">Sort: KEV Date</option>
          <option value="updated">Sort: Updated</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16"><Loader2 className="w-5 h-5 animate-spin text-gray-400" /></div>
        ) : cveList.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-gray-400">
            <Shield className="w-10 h-10 mb-2" />
            <p className="text-sm">No vulnerabilities found</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">CVE ID</th>
                <th className="px-4 py-3">Product</th>
                <th className="px-4 py-3">CVSS</th>
                <th className="px-4 py-3">EPSS</th>
                <th className="px-4 py-3">KEV</th>
                <th className="px-4 py-3">Patch</th>
                <th className="px-4 py-3">Sources</th>
                <th className="px-4 py-3">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {cveList.map(cve => (
                <tr key={cve.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <code className="font-mono font-semibold text-gray-800">{cve.cve_id}</code>
                  </td>
                  <td className="px-4 py-3 text-gray-600 max-w-xs truncate">
                    {cve.product_summary || cve.vendor_project || '—'}
                  </td>
                  <td className="px-4 py-3">
                    {cve.cvss_base != null ? (
                      <Badge variant={cve.cvss_base >= 9 ? 'critical' : cve.cvss_base >= 7 ? 'high' : cve.cvss_base >= 4 ? 'medium' : 'low'}>
                        {cve.cvss_base.toFixed(1)}
                      </Badge>
                    ) : <span className="text-gray-400">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    {cve.epss_score != null ? (
                      <span className={`text-xs font-medium ${cve.epss_score >= 0.7 ? 'text-red-600' : cve.epss_score >= 0.4 ? 'text-amber-600' : 'text-gray-600'}`}>
                        {(cve.epss_score * 100).toFixed(1)}%
                      </span>
                    ) : <span className="text-gray-400">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    {cve.kev_listed ? (
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-600 text-white">KEV</span>
                    ) : <span className="text-gray-400">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    {cve.patch_available ? (
                      <span className="text-green-600 text-xs font-medium">Yes</span>
                    ) : (
                      <span className="text-red-600 text-xs font-medium">No</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      {Object.keys(cve.provenance || {}).map(s => (
                        <span key={s} className="text-[10px] font-bold px-1 py-0.5 rounded bg-gray-100 text-gray-600">
                          {s.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {new Date(cve.updated_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {/* Pagination */}
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
