import { create } from 'zustand'
import { threatIntelApi } from '../api/endpoints'

export interface CVEItem {
  id: string
  cve_id: string
  product_summary: string | null
  cvss_base: number | null
  cvss_vector: string | null
  epss_score: number | null
  epss_percentile: number | null
  kev_listed: boolean
  kev_date_added: string | null
  kev_due_date: string | null
  kev_notes: string | null
  patch_available: boolean
  patch_date: string | null
  vendor_project: string | null
  product: string | null
  description: string | null
  references: string[] | null
  provenance: Record<string, any> | null
  created_at: string
  updated_at: string
}

export interface AdvisoryItem {
  id: string
  advisory_id: string
  issuer: string
  severity: string
  title: string
  summary: string | null
  affected_products: string[] | null
  recommendations: string | null
  cve_ids: string[] | null
  references: string[] | null
  source_url: string | null
  published_at: string | null
  updated_at_source: string | null
  provenance: Record<string, any> | null
  created_at: string
  updated_at: string
}

export interface TriageItem {
  id: string
  item_type: string
  primary_id: string
  title: string
  why_here: string
  urgency_score: number
  source_badges: string[] | null
  deep_link: string | null
  extra_data: Record<string, any> | null
  updated_at: string
}

export interface ConnectorStatus {
  id: string
  connector_name: string
  display_name: string
  source_url: string | null
  last_success: string | null
  last_attempt: string | null
  last_error: string | null
  items_ingested: number
  error_count: number
  enabled: boolean
}

export interface KeyCounters {
  kev_additions_7d: number
  exploited_wild_72h: number
  high_epss_72h: number
  critical_advisories_72h: number
  national_advisories_72h: number
  total_cves: number
  total_advisories: number
}

interface ThreatIntelState {
  // Dashboard data
  triage: TriageItem[]
  counters: KeyCounters | null
  kevLatest: CVEItem[]
  epssTop: CVEItem[]
  advisoriesLatest: AdvisoryItem[]
  connectors: ConnectorStatus[]

  // List views
  cveList: CVEItem[]
  cveTotal: number
  advisoryList: AdvisoryItem[]
  advisoryTotal: number

  // State
  loading: boolean
  ingesting: boolean
  error: string | null
  timeWindow: 24 | 72 | 168

  // Actions
  setTimeWindow: (hours: 24 | 72 | 168) => void
  fetchDashboard: () => Promise<void>
  fetchVulnerabilities: (params?: Record<string, any>) => Promise<void>
  fetchAdvisories: (params?: Record<string, any>) => Promise<void>
  fetchSources: () => Promise<void>
  runIngest: () => Promise<void>
  runSingleIngest: (connector: string) => Promise<void>
}

export const useThreatIntelStore = create<ThreatIntelState>((set, get) => ({
  triage: [],
  counters: null,
  kevLatest: [],
  epssTop: [],
  advisoriesLatest: [],
  connectors: [],
  cveList: [],
  cveTotal: 0,
  advisoryList: [],
  advisoryTotal: 0,
  loading: false,
  ingesting: false,
  error: null,
  timeWindow: 72,

  setTimeWindow: (hours) => {
    set({ timeWindow: hours })
    get().fetchDashboard()
  },

  fetchDashboard: async () => {
    set({ loading: true, error: null })
    try {
      const resp = await threatIntelApi.dashboard({ hours: get().timeWindow })
      const d = resp.data
      set({
        triage: d.triage,
        counters: d.counters,
        kevLatest: d.kev_latest,
        epssTop: d.epss_top,
        advisoriesLatest: d.advisories_latest,
        connectors: d.connectors,
        loading: false,
      })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchVulnerabilities: async (params) => {
    set({ loading: true, error: null })
    try {
      const resp = await threatIntelApi.vulnerabilities(params)
      set({ cveList: resp.data.items, cveTotal: resp.data.total, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchAdvisories: async (params) => {
    set({ loading: true, error: null })
    try {
      const resp = await threatIntelApi.advisories(params)
      set({ advisoryList: resp.data.items, advisoryTotal: resp.data.total, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchSources: async () => {
    try {
      const resp = await threatIntelApi.sources()
      set({ connectors: resp.data })
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  runIngest: async () => {
    set({ ingesting: true, error: null })
    try {
      await threatIntelApi.ingest()
      await get().fetchDashboard()
      set({ ingesting: false })
    } catch (err: any) {
      set({ error: err.message, ingesting: false })
    }
  },

  runSingleIngest: async (connector) => {
    set({ ingesting: true, error: null })
    try {
      await threatIntelApi.ingestSingle(connector)
      await get().fetchDashboard()
      set({ ingesting: false })
    } catch (err: any) {
      set({ error: err.message, ingesting: false })
    }
  },
}))
