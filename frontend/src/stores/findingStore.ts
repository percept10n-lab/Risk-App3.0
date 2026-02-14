import { create } from 'zustand'
import type { Finding, PaginatedResponse } from '../types'
import { findingsApi } from '../api/endpoints'

interface FindingState {
  findings: Finding[]
  selectedFinding: Finding | null
  total: number
  page: number
  pageSize: number
  loading: boolean
  error: string | null
  filters: {
    asset_id?: string
    severity?: string
    status?: string
    category?: string
  }
  fetchFindings: () => Promise<void>
  fetchFinding: (id: string) => Promise<void>
  setFilters: (filters: Partial<FindingState['filters']>) => void
  setPage: (page: number) => void
}

export const useFindingStore = create<FindingState>((set, get) => ({
  findings: [],
  selectedFinding: null,
  total: 0,
  page: 1,
  pageSize: 50,
  loading: false,
  error: null,
  filters: {},

  fetchFindings: async () => {
    set({ loading: true, error: null })
    try {
      const { page, pageSize, filters } = get()
      const params = { page, page_size: pageSize, ...filters }
      const response = await findingsApi.list(params)
      set({
        findings: response.data.items,
        total: response.data.total,
        loading: false,
      })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchFinding: async (id: string) => {
    set({ loading: true, error: null })
    try {
      const response = await findingsApi.get(id)
      set({ selectedFinding: response.data, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  setFilters: (filters) => {
    set((state) => ({ filters: { ...state.filters, ...filters }, page: 1 }))
    get().fetchFindings()
  },

  setPage: (page) => {
    set({ page })
    get().fetchFindings()
  },
}))
