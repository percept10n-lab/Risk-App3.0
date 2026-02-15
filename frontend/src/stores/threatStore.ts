import { create } from 'zustand'
import type { Threat, PaginatedResponse } from '../types'
import { threatsApi } from '../api/endpoints'

interface ThreatState {
  threats: Threat[]
  total: number
  page: number
  pageSize: number
  loading: boolean
  error: string | null
  filters: {
    threat_type?: string
    asset_id?: string
    zone?: string
    source?: string
  }
  fetchThreats: () => Promise<void>
  deleteThreat: (id: string) => Promise<void>
  setFilters: (filters: Partial<ThreatState['filters']>) => void
  setPage: (page: number) => void
}

export const useThreatStore = create<ThreatState>((set, get) => ({
  threats: [],
  total: 0,
  page: 1,
  pageSize: 50,
  loading: false,
  error: null,
  filters: {},

  fetchThreats: async () => {
    set({ loading: true, error: null })
    try {
      const { page, pageSize, filters } = get()
      const params = { page, page_size: pageSize, ...filters }
      const response = await threatsApi.list(params)
      set({
        threats: response.data.items,
        total: response.data.total,
        loading: false,
      })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  deleteThreat: async (id: string) => {
    try {
      await threatsApi.delete(id)
      get().fetchThreats()
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  setFilters: (filters) => {
    set((state) => ({ filters: { ...state.filters, ...filters }, page: 1 }))
    get().fetchThreats()
  },

  setPage: (page) => {
    set({ page })
    get().fetchThreats()
  },
}))
