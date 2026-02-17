import { create } from 'zustand'
import type { Risk, PaginatedResponse } from '../types'
import { risksApi } from '../api/endpoints'

interface RiskState {
  risks: Risk[]
  selectedRisk: Risk | null
  total: number
  page: number
  pageSize: number
  loading: boolean
  error: string | null
  extraParams: Record<string, any>
  filters: {
    asset_id?: string
    risk_level?: string
    status?: string
  }
  fetchRisks: (extraParams?: Record<string, any>) => Promise<void>
  fetchRisk: (id: string) => Promise<void>
  setFilters: (filters: Partial<RiskState['filters']>) => void
  setPage: (page: number) => void
}

export const useRiskStore = create<RiskState>((set, get) => ({
  risks: [],
  selectedRisk: null,
  total: 0,
  page: 1,
  pageSize: 200,
  loading: false,
  error: null,
  extraParams: {},
  filters: {},

  fetchRisks: async (extraParams?: Record<string, any>) => {
    if (extraParams) set({ extraParams })
    set({ loading: true, error: null })
    try {
      const { page, pageSize, filters, extraParams: stored } = get()
      const params = { page, page_size: pageSize, ...filters, ...stored, ...extraParams }
      const response = await risksApi.list(params)
      set({
        risks: response.data.items,
        total: response.data.total,
        loading: false,
      })
    } catch (err: any) {
      set({ error: err.response?.data?.detail || err.message || 'Failed to fetch risks', loading: false })
    }
  },

  fetchRisk: async (id: string) => {
    set({ loading: true, error: null })
    try {
      const response = await risksApi.get(id)
      set({ selectedRisk: response.data, loading: false })
    } catch (err: any) {
      set({ error: err.response?.data?.detail || err.message || 'Failed to fetch risk', loading: false })
    }
  },

  setFilters: (filters) => {
    set((state) => ({ filters: { ...state.filters, ...filters }, page: 1 }))
    get().fetchRisks()
  },

  setPage: (page) => {
    set({ page })
    get().fetchRisks()
  },
}))
