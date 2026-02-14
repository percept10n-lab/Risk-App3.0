import { create } from 'zustand'
import type { Asset, PaginatedResponse } from '../types'
import { assetsApi } from '../api/endpoints'

interface AssetState {
  assets: Asset[]
  selectedAsset: Asset | null
  total: number
  page: number
  pageSize: number
  loading: boolean
  error: string | null
  filters: {
    zone?: string
    asset_type?: string
    criticality?: string
    search?: string
  }
  fetchAssets: () => Promise<void>
  fetchAsset: (id: string) => Promise<void>
  setFilters: (filters: Partial<AssetState['filters']>) => void
  setPage: (page: number) => void
}

export const useAssetStore = create<AssetState>((set, get) => ({
  assets: [],
  selectedAsset: null,
  total: 0,
  page: 1,
  pageSize: 50,
  loading: false,
  error: null,
  filters: {},

  fetchAssets: async () => {
    set({ loading: true, error: null })
    try {
      const { page, pageSize, filters } = get()
      const params = { page, page_size: pageSize, ...filters }
      const response = await assetsApi.list(params)
      set({
        assets: response.data.items,
        total: response.data.total,
        loading: false,
      })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchAsset: async (id: string) => {
    set({ loading: true, error: null })
    try {
      const response = await assetsApi.get(id)
      set({ selectedAsset: response.data, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  setFilters: (filters) => {
    set((state) => ({ filters: { ...state.filters, ...filters }, page: 1 }))
    get().fetchAssets()
  },

  setPage: (page) => {
    set({ page })
    get().fetchAssets()
  },
}))
