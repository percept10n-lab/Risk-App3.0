import { create } from 'zustand'
import { threatIntelApi } from '../api/endpoints'

export interface MonitoredIdentity {
  id: string
  email: string
  label: string | null
  owner: string | null
  enabled: boolean
  last_checked: string | null
  breach_count: number
  paste_count: number
  created_at: string
  updated_at: string
}

export interface BreachHit {
  id: string
  identity_id: string
  email: string
  breach_name: string
  breach_title: string | null
  breach_domain: string | null
  breach_date: string | null
  added_date: string | null
  data_classes: string[] | null
  description: string | null
  is_verified: boolean
  is_sensitive: boolean
  severity: string
  source: string
  provenance: Record<string, any> | null
  created_at: string
}

export interface IdentitySummary {
  total_identities: number
  total_breaches: number
  critical_breaches: number
  high_breaches: number
  exposed_identities: number
  latest_breaches: BreachHit[]
}

export interface PasswordCheckResult {
  sha1_prefix: string
  is_compromised: boolean
  occurrence_count: number
}

interface IdentityMonitorState {
  identities: MonitoredIdentity[]
  selectedBreaches: BreachHit[]
  summary: IdentitySummary | null
  passwordResult: PasswordCheckResult | null
  loading: boolean
  checking: boolean
  error: string | null

  fetchIdentities: () => Promise<void>
  addIdentity: (email: string, label?: string, owner?: string) => Promise<void>
  deleteIdentity: (id: string) => Promise<void>
  fetchBreaches: (identityId: string) => Promise<void>
  checkAll: () => Promise<void>
  checkSingle: (id: string) => Promise<void>
  fetchSummary: () => Promise<void>
  checkPassword: (sha1Hash: string) => Promise<void>
  clearPasswordResult: () => void
}

export const useIdentityMonitorStore = create<IdentityMonitorState>((set, get) => ({
  identities: [],
  selectedBreaches: [],
  summary: null,
  passwordResult: null,
  loading: false,
  checking: false,
  error: null,

  fetchIdentities: async () => {
    set({ loading: true, error: null })
    try {
      const resp = await threatIntelApi.identities()
      set({ identities: resp.data, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  addIdentity: async (email, label, owner) => {
    set({ error: null })
    try {
      await threatIntelApi.addIdentity({ email, label, owner })
      await get().fetchIdentities()
      await get().fetchSummary()
    } catch (err: any) {
      set({ error: err.response?.data?.detail || err.message })
    }
  },

  deleteIdentity: async (id) => {
    set({ error: null })
    try {
      await threatIntelApi.deleteIdentity(id)
      await get().fetchIdentities()
      await get().fetchSummary()
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  fetchBreaches: async (identityId) => {
    set({ loading: true, error: null })
    try {
      const resp = await threatIntelApi.identityBreaches(identityId)
      set({ selectedBreaches: resp.data, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  checkAll: async () => {
    set({ checking: true, error: null })
    try {
      await threatIntelApi.checkAllIdentities()
      await get().fetchIdentities()
      await get().fetchSummary()
      set({ checking: false })
    } catch (err: any) {
      set({ error: err.message, checking: false })
    }
  },

  checkSingle: async (id) => {
    set({ checking: true, error: null })
    try {
      await threatIntelApi.checkIdentity(id)
      await get().fetchIdentities()
      await get().fetchBreaches(id)
      await get().fetchSummary()
      set({ checking: false })
    } catch (err: any) {
      set({ error: err.message, checking: false })
    }
  },

  fetchSummary: async () => {
    try {
      const resp = await threatIntelApi.identitySummary()
      set({ summary: resp.data })
    } catch {
      // Non-critical
    }
  },

  checkPassword: async (sha1Hash) => {
    set({ loading: true, error: null, passwordResult: null })
    try {
      const resp = await threatIntelApi.passwordCheck(sha1Hash)
      set({ passwordResult: resp.data, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  clearPasswordResult: () => set({ passwordResult: null }),
}))
