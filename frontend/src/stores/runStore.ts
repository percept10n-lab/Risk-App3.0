import { create } from 'zustand'
import type { Run } from '../types'
import { runsApi } from '../api/endpoints'

interface RunState {
  runs: Run[]
  activeRun: Run | null
  loading: boolean
  error: string | null
  polling: boolean
  fetchRuns: () => Promise<void>
  fetchRun: (id: string) => Promise<void>
  createRun: (data?: any) => Promise<Run | null>
  pauseRun: (id: string) => Promise<void>
  resumeRun: (id: string) => Promise<void>
  cancelRun: (id: string) => Promise<void>
  startPolling: (runId: string) => void
  stopPolling: () => void
}

let pollInterval: ReturnType<typeof setInterval> | null = null

export const useRunStore = create<RunState>((set, get) => ({
  runs: [],
  activeRun: null,
  loading: false,
  error: null,
  polling: false,

  fetchRuns: async () => {
    set({ loading: true, error: null })
    try {
      const response = await runsApi.list()
      const runs = response.data.items
      set({ runs, loading: false })
      // Auto-detect active run
      const active = runs.find((r: Run) => r.status === 'running' || r.status === 'pending')
      if (active) {
        set({ activeRun: active })
        get().startPolling(active.id)
      }
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchRun: async (id: string) => {
    try {
      const response = await runsApi.get(id)
      set({ activeRun: response.data })
      // Stop polling if run is finished
      if (['completed', 'failed', 'cancelled'].includes(response.data.status)) {
        get().stopPolling()
        get().fetchRuns()
      }
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  createRun: async (data?: any) => {
    set({ loading: true, error: null })
    try {
      const response = await runsApi.create(data)
      const run = response.data
      set({ activeRun: run, loading: false })
      // Start polling for status updates
      get().startPolling(run.id)
      get().fetchRuns()
      return run
    } catch (err: any) {
      set({ error: err.message, loading: false })
      return null
    }
  },

  pauseRun: async (id: string) => {
    try {
      await runsApi.pause(id)
      get().fetchRun(id)
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  resumeRun: async (id: string) => {
    try {
      await runsApi.resume(id)
      get().fetchRun(id)
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  cancelRun: async (id: string) => {
    try {
      await runsApi.cancel(id)
      get().fetchRun(id)
    } catch (err: any) {
      set({ error: err.message })
    }
  },

  startPolling: (runId: string) => {
    if (!runId) return
    if (pollInterval) clearInterval(pollInterval)
    set({ polling: true })
    pollInterval = setInterval(() => {
      const { activeRun } = get()
      if (!activeRun || activeRun.id !== runId) {
        get().stopPolling()
        return
      }
      get().fetchRun(runId)
    }, 2000)
  },

  stopPolling: () => {
    if (pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
    }
    set({ polling: false })
  },
}))
