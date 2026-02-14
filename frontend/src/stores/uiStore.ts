import { create } from 'zustand'

interface UIState {
  sidebarOpen: boolean
  activeModal: string | null
  modalData: any
  notifications: Array<{
    id: string
    type: 'success' | 'error' | 'warning' | 'info'
    message: string
    timestamp: number
  }>
  toggleSidebar: () => void
  openModal: (name: string, data?: any) => void
  closeModal: () => void
  addNotification: (type: 'success' | 'error' | 'warning' | 'info', message: string) => void
  removeNotification: (id: string) => void
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  activeModal: null,
  modalData: null,
  notifications: [],

  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),

  openModal: (name, data = null) => set({ activeModal: name, modalData: data }),

  closeModal: () => set({ activeModal: null, modalData: null }),

  addNotification: (type, message) =>
    set((state) => ({
      notifications: [
        ...state.notifications,
        { id: crypto.randomUUID(), type, message, timestamp: Date.now() },
      ],
    })),

  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
}))
