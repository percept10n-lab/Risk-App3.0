import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import { useUIStore } from '../../stores/uiStore'
import Notifications from './Notifications'

export default function Layout() {
  const sidebarOpen = useUIStore((s) => s.sidebarOpen)

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50">
      <Sidebar />
      <div
        className={`flex-1 flex flex-col overflow-hidden transition-all duration-300 ${
          sidebarOpen ? 'ml-64' : 'ml-16'
        }`}
      >
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
      <Notifications />
    </div>
  )
}
