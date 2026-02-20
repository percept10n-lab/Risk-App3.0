import { NavLink } from 'react-router-dom'
import { useUIStore } from '../../stores/uiStore'
import {
  LayoutDashboard,
  Monitor,
  Shield,
  Crosshair,
  PlayCircle,
  Bug,
  FileText,
  Bot,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
} from 'lucide-react'

const navItems = [
  { to: '/', icon: Bot, label: 'AI Copilot', end: true },
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/assets', icon: Monitor, label: 'Assets' },
  { to: '/findings', icon: Bug, label: 'Findings & Vulns' },
  { to: '/threats', icon: Crosshair, label: 'Threat Analysis' },
  { to: '/operations', icon: PlayCircle, label: 'Operations' },
  { to: '/risks', icon: Shield, label: 'Risks' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

const bottomItems = [
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  const { sidebarOpen, toggleSidebar } = useUIStore()

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-30 flex flex-col bg-gray-900 text-white transition-all duration-300 ${
        sidebarOpen ? 'w-64' : 'w-16'
      }`}
    >
      <div className="flex items-center h-16 px-4 border-b border-gray-800">
        <ShieldAlert className="w-8 h-8 text-brand-400 flex-shrink-0" />
        {sidebarOpen && (
          <span className="ml-3 text-lg font-semibold truncate">Risk Platform</span>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto py-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={'end' in item ? item.end : undefined}
            aria-label={!sidebarOpen ? item.label : undefined}
            title={!sidebarOpen ? item.label : undefined}
            className={({ isActive }) =>
              `flex items-center px-4 py-2.5 mx-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-brand-600 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {sidebarOpen && <span className="ml-3 truncate">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-gray-800 py-2 space-y-1">
        {bottomItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            aria-label={!sidebarOpen ? item.label : undefined}
            title={!sidebarOpen ? item.label : undefined}
            className={({ isActive }) =>
              `flex items-center px-4 py-2.5 mx-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-brand-600 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {sidebarOpen && <span className="ml-3 truncate">{item.label}</span>}
          </NavLink>
        ))}
      </div>

      <button
        onClick={toggleSidebar}
        aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        className="flex items-center justify-center h-12 border-t border-gray-800 hover:bg-gray-800 transition-colors"
      >
        {sidebarOpen ? (
          <ChevronLeft className="w-5 h-5" />
        ) : (
          <ChevronRight className="w-5 h-5" />
        )}
      </button>
    </aside>
  )
}
