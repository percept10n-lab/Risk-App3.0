import { useEffect, useRef } from 'react'
import { useUIStore } from '../../stores/uiStore'
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react'

const icons = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
}

const colors = {
  success: 'bg-green-50 border-green-200 text-green-800',
  error: 'bg-red-50 border-red-200 text-red-800',
  warning: 'bg-yellow-50 border-yellow-200 text-yellow-800',
  info: 'bg-blue-50 border-blue-200 text-blue-800',
}

export default function Notifications() {
  const { notifications, removeNotification } = useUIStore()

  const notificationsRef = useRef(notifications)
  notificationsRef.current = notifications

  useEffect(() => {
    const timer = setInterval(() => {
      const now = Date.now()
      notificationsRef.current.forEach((n) => {
        if (now - n.timestamp > 5000) {
          removeNotification(n.id)
        }
      })
    }, 1000)
    return () => clearInterval(timer)
  }, [removeNotification])

  if (notifications.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm">
      {notifications.map((notification) => {
        const Icon = icons[notification.type]
        return (
          <div
            key={notification.id}
            className={`flex items-start gap-3 p-4 rounded-lg border shadow-lg ${colors[notification.type]}`}
          >
            <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <p className="text-sm flex-1">{notification.message}</p>
            <button
              onClick={() => removeNotification(notification.id)}
              className="flex-shrink-0 hover:opacity-70"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )
      })}
    </div>
  )
}
