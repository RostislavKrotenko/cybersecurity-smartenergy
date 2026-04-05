import { useState, useEffect } from 'react'
import { format } from 'date-fns'
import { uk } from 'date-fns/locale'

interface SidebarProps {
  autoRefresh: boolean
  setAutoRefresh: (v: boolean) => void
  refreshInterval: number
  setRefreshInterval: (v: number) => void
}

export default function Sidebar({
  autoRefresh,
  setAutoRefresh,
  refreshInterval,
  setRefreshInterval,
}: SidebarProps) {
  const [lastUpdate, setLastUpdate] = useState(new Date())

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(() => {
        setLastUpdate(new Date())
      }, refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [autoRefresh, refreshInterval])

  return (
    <aside className="w-64 bg-bg-secondary border-r border-gray-800 p-4 flex flex-col">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-text-primary">SmartEnergy</h1>
        <p className="text-text-secondary text-sm">Аналізатор кіберстійкості</p>
      </div>

      <div className="border-t border-gray-700 pt-4 mb-4">
        <h2 className="text-sm font-medium text-text-primary mb-3">
          Автооновлення
        </h2>

        <label className="flex items-center gap-2 mb-3 cursor-pointer">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="w-4 h-4 rounded border-gray-600 bg-bg-card text-blue-500 focus:ring-blue-500"
          />
          <span className="text-text-primary text-sm">Увімкнути автооновлення</span>
        </label>

        <div className="mb-3">
          <label className="text-text-secondary text-xs block mb-1">
            Інтервал оновлення (сек)
          </label>
          <input
            type="range"
            min={2}
            max={60}
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            disabled={!autoRefresh}
            className="w-full h-2 bg-bg-card rounded-lg appearance-none cursor-pointer disabled:opacity-50"
          />
          <span className="text-text-secondary text-xs">{refreshInterval}с</span>
        </div>
      </div>

      <div className="mt-auto pt-4 border-t border-gray-700">
        <p className="text-text-secondary text-xs">
          Останнє оновлення:{' '}
          {format(lastUpdate, 'HH:mm:ss', { locale: uk })}
        </p>
      </div>
    </aside>
  )
}
