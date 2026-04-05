import clsx from 'clsx'
import type { ComponentState } from '../../types'

const STATUS_CONFIG = {
  healthy: { color: 'text-status-healthy', borderColor: 'border-status-healthy', icon: '[OK]' },
  degraded: { color: 'text-status-degraded', borderColor: 'border-status-degraded', icon: '[!!]' },
  isolated: { color: 'text-status-isolated', borderColor: 'border-status-isolated', icon: '[X]' },
  restoring: { color: 'text-status-restoring', borderColor: 'border-status-restoring', icon: '[..]' },
  corrupted: { color: 'text-red-600', borderColor: 'border-red-600', icon: '[!!]' },
  disconnected: { color: 'text-red-600', borderColor: 'border-red-600', icon: '[X]' },
  rate_limited: { color: 'text-yellow-500', borderColor: 'border-yellow-500', icon: '[!]' },
  blocking: { color: 'text-orange-500', borderColor: 'border-orange-500', icon: '[B]' },
  restored: { color: 'text-status-healthy', borderColor: 'border-status-healthy', icon: '[OK]' },
  reset: { color: 'text-status-healthy', borderColor: 'border-status-healthy', icon: '[OK]' },
} as const

const COMPONENT_LABELS: Record<string, string> = {
  gateway: 'Шлюз',
  api: 'API',
  auth: 'Авторизація',
  db: 'База даних',
  network: 'Мережа',
}

interface ComponentStatusCardProps {
  component: ComponentState
}

export default function ComponentStatusCard({ component }: ComponentStatusCardProps) {
  const status = (component.status || 'healthy').toLowerCase()
  const config = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] ?? {
    color: 'text-gray-500',
    borderColor: 'border-gray-500',
    icon: '',
  }

  const label = COMPONENT_LABELS[component.component_id] ?? component.component_id.toUpperCase()
  const ttlSec = (component.details?.ttl_sec as number) ?? 0

  const formatTtl = (sec: number) => {
    const m = Math.floor(sec / 60)
    const s = Math.floor(sec % 60)
    return m > 0 ? `${m}хв ${s}с` : `${s}с`
  }

  const detailsStr = Object.entries(component.details || {})
    .filter(([k, v]) => k !== 'ttl_sec' && v !== null && v !== '')
    .map(([k, v]) => `${k}=${v}`)
    .join(' ')

  return (
    <div className={clsx('bg-bg-card rounded-lg p-4 border-t-4', config.borderColor)}>
      <h3 className="text-text-secondary text-sm font-medium mb-3">{label}</h3>

      <div className={clsx('text-xl font-bold mb-2', config.color)}>
        {config.icon} {status.toUpperCase().replace('_', ' ')}
      </div>

      {detailsStr && (
        <div className="text-text-secondary text-xs mb-2">{detailsStr}</div>
      )}

      {ttlSec > 0 && (
        <div className="text-yellow-500 text-xs">
          TTL: {formatTtl(ttlSec)}
        </div>
      )}
    </div>
  )
}
