import clsx from 'clsx'
import type { PolicyMetrics } from '../../types'

const POLICY_CONFIG = {
  minimal: {
    label: 'Мінімальний захист',
    color: 'border-policy-minimal',
    textColor: 'text-policy-minimal',
  },
  baseline: {
    label: 'Базова політика',
    color: 'border-policy-baseline',
    textColor: 'text-policy-baseline',
  },
  standard: {
    label: 'Стандартний захист',
    color: 'border-policy-standard',
    textColor: 'text-policy-standard',
  },
} as const

interface PolicyKpiCardProps {
  metrics: PolicyMetrics
}

export default function PolicyKpiCard({ metrics }: PolicyKpiCardProps) {
  const config = POLICY_CONFIG[metrics.policy as keyof typeof POLICY_CONFIG] ?? {
    label: metrics.policy,
    color: 'border-gray-500',
    textColor: 'text-gray-500',
  }

  return (
    <div
      className={clsx(
        'bg-bg-card rounded-lg p-4 border-t-4',
        config.color
      )}
    >
      <h3 className="text-text-secondary text-sm font-medium mb-3">
        {config.label}
      </h3>

      <div className="space-y-3">
        <div>
          <div className={clsx('text-3xl font-bold', config.textColor)}>
            {metrics.availability_pct.toFixed(2)}%
          </div>
          <div className="text-text-secondary text-xs">Доступність</div>
        </div>

        <div className="flex gap-4 text-sm">
          <div>
            <span className="text-text-secondary">Простій: </span>
            <span className="text-text-primary">{metrics.total_downtime_hr.toFixed(2)} год</span>
          </div>
        </div>

        <div className="flex gap-4 text-sm">
          <div>
            <span className="text-text-secondary">СЧОВ: </span>
            <span className="text-text-primary">{metrics.mean_mttd_min.toFixed(0)} хв</span>
          </div>
          <div>
            <span className="text-text-secondary">СЧВВ: </span>
            <span className="text-text-primary">{metrics.mean_mttr_min.toFixed(0)} хв</span>
          </div>
        </div>
      </div>
    </div>
  )
}
