import type { ActionSummary } from '../../types'

interface ActionSummaryCardProps {
  summary: ActionSummary
}

export default function ActionSummaryCard({ summary }: ActionSummaryCardProps) {
  const { total, applied, failed, emitted } = summary

  const pctApplied = total > 0 ? (applied / total) * 100 : 0
  const pctFailed = total > 0 ? (failed / total) * 100 : 0
  const pctEmitted = total > 0 ? 100 - pctApplied - pctFailed : 0

  return (
    <div className="bg-bg-card rounded-lg p-4 border-t-4 border-blue-500">
      <h3 className="text-text-secondary text-sm font-medium mb-3">
        Дії виконавця
      </h3>

      <div className="text-xl font-bold text-blue-500 mb-2">
        {total} ВСЬОГО
      </div>

      <div className="flex gap-4 text-sm mb-3">
        <span className="text-status-healthy">Застосовано: {applied}</span>
        <span className="text-red-500">Помилки: {failed}</span>
        <span className="text-gray-500">Очікує: {emitted}</span>
      </div>

      {total > 0 && (
        <div className="flex h-1.5 rounded overflow-hidden">
          <div
            className="bg-status-healthy"
            style={{ width: `${pctApplied}%` }}
          />
          <div
            className="bg-red-500"
            style={{ width: `${pctFailed}%` }}
          />
          <div
            className="bg-gray-500"
            style={{ width: `${pctEmitted}%` }}
          />
        </div>
      )}
    </div>
  )
}
