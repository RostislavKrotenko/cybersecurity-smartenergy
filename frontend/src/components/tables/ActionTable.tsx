import { useState, useMemo } from 'react'
import { format, parseISO } from 'date-fns'
import clsx from 'clsx'
import type { Action } from '../../types'

const STATUS_COLORS: Record<string, string> = {
  applied: 'text-green-500 bg-green-500/10',
  failed: 'text-red-500 bg-red-500/10',
  emitted: 'text-gray-500 bg-gray-500/10',
  pending: 'text-yellow-500 bg-yellow-500/10',
}

const PAGE_SIZE = 50

interface ActionTableProps {
  actions: Action[]
}

export default function ActionTable({ actions }: ActionTableProps) {
  const [page, setPage] = useState(0)

  const formatTs = (ts: string | null) => {
    if (!ts) return '-'
    try {
      return format(parseISO(ts), 'dd.MM.yyyy HH:mm:ss')
    } catch {
      return ts
    }
  }

  const sortedActions = useMemo(() => {
    return [...actions].sort((a, b) => {
      if (!a.ts_utc || !b.ts_utc) return 0
      return b.ts_utc.localeCompare(a.ts_utc)
    })
  }, [actions])

  const totalPages = Math.ceil(sortedActions.length / PAGE_SIZE)
  const paginatedActions = sortedActions.slice(
    page * PAGE_SIZE,
    (page + 1) * PAGE_SIZE
  )

  if (!actions.length) {
    return (
      <div className="bg-bg-card rounded-lg p-4">
        <h3 className="text-text-primary text-sm font-medium mb-4">
          Хронологія дій (замкнений цикл)
        </h3>
        <div className="text-text-secondary text-center py-8">
          Дії ще не надіслано
        </div>
      </div>
    )
  }

  return (
    <div className="bg-bg-card rounded-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-text-primary text-sm font-medium">
          Хронологія дій (замкнений цикл)
        </h3>
        <span className="text-text-secondary text-xs">
          {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, sortedActions.length)} з {sortedActions.length}
        </span>
      </div>

      <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-bg-card">
            <tr className="border-b border-gray-700">
              <th className="px-3 py-2 text-left text-text-secondary">Час</th>
              <th className="px-3 py-2 text-left text-text-secondary">Дія</th>
              <th className="px-3 py-2 text-left text-text-secondary">Компонент</th>
              <th className="px-3 py-2 text-left text-text-secondary">Ціль</th>
              <th className="px-3 py-2 text-left text-text-secondary">Причина</th>
              <th className="px-3 py-2 text-left text-text-secondary">Статус</th>
            </tr>
          </thead>
          <tbody>
            {paginatedActions.map((act) => (
              <tr
                key={act.action_id}
                className="border-b border-gray-800 hover:bg-bg-secondary"
              >
                <td className="px-3 py-2 text-text-primary whitespace-nowrap">
                  {formatTs(act.ts_utc)}
                </td>
                <td className="px-3 py-2 text-text-primary font-mono text-xs">
                  {act.action}
                </td>
                <td className="px-3 py-2 text-text-primary">
                  {act.target_component}
                </td>
                <td className="px-3 py-2 text-text-secondary text-xs">
                  {act.target_id || '-'}
                </td>
                <td className="px-3 py-2 text-text-secondary text-xs max-w-[200px] truncate">
                  {act.reason || '-'}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={clsx(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      STATUS_COLORS[act.status] ?? 'text-gray-500'
                    )}
                  >
                    {act.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-700">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className={clsx(
              'px-3 py-1 rounded text-sm',
              page === 0
                ? 'text-text-secondary cursor-not-allowed'
                : 'text-text-primary bg-bg-secondary hover:bg-gray-700'
            )}
          >
            ← Попередня
          </button>

          <div className="flex items-center gap-1">
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
              let pageNum: number
              if (totalPages <= 7) {
                pageNum = i
              } else if (page < 3) {
                pageNum = i
              } else if (page > totalPages - 4) {
                pageNum = totalPages - 7 + i
              } else {
                pageNum = page - 3 + i
              }

              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={clsx(
                    'w-8 h-8 rounded text-sm',
                    page === pageNum
                      ? 'bg-blue-600 text-white'
                      : 'text-text-secondary hover:bg-bg-secondary'
                  )}
                >
                  {pageNum + 1}
                </button>
              )
            })}
          </div>

          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className={clsx(
              'px-3 py-1 rounded text-sm',
              page >= totalPages - 1
                ? 'text-text-secondary cursor-not-allowed'
                : 'text-text-primary bg-bg-secondary hover:bg-gray-700'
            )}
          >
            Наступна →
          </button>
        </div>
      )}
    </div>
  )
}
