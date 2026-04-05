import { useMemo, useState } from 'react'
import { format, parseISO } from 'date-fns'
import clsx from 'clsx'
import type { Incident } from '../../types'

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 bg-red-500/10',
  high: 'text-orange-500 bg-orange-500/10',
  medium: 'text-yellow-500 bg-yellow-500/10',
  low: 'text-green-500 bg-green-500/10',
}

const PAGE_SIZE = 50

interface IncidentTableProps {
  incidents: Incident[]
}

export default function IncidentTable({ incidents }: IncidentTableProps) {
  const [sortField, setSortField] = useState<keyof Incident>('start_ts')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(0)

  const sortedIncidents = useMemo(() => {
    const sorted = [...incidents].sort((a, b) => {
      // First sort by severity
      const sevA = SEVERITY_ORDER[a.severity] ?? 99
      const sevB = SEVERITY_ORDER[b.severity] ?? 99
      if (sevA !== sevB) return sevA - sevB

      // Then by selected field
      const valA = a[sortField]
      const valB = b[sortField]
      if (valA == null && valB == null) return 0
      if (valA == null) return 1
      if (valB == null) return -1

      const cmp = String(valA).localeCompare(String(valB))
      return sortDir === 'asc' ? cmp : -cmp
    })
    return sorted
  }, [incidents, sortField, sortDir])

  const totalPages = Math.ceil(sortedIncidents.length / PAGE_SIZE)
  const paginatedIncidents = sortedIncidents.slice(
    page * PAGE_SIZE,
    (page + 1) * PAGE_SIZE
  )

  const handleSort = (field: keyof Incident) => {
    if (field === sortField) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('desc')
    }
    setPage(0) // Reset to first page on sort change
  }

  const formatTs = (ts: string | null) => {
    if (!ts) return '-'
    try {
      return format(parseISO(ts), 'dd.MM.yyyy HH:mm')
    } catch {
      return ts
    }
  }

  if (!incidents.length) {
    return (
      <div className="bg-bg-card rounded-lg p-4">
        <h3 className="text-text-primary text-sm font-medium mb-4">
          Таблиця інцидентів
        </h3>
        <div className="text-text-secondary text-center py-8">
          Немає інцидентів для відображення
        </div>
      </div>
    )
  }

  return (
    <div className="bg-bg-card rounded-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-text-primary text-sm font-medium">
          Таблиця інцидентів
        </h3>
        <span className="text-text-secondary text-xs">
          {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, sortedIncidents.length)} з {sortedIncidents.length}
        </span>
      </div>

      <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-bg-card">
            <tr className="border-b border-gray-700">
              <th
                className="px-3 py-2 text-left text-text-secondary cursor-pointer hover:text-text-primary"
                onClick={() => handleSort('start_ts')}
              >
                Час {sortField === 'start_ts' && (sortDir === 'asc' ? '↑' : '↓')}
              </th>
              <th className="px-3 py-2 text-left text-text-secondary">Тип</th>
              <th
                className="px-3 py-2 text-left text-text-secondary cursor-pointer hover:text-text-primary"
                onClick={() => handleSort('severity')}
              >
                Критичність
              </th>
              <th className="px-3 py-2 text-left text-text-secondary">Компонент</th>
              <th className="px-3 py-2 text-left text-text-secondary">Політика</th>
              <th className="px-3 py-2 text-right text-text-secondary">СЧОВ (с)</th>
              <th className="px-3 py-2 text-right text-text-secondary">СЧВВ (с)</th>
            </tr>
          </thead>
          <tbody>
            {paginatedIncidents.map((inc) => (
              <tr
                key={inc.incident_id}
                className="border-b border-gray-800 hover:bg-bg-secondary"
              >
                <td className="px-3 py-2 text-text-primary">
                  {formatTs(inc.start_ts)}
                </td>
                <td className="px-3 py-2 text-text-primary">
                  {inc.threat_type || inc.category || '-'}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={clsx(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      SEVERITY_COLORS[inc.severity] ?? 'text-gray-500'
                    )}
                  >
                    {inc.severity}
                  </span>
                </td>
                <td className="px-3 py-2 text-text-primary">{inc.component}</td>
                <td className="px-3 py-2 text-text-primary">{inc.policy}</td>
                <td className="px-3 py-2 text-right text-text-primary">
                  {inc.mttd_sec?.toFixed(1) ?? '-'}
                </td>
                <td className="px-3 py-2 text-right text-text-primary">
                  {inc.mttr_sec?.toFixed(1) ?? '-'}
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
