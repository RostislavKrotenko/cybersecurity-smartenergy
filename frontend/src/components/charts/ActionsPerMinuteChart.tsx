import { useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { format, parseISO } from 'date-fns'
import type { Action } from '../../types'

interface ActionsPerMinuteChartProps {
  actions: Action[]
}

export default function ActionsPerMinuteChart({ actions }: ActionsPerMinuteChartProps) {
  const chartData = useMemo(() => {
    if (!actions.length) return []

    const minuteCounts: Record<string, number> = {}

    actions.forEach((act) => {
      const ts = act.ts_utc
      if (!ts) return
      try {
        const date = parseISO(ts)
        const minute = format(date, 'yyyy-MM-dd HH:mm')
        minuteCounts[minute] = (minuteCounts[minute] || 0) + 1
      } catch {
        // skip invalid dates
      }
    })

    return Object.entries(minuteCounts)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([minute, count]) => ({
        minute,
        time: format(parseISO(minute), 'HH:mm'),
        count,
      }))
  }, [actions])

  if (!chartData.length) {
    return (
      <div className="bg-bg-card rounded-lg p-4">
        <h3 className="text-text-primary text-sm font-medium mb-4">
          Дій за хвилину (замкнений цикл)
        </h3>
        <div className="h-[300px] flex items-center justify-center text-text-secondary">
          Дії ще не надіслано
        </div>
      </div>
    )
  }

  return (
    <div className="bg-bg-card rounded-lg p-4">
      <h3 className="text-text-primary text-sm font-medium mb-4">
        Дій за хвилину (замкнений цикл)
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={chartData} margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
          <XAxis
            dataKey="time"
            tick={{ fill: '#8b949e', fontSize: 12 }}
            axisLine={{ stroke: '#30363d' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: '#8b949e', fontSize: 12 }}
            axisLine={{ stroke: '#30363d' }}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#21262d',
              border: '1px solid #30363d',
              borderRadius: '6px',
            }}
            labelStyle={{ color: '#e6edf3' }}
            formatter={(value: number) => [value, 'Дій']}
          />
          <Line
            type="monotone"
            dataKey="count"
            stroke="#10b981"
            strokeWidth={2}
            dot={{ fill: '#10b981', r: 4 }}
            activeDot={{ fill: '#10b981', r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
