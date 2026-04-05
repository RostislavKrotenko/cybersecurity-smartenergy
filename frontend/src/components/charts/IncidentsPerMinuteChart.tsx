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
import type { Incident } from '../../types'

interface IncidentsPerMinuteChartProps {
  incidents: Incident[]
}

export default function IncidentsPerMinuteChart({ incidents }: IncidentsPerMinuteChartProps) {
  const chartData = useMemo(() => {
    if (!incidents.length) return []

    const minuteCounts: Record<string, number> = {}

    incidents.forEach((inc) => {
      const ts = inc.start_ts || inc.detect_ts
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
  }, [incidents])

  if (!chartData.length) {
    return (
      <div className="bg-bg-card rounded-lg p-4">
        <h3 className="text-text-primary text-sm font-medium mb-4">
          Інцидентів за хвилину
        </h3>
        <div className="h-[300px] flex items-center justify-center text-text-secondary">
          Недостатньо даних
        </div>
      </div>
    )
  }

  return (
    <div className="bg-bg-card rounded-lg p-4">
      <h3 className="text-text-primary text-sm font-medium mb-4">
        Інцидентів за хвилину
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
            formatter={(value: number) => [value, 'Інцидентів']}
          />
          <Line
            type="monotone"
            dataKey="count"
            stroke="#8b5cf6"
            strokeWidth={2}
            dot={{ fill: '#8b5cf6', r: 4 }}
            activeDot={{ fill: '#8b5cf6', r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
