import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import type { PolicyMetrics } from '../../types'

const POLICY_COLORS: Record<string, string> = {
  minimal: '#ef4444',
  baseline: '#f59e0b',
  standard: '#22c55e',
}

const POLICY_LABELS: Record<string, string> = {
  minimal: 'Мінімальний',
  baseline: 'Базова',
  standard: 'Стандартний',
}

interface AvailabilityChartProps {
  data: PolicyMetrics[]
}

export default function AvailabilityChart({ data }: AvailabilityChartProps) {
  const chartData = data.map((d) => ({
    ...d,
    label: POLICY_LABELS[d.policy] ?? d.policy,
  }))

  return (
    <div className="bg-bg-card rounded-lg p-4">
      <h3 className="text-text-primary text-sm font-medium mb-4">
        Доступність за політикою безпеки
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData} margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
          <XAxis
            dataKey="label"
            tick={{ fill: '#8b949e', fontSize: 12 }}
            axisLine={{ stroke: '#30363d' }}
            tickLine={false}
          />
          <YAxis
            domain={[95, 100]}
            tick={{ fill: '#8b949e', fontSize: 12 }}
            axisLine={{ stroke: '#30363d' }}
            tickLine={false}
            tickFormatter={(v) => `${v}%`}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#21262d',
              border: '1px solid #30363d',
              borderRadius: '6px',
            }}
            labelStyle={{ color: '#e6edf3' }}
            formatter={(value: number) => [`${value.toFixed(2)}%`, 'Доступність']}
          />
          <Bar dataKey="availability_pct" radius={[4, 4, 0, 0]}>
            {chartData.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={POLICY_COLORS[entry.policy] ?? '#6b7280'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
