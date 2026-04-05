import { useMetrics, useIncidents, useActions, useStateApi } from '../hooks/useApi'
import { PolicyKpiCard, ComponentStatusCard, ActionSummaryCard } from '../components/cards'
import { AvailabilityChart, DowntimeChart, IncidentsPerMinuteChart, ActionsPerMinuteChart } from '../components/charts'
import { IncidentTable, ActionTable } from '../components/tables'

const POLICY_ORDER = ['baseline', 'minimal', 'standard']
const BASIC_COMPONENTS = ['gateway', 'api', 'auth']

export default function Dashboard() {
  const { data: metrics, isLoading: metricsLoading } = useMetrics()
  const { data: incidents, isLoading: incidentsLoading } = useIncidents({ limit: 1000 })
  const { data: actions, isLoading: actionsLoading } = useActions({ limit: 1000 })
  const { data: state, isLoading: stateLoading } = useStateApi()

  const isLoading = metricsLoading || incidentsLoading || actionsLoading || stateLoading

  if (isLoading && !metrics && !incidents && !actions && !state) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-text-secondary">Завантаження...</div>
      </div>
    )
  }

  // Sort policies
  const sortedMetrics = metrics?.by_policy
    ? [...metrics.by_policy].sort(
        (a, b) => POLICY_ORDER.indexOf(a.policy) - POLICY_ORDER.indexOf(b.policy)
      )
    : []

  // Get component states
  const componentStates = state?.components ?? []
  const basicComponentStates = componentStates.filter((c) =>
    BASIC_COMPONENTS.includes(c.component_id)
  )
  const dbState = componentStates.find((c) => c.component_id === 'db')
  const networkState = componentStates.find((c) => c.component_id === 'network')

  const actionSummary = actions?.summary ?? {
    total: 0,
    applied: 0,
    failed: 0,
    emitted: 0,
    pending: 0,
  }

  return (
    <div className="space-y-6">
      {/* Policy KPI Cards */}
      {sortedMetrics.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {sortedMetrics.map((m) => (
            <PolicyKpiCard key={m.policy} metrics={m} />
          ))}
        </div>
      ) : (
        <div className="bg-bg-card rounded-lg p-6 text-center">
          <p className="text-text-secondary">
            <strong>Результатів ще немає.</strong> Спочатку запустіть аналіз.
          </p>
          <p className="text-text-secondary text-sm mt-2">
            Вихідні файли <code className="bg-bg-secondary px-1 rounded">out/results.csv</code> не знайдено.
          </p>
        </div>
      )}

      {/* Infrastructure Status */}
      <div>
        <h2 className="text-text-secondary text-sm font-medium mb-3">
          Стан інфраструктури (в реальному часі)
        </h2>

        {componentStates.length > 0 ? (
          <>
            {/* Row 1: Gateway, API, Auth */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              {BASIC_COMPONENTS.map((compId) => {
                const comp = basicComponentStates.find((c) => c.component_id === compId)
                if (!comp) {
                  return (
                    <ComponentStatusCard
                      key={compId}
                      component={{
                        component_id: compId,
                        component_type: '',
                        status: 'healthy',
                        details: {},
                        last_updated: null,
                      }}
                    />
                  )
                }
                return <ComponentStatusCard key={compId} component={comp} />
              })}
            </div>

            {/* Row 2: DB, Network, Actions */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <ComponentStatusCard
                component={
                  dbState ?? {
                    component_id: 'db',
                    component_type: '',
                    status: 'healthy',
                    details: {},
                    last_updated: null,
                  }
                }
              />
              <ComponentStatusCard
                component={
                  networkState ?? {
                    component_id: 'network',
                    component_type: '',
                    status: 'healthy',
                    details: {},
                    last_updated: null,
                  }
                }
              />
              <ActionSummaryCard summary={actionSummary} />
            </div>
          </>
        ) : (
          <div className="bg-bg-card rounded-lg p-6 text-center">
            <p className="text-text-secondary">
              Дані ще недоступні. Очікування оперативних даних...
            </p>
          </div>
        )}
      </div>

      {/* Charts: Availability + Downtime */}
      {sortedMetrics.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <AvailabilityChart data={sortedMetrics} />
          <DowntimeChart data={sortedMetrics} />
        </div>
      )}

      {/* Chart: Incidents per minute */}
      <IncidentsPerMinuteChart incidents={incidents?.items ?? []} />

      {/* Incident Table */}
      <IncidentTable incidents={incidents?.items ?? []} />

      {/* Chart: Actions per minute */}
      <ActionsPerMinuteChart actions={actions?.items ?? []} />

      {/* Action Table */}
      <ActionTable actions={actions?.items ?? []} />
    </div>
  )
}
