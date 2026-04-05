// API Response Types

export interface Incident {
  incident_id: string
  policy: string
  category: string
  severity: string
  component: string
  start_ts: string | null
  detect_ts: string | null
  recover_ts: string | null
  mttd_sec: number | null
  mttr_sec: number | null
  status: string
  details: Record<string, unknown>
  threat_type?: string
  description?: string
  impact_score?: number
}

export interface IncidentListResponse {
  total: number
  items: Incident[]
}

export interface Action {
  action_id: string
  action: string
  target_component: string
  target_id: string | null
  ts_utc: string | null
  reason: string | null
  correlation_id: string | null
  status: string
}

export interface ActionSummary {
  total: number
  applied: number
  failed: number
  emitted: number
  pending: number
}

export interface ActionListResponse {
  total: number
  summary: ActionSummary
  items: Action[]
}

export interface ComponentState {
  component_id: string
  component_type: string
  status: string
  details: Record<string, unknown>
  last_updated: string | null
}

export interface StateResponse {
  components: ComponentState[]
}

export interface PolicyMetrics {
  policy: string
  availability_pct: number
  total_downtime_hr: number
  mean_mttd_min: number
  mean_mttr_min: number
  incident_count: number
}

export interface OverallMetrics {
  total_incidents: number
  total_actions: number
  avg_availability_pct: number
  avg_mttd_min: number
  avg_mttr_min: number
}

export interface MetricsResponse {
  by_policy: PolicyMetrics[]
  overall: OverallMetrics
}

export interface HealthResponse {
  status: string
  version: string
  timestamp: string
}

// UI Types
export type PolicyType = 'minimal' | 'baseline' | 'standard'
export type ComponentType = 'gateway' | 'api' | 'auth' | 'db' | 'network'
export type StatusType = 'healthy' | 'degraded' | 'isolated' | 'restoring' | 'corrupted' | 'disconnected'
