import axios from 'axios'
import type {
  IncidentListResponse,
  ActionListResponse,
  StateResponse,
  MetricsResponse,
  HealthResponse,
} from '../types'

const API_BASE = '/api'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
})

export const apiService = {
  // Health
  async getHealth(): Promise<HealthResponse> {
    const { data } = await api.get<HealthResponse>('/health')
    return data
  },

  // Incidents
  async getIncidents(params?: {
    limit?: number
    severity?: string
    component?: string
    policy?: string
  }): Promise<IncidentListResponse> {
    const { data } = await api.get<IncidentListResponse>('/incidents', { params })
    return data
  },

  async getIncidentsCount(): Promise<number> {
    const { data } = await api.get<{ count: number }>('/incidents/count')
    return data.count
  },

  // Actions
  async getActions(params?: { limit?: number }): Promise<ActionListResponse> {
    const { data } = await api.get<ActionListResponse>('/actions', { params })
    return data
  },

  // State
  async getState(): Promise<StateResponse> {
    const { data } = await api.get<StateResponse>('/state')
    return data
  },

  async getComponentState(componentId: string): Promise<StateResponse['components'][0] | null> {
    try {
      const { data } = await api.get(`/state/components/${componentId}`)
      return data
    } catch {
      return null
    }
  },

  // Metrics
  async getMetrics(): Promise<MetricsResponse> {
    const { data } = await api.get<MetricsResponse>('/metrics')
    return data
  },
}

export default apiService
