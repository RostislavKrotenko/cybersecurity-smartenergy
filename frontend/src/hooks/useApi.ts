import { useQuery } from '@tanstack/react-query'
import apiService from '../services/api'

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => apiService.getHealth(),
    refetchInterval: 10000,
  })
}

export function useIncidents(params?: {
  limit?: number
  severity?: string
  component?: string
  policy?: string
}) {
  return useQuery({
    queryKey: ['incidents', params],
    queryFn: () => apiService.getIncidents(params),
  })
}

export function useActions(params?: { limit?: number }) {
  return useQuery({
    queryKey: ['actions', params],
    queryFn: () => apiService.getActions(params),
  })
}

export function useStateApi() {
  return useQuery({
    queryKey: ['state'],
    queryFn: () => apiService.getState(),
  })
}

export function useMetrics() {
  return useQuery({
    queryKey: ['metrics'],
    queryFn: () => apiService.getMetrics(),
  })
}
