import { apiGet, apiPatch, apiPost } from './client'
import type { PageResult } from '../types/common'
import type { Incident, IncidentFilters } from '../types/incident'

export function listIncidents(query: IncidentFilters): Promise<PageResult<Incident>> {
  return apiGet('/incidents', query as unknown as Record<string, unknown>)
}

export function getIncident(id: number): Promise<Incident> {
  return apiGet(`/incidents/${id}`)
}

export function updateIncidentStatus(id: number, status: string): Promise<Incident> {
  return apiPatch(`/incidents/${id}`, { status })
}

export function correlateIncidents(findings: Array<Record<string, unknown>>, windowSeconds = 3600): Promise<Array<Record<string, unknown>>> {
  return apiPost('/incidents/correlate', { findings, window_seconds: windowSeconds })
}
