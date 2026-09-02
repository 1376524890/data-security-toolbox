import { apiGet, apiPatch } from './client'
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
