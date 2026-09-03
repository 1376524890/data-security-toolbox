import { API_BASE, apiGet, apiPatch } from './client'
import type { PageResult } from '../types/common'
import type { Alert, AlertDetail, AlertSummary } from '../types/alert'

export interface AlertQuery {
  status?: string
  severity?: string
  source?: string
  probe_id?: number
  start?: string
  end?: string
  search?: string
  page: number
  page_size: number
}

export function listAlerts(query: AlertQuery): Promise<PageResult<Alert>> {
  return apiGet('/alerts', query as unknown as Record<string, unknown>)
}

export function getAlert(id: number): Promise<AlertDetail> {
  return apiGet(`/alerts/${id}`)
}

export function getAlertSummary(): Promise<AlertSummary> {
  return apiGet('/alerts/summary')
}

export function updateAlert(id: number, payload: { status?: string; severity?: string; summary?: string }): Promise<Alert> {
  return apiPatch(`/alerts/${id}`, payload)
}

export function alertStreamUrl(): string {
  return `${API_BASE}/alerts/stream`
}
