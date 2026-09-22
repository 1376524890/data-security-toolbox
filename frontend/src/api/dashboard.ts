import { apiGet } from './client'
import { listAlerts } from './alerts'
import type {
  CockpitOverview, CockpitTrend, DashboardItems, DashboardOverview, DashboardSummary,
  DetectionTrendPoint, RiskDistribution, RiskTrendResponse, TrafficFlow,
} from '../types/dashboard'
import type { Alert } from '../types/alert'
import type { PageResult } from '../types/common'
import type { Incident } from '../types/incident'
import type { Asset } from '../types/asset'
import type { Task } from '../types/task'
import type { Probe } from './probes'

export function getDashboardSummary(): Promise<DashboardSummary> {
  return apiGet('/dashboard/summary')
}

export function getRiskTrend(range: '24h' | '7d' = '7d'): Promise<RiskTrendResponse> {
  return apiGet('/dashboard/risk-trend', { range })
}

export function getDashboardSeverity(): Promise<{ items: Array<{ severity: string; count: number }> }> {
  return apiGet('/dashboard/severity')
}

export function getDashboardEngines(): Promise<{ items: Array<{ engine: string; count: number }> }> {
  return apiGet('/dashboard/engines')
}

export function getDashboardIncidents(): Promise<DashboardItems<Incident>> {
  return apiGet('/dashboard/incidents', { limit: 10 })
}

export function getHighRiskAssets(): Promise<DashboardItems<Asset>> {
  return apiGet('/dashboard/high-risk-assets', { limit: 10 })
}

export function getSensitiveData(): Promise<{ items: Array<{ category: string; count: number }> }> {
  return apiGet('/dashboard/sensitive-data')
}

export function getIncidentTrend(range: '24h' | '7d' = '7d'): Promise<{ range: string; items: Array<{ time: string; count: number; critical: number; high: number; medium: number; risk_score: number }> }> {
  return apiGet('/dashboard/incident-trend', { range })
}

// ---------------------------------------------------------------------------
// 数据安全态势大屏
//
// The screen's four reads plus the two list reads it reuses: every number on
// the page comes from one of these, so there is a single place to look when a
// figure on the wall disagrees with the console.
// ---------------------------------------------------------------------------

export function getDashboardOverview(): Promise<DashboardOverview> {
  return apiGet('/dashboard/overview')
}

/** The cockpit half of the same response. Both homepages read one endpoint so
    they can never disagree about a number; the two wrappers only say which part
    of the payload the calling page models. */
export function getCockpitOverview(): Promise<CockpitOverview> {
  return apiGet('/dashboard/overview')
}

export function getTrafficFlow(params: { limit?: number; days?: number } = {}): Promise<TrafficFlow> {
  return apiGet('/dashboard/traffic-flow', { limit: 18, days: 7, ...params })
}

export function getRiskDistribution(): Promise<RiskDistribution> {
  return apiGet('/dashboard/risk-distribution')
}

export function getDetectionTrend(range: '24h' | '7d' = '7d'): Promise<{ range: string; items: DetectionTrendPoint[] }> {
  return apiGet('/dashboard/detection-trend', { range })
}

/**
 * Probe rows for the health card. The counts stay on the overview: the 90 s
 * heartbeat rule that decides online/offline lives on the server, so the client
 * never re-derives a status from ``last_seen``.
 */
export function getProbeStatus(): Promise<PageResult<Probe>> {
  return apiGet('/probes', { page: 1, page_size: 100 })
}

/** Newest alerts first — the order the console's list endpoint needs a hint for. */
export async function getRecentAlerts(limit = 20): Promise<Alert[]> {
  const page = await listAlerts({ page: 1, page_size: limit, order: 'recent' })
  return page.items
}

// ---------------------------------------------------------------------------
// 数据安全综合驾驶舱
//
// Three reads: the KPI band + posture + compliance (the overview endpoint the
// wall screen also uses, whose cockpit half is additive), the daily trend and
// the recent task rows.
// ---------------------------------------------------------------------------

export function getCockpitTrend(range: '24h' | '7d' = '7d'): Promise<CockpitTrend> {
  return apiGet('/dashboard/trend', { range })
}

export function getCockpitTasks(limit = 8): Promise<{ items: Task[] }> {
  return apiGet('/dashboard/tasks', { limit })
}
