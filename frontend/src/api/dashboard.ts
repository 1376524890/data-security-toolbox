import { apiGet } from './client'
import type { DashboardItems, DashboardSummary, RiskTrendResponse } from '../types/dashboard'
import type { Incident } from '../types/incident'
import type { Asset } from '../types/asset'

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
