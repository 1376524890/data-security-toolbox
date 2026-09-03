import { apiGet } from './client'

export interface RiskSummary {
  count: number
  risk_levels: Record<string, number>
  engines: Record<string, number>
  asset_risk: Record<string, number>
  data_sensitivity: Record<string, number>
  max_score: number
  avg_score: number
}

export function getRiskSummary(): Promise<RiskSummary> {
  return apiGet('/risk/summary')
}
