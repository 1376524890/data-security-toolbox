export interface DashboardSummary {
  assets: number
  files: number
  pcaps: number
  anomalies: number
  tasks: number
  reports: number
  probes: number
  incidents: number
  iocs: number
  alerts: number
  open_alerts: number
  high_risk_findings: number
  open_incidents: number
  high_risk_assets: number
  sensitive_data_assets: number
  online_probes: number
  healthy_integrations: number
}

export interface TrendPoint {
  time: string
  risk_score: number
  count: number
  critical: number
  high: number
}

export interface RiskTrendResponse {
  range: string
  items: TrendPoint[]
}

export interface NameCount {
  name: string
  value: number
}

export interface DashboardItems<T> {
  items: T[]
}
