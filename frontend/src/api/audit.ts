import { apiGet, apiPost } from './client'

export interface LogMatchGroups {
  auth_failure?: string[]
  sql_error?: string[]
  port_scan?: string[]
  privilege?: string[]
  traversal?: string[]
}

export interface LogSummary {
  line_count: number
  matches: LogMatchGroups
}

export interface AuditFinding {
  engine: string
  rule_id: string
  severity: string
  confidence: number
  evidence: Record<string, unknown>
  recommendation?: string
  risk_score: number
  risk_level: string
  timestamp?: string
}

export interface LogAnalysisResult {
  log_summary: LogSummary
  findings: AuditFinding[]
  risk: { score: number; level: string }
}

export interface LeakRisk {
  risk_level: string
  protocols: Record<string, number>
  high_risk_protocols: string[]
}

export interface AuditSummary {
  assets: number
  asset_risk: Record<string, number>
  files: number
  file_risk: Record<string, number>
  pcaps: number
  anomalies: number
  anomaly_severity: Record<string, number>
  leak_risk: LeakRisk
}

export function analyzeLog(content: string): Promise<LogAnalysisResult> {
  return apiPost('/audit/logs', { content })
}

export function getAuditSummary(): Promise<AuditSummary> {
  return apiGet('/audit/summary')
}
