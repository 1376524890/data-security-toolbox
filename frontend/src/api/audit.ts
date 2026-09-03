import { apiGet, apiPost } from './client'

export interface LogAnalysisResult {
  log_summary: Record<string, unknown>
  findings: Array<Record<string, unknown>>
  risk: { score: number; level: string }
}

export function analyzeLog(content: string): Promise<LogAnalysisResult> {
  return apiPost('/audit/logs', { content })
}

export function getAuditSummary(): Promise<Record<string, unknown>> {
  return apiGet('/audit/summary')
}
