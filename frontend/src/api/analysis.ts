import { apiGet } from './client'

export interface AnalysisResult {
  id: number
  task_id: number
  module: string
  content: Record<string, unknown>
  score: number
  risk_level: string
  created_at: string
}

export function getAnalysisResults(module?: string): Promise<AnalysisResult[]> {
  return apiGet('/analysis/results', module ? { module } : {})
}
