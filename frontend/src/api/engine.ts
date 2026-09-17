import { apiGet, apiPost } from './client'

export interface EngineInfo {
  name: string
  version: string
  description?: string
  capabilities?: string[]
  /** Console route segment for this engine (``sigma`` for ``sigma_log_engine``). */
  slug?: string
  /** Human readable engine name. */
  label?: string
  /** Rule files in the platform library that this engine loads. */
  rule_count?: number
  /** The value this engine writes to ``detection_findings.engine``. */
  detection_engine?: string
  /** Findings this engine has already produced. */
  detection_count?: number
}

export function getEngineRegistry(): Promise<EngineInfo[]> {
  return apiGet('/engine/registry')
}

export interface PipelineRunInput {
  target_type?: string
  target_id?: string
  data?: Record<string, unknown>
  assets?: Array<Record<string, unknown>>
  flows?: Array<Record<string, unknown>>
  packets?: Array<Record<string, unknown>>
  metadata?: Record<string, unknown>
  log_lines?: string[]
}

export interface PipelineRunResult {
  target_type: string
  target_id?: string
  findings: Array<Record<string, unknown>>
  risk_score: number
  risk_level: string
  summary: Record<string, unknown>
}

export function runPipeline(input: PipelineRunInput): Promise<PipelineRunResult> {
  return apiPost('/engine/pipeline', input)
}
