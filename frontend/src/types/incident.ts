import type { Severity } from './common'
import type { DetectionFinding } from './finding'

export interface Incident {
  id: number
  title: string
  severity: Severity
  confidence: number
  status: string
  findings: { items?: DetectionFinding[] }
  evidence: Record<string, unknown>
  risk_score: number
  risk_level: string
  timestamp: string
  created_at: string
  updated_at?: string
}

export interface IncidentFilters {
  severity?: string
  status?: string
  search?: string
  start_time?: string
  end_time?: string
  page: number
  page_size: number
}
