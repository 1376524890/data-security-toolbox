import type { Severity } from './common'
import type { DetectionFinding } from './finding'

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type AttackStage = 'recon' | 'exploit' | 'credential' | 'c2' | 'exfil' | 'impact' | 'unknown'

export interface Incident {
  id: number
  fingerprint?: string
  probe_id?: number | null
  source?: string
  title: string
  severity: Severity
  confidence: number
  status: string
  findings: { items?: DetectionFinding[] }
  evidence: Record<string, unknown>
  risk_score: number
  risk_level: string
  timestamp: string
  last_seen?: string
  occurrence_count?: number
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

export function incidentStages(incident: Incident): AttackStage[] {
  const stages = incident.evidence?.stages
  if (Array.isArray(stages)) return stages.map(String) as AttackStage[]
  return []
}
