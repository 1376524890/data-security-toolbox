import type { Severity } from './common'
import type { Incident } from './incident'
import type { PcapRecord } from './pcap'
import type { Alert } from './alert'

export interface DetectionFinding {
  id: number
  task_id?: number | null
  target_type: string
  target_id: string
  engine: string
  rule_id: string
  severity: Severity
  confidence: number
  evidence: Record<string, unknown>
  recommendation: string
  risk_score: number
  risk_level: string
  timestamp: string
  created_at: string
}

export interface FindingDetail {
  detection: DetectionFinding
  related_incidents: Incident[]
  pcap?: PcapRecord | null
  alert?: Alert | null
}
