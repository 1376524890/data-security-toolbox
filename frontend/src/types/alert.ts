import type { Severity } from './common'
import type { DetectionFinding } from './finding'
import type { Incident } from './incident'
import type { PcapRecord } from './pcap'

export interface Alert {
  id: number
  fingerprint: string
  finding_id?: number | null
  incident_id?: number | null
  probe_id?: number | null
  severity: Severity
  risk_score: number
  title: string
  summary: string
  status: 'new' | 'acknowledged' | 'resolved' | 'suppressed'
  first_seen: string
  last_seen: string
  occurrence_count: number
  source: string
  created_at: string
  updated_at: string
}

export interface AlertDetail {
  alert: Alert
  finding?: DetectionFinding | null
  incident?: Incident | null
  probe?: { id: number; name: string; ip_address: string; status: string } | null
  pcap?: PcapRecord | null
  deliveries: Array<{ id: number; channel: string; target: string; status: string; attempts: number; last_error: string; sent_at?: string | null }>
}

export interface AlertSummary {
  total: number
  status: Record<string, number>
  severity: Record<string, number>
  unhandled_critical_high: number
}
