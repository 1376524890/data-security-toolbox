export interface PcapRecord {
  id: number
  probe_id?: number | null
  filename: string
  size: number
  sha256: string
  packet_count: number
  duration: number
  capture_start: string
  capture_end: string
  protocol_summary: Record<string, number>
  status: string
  created_at: string
}

export interface Flow {
  id: number
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: string
  app_protocol: string
  packets: number
  bytes: number
  start_time: number
  end_time: number
}

export interface Packet {
  id: number
  number: number
  timestamp: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  length: number
  info: string
}

export interface AlertItem {
  kind: 'anomaly' | 'finding' | 'external'
  severity: string
  title: string
  description: string
  evidence: Record<string, unknown>
  source: string
  id?: number
}

export interface TrafficOverview {
  trend: Array<Record<string, number>>
  top_n: Flow[]
  protocols: Record<string, number>
  hosts: Array<Record<string, unknown>>
  anomalies: Array<Record<string, unknown>>
}
