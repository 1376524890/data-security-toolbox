import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { Flow } from '../types/pcap'

export interface LiveNetwork {
  window_seconds: number
  probes: { online: number; degraded: number; total: number }
  connections: number
  packets: number
  bytes: number
  pps: number
  bps: number
  avg_cpu_percent: number
  avg_memory_percent: number
  top_src: Array<{ ip: string; bytes: number }>
  top_dst: Array<{ ip: string; bytes: number }>
  top_port: Array<{ port: number; bytes: number }>
  alerts_30m: number
}

export function getGlobalFlows(query: { search?: string; ip?: string; protocol?: string; port?: number; page: number; page_size: number }): Promise<PageResult<Flow>> {
  return apiGet('/flows', query as unknown as Record<string, unknown>)
}

export function getGlobalProtocols(): Promise<Array<{ name: string; count: number; bytes: number }>> {
  return apiGet('/protocols')
}

export function getLiveNetwork(): Promise<LiveNetwork> {
  return apiGet('/network/live')
}
