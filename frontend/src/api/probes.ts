import { apiGet, apiPost } from './client'
import type { PageResult } from '../types/common'
import type { Task } from '../types/task'

export interface Probe {
  id: number
  name: string
  hostname: string
  ip_address: string
  status: string
  last_seen?: string | null
  metadata: Record<string, unknown>
  created_at: string
}

export interface ProbeRegisterPayload {
  name: string
  hostname: string
  ip_address: string
  metadata?: Record<string, unknown>
}

export function listProbes(query: { search?: string; status?: string; page: number; page_size: number }): Promise<PageResult<Probe>> {
  return apiGet('/probes', query as unknown as Record<string, unknown>)
}

export function registerProbe(payload: ProbeRegisterPayload): Promise<{ id: number; name: string }> {
  return apiPost('/probes/register', payload)
}

export function analyzeProbe(id: number): Promise<Task> {
  return apiPost(`/probes/${id}/analyze`)
}

export function getProbeTasks(id: number): Promise<Task[]> {
  return apiGet(`/probes/${id}/tasks`)
}

export interface ProbeMetrics {
  probe: Probe
  system: Record<string, unknown>
  cpu_percent?: number
  memory_percent?: number
  memory_rss_mb?: number
  capture_status: string
  upload_status: string
  capture_tool: string
  spool_size_mb: number
  pending_segments: number
  quarantined_segments: number
  drop_rate?: number | null
  last_capture: string
  last_upload: string
  last_seen: string | null
}

export function getProbeMetrics(id: number): Promise<ProbeMetrics> {
  return apiGet(`/probes/${id}/metrics`)
}
