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
