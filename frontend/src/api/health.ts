import { apiGet } from './client'

export interface CeleryStatus { broker: string; workers: number; running: number; queued: number }
export interface WorkerCapability { tshark?: { available: boolean; version: string; rule_count?: number }; zeek?: { available: boolean; version: string; rule_count?: number }; suricata?: { available: boolean; version: string; rule_count?: number } }

export interface HealthResponse {
  status: string
  service: string
  api: string
  database: string
  redis: string
  celery: CeleryStatus
  analysis_worker: string
  worker_capabilities: WorkerCapability[]
  tshark: { available: boolean; version: string }
  zeek: { available: boolean; version: string }
  suricata: { available: boolean; version: string; rule_count: number }
  storage_usage_bytes: number
  storage_max_bytes: number
  queue: { pending: number; running: number; oldest_pending_age: number }
  probe: { count: number; online: number; degraded: number; offline: number; auth_error: number }
}

export function getHealth(): Promise<HealthResponse> {
  return apiGet('/health')
}
