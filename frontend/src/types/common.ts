export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type TaskStatus = 'Pending' | 'Running' | 'Success' | 'Failed'
export type IntegrationStatus = 'ready' | 'disabled' | 'unavailable' | 'error'

export interface PageResult<T> {
  items: T[]
  page: number
  page_size: number
  total: number
}

export interface ApiError {
  detail?: string
  message?: string
}

export interface HealthResponse {
  status: string
  service: string
  database?: string
  redis?: string
  celery?: { running: number; queued: number }
  analysis_worker?: string
  tshark?: boolean
  zeek?: boolean
  suricata?: boolean
  storage_usage_bytes?: number
  storage_max_bytes?: number
  queue?: { pending: number; running: number; oldest_pending_age: number }
  probe_count?: number
  offline_probe_count?: number
}
