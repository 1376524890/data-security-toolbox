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
}
