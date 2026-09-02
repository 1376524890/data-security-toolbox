import { apiGet, apiPost } from './client'
import type { PageResult } from '../types/common'

export interface Report {
  id: number
  title: string
  report_type: string
  format: string
  summary: Record<string, unknown>
  storage_path: string
  size: number
  created_at: string
}

export function listReports(query: { report_type?: string; format?: string; search?: string; page: number; page_size: number }): Promise<PageResult<Report>> {
  return apiGet('/reports', query as unknown as Record<string, unknown>)
}

export function generateReport(payload: { title: string; report_type: string; format: string }): Promise<Report> {
  return apiPost('/reports/generate', payload)
}
