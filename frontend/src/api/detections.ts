import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { DetectionFinding, FindingDetail } from '../types/finding'

export interface DetectionQuery {
  severity?: string
  engine?: string
  risk_level?: string
  target_type?: string
  target_id?: string
  search?: string
  start_time?: string
  end_time?: string
  page: number
  page_size: number
}

export function listDetections(query: DetectionQuery): Promise<PageResult<DetectionFinding>> {
  return apiGet('/detections', query as unknown as Record<string, unknown>)
}

export function getDetection(id: number): Promise<FindingDetail> {
  return apiGet(`/detections/${id}`)
}
