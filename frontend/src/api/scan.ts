import { apiGet, apiPost } from './client'
import type { Task } from '../types/task'

export interface ScanRequest {
  target: string
  discovery?: boolean
  top_ports?: number
  public_exposed?: boolean
}

export interface ScanResult extends Task {
  scanned_assets?: Array<{
    id: number
    ip: string
    port: number
    service: string
    asset_type: string
    risk_level: string
  }>
}

export function startScan(payload: ScanRequest): Promise<Task> {
  return apiPost('/scan', payload)
}

export function getScan(taskId: number): Promise<ScanResult> {
  return apiGet(`/scan/${taskId}`)
}
