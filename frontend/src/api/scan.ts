import { apiGet, apiPost } from './client'
import type { Task } from '../types/task'

export interface ScanRequest {
  target: string
  discovery?: boolean
  top_ports?: number
  /** Explicit TCP ports; takes precedence over top_ports when set. */
  ports?: number[]
  public_exposed?: boolean
  nuclei?: boolean
  nuclei_tags?: string
  nuclei_templates?: string
  /** Run the scan from this probe instead of the platform/worker host. */
  probe_id?: number
}

export interface ScanAsset {
  id: number
  ip: string
  port: number
  protocol: string
  service: string
  asset_type: string
  risk_level: string
}

export interface ScanResult extends Task {
  location?: 'platform' | 'probe'
  scanned_assets?: ScanAsset[]
}

export function startScan(payload: ScanRequest): Promise<Task> {
  return apiPost('/scan', payload)
}

export function getScan(taskId: number): Promise<ScanResult> {
  return apiGet(`/scan/${taskId}`)
}
