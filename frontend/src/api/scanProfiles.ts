import { apiGet, apiPatch, apiPost } from './client'
import client from './client'
import type { PageResult } from '../types/common'

/**
 * ScanProfile CRUD plus profile-driven collection jobs.
 *
 * `enabled` only means "usable for a job"; it never turns scheduled collection
 * on. `scheduled`/`interval_seconds` are stored for the future and the probe's
 * own `[data].enabled` remains the switch that decides whether the host scans at
 * all, so nothing here changes a probe's release default.
 */
export interface ScanProfile {
  id: number
  name: string
  version: number
  description: string
  include_paths: string[]
  exclude_paths: string[]
  file_types: string[]
  max_files: number
  max_dirs: number
  max_depth: number
  max_runtime_seconds: number
  max_bytes_read: number
  max_single_file_size: number
  max_full_hash_size: number
  large_file_sampling: boolean
  sample_block_size: number
  max_sample_rows: number
  max_cpu_seconds: number
  max_rss_mb: number
  xlsx_max_entries: number
  xlsx_max_uncompressed_bytes: number
  xlsx_max_compression_ratio: number
  xlsx_max_shared_strings: number
  xlsx_max_sheets: number
  xlsx_max_columns: number
  xlsx_max_rows: number
  enabled: boolean
  scheduled: boolean
  interval_seconds: number
  created_by: string
  created_at: string
  updated_at: string
}

export type ScanProfileDraft = Omit<ScanProfile, 'id' | 'version' | 'created_by' | 'created_at' | 'updated_at'>

export function listScanProfiles(query: { page: number; page_size: number; enabled?: boolean; name?: string }):
  Promise<PageResult<ScanProfile>> {
  return apiGet('/scan-profiles', query as unknown as Record<string, unknown>)
}

export function createScanProfile(payload: Partial<ScanProfileDraft>): Promise<ScanProfile> {
  return apiPost('/scan-profiles', payload)
}

export function updateScanProfile(id: number, payload: Partial<ScanProfileDraft>): Promise<ScanProfile> {
  return apiPatch(`/scan-profiles/${id}`, payload)
}

export async function deleteScanProfile(id: number): Promise<void> {
  await client.delete(`/scan-profiles/${id}`)
}

export function runScanProfile(id: number, probeId: number): Promise<{ id: number; status: string }> {
  return apiPost(`/scan-profiles/${id}/run`, { probe_id: probeId })
}

/** The probe-side data-asset job API the legacy pages also use. */
export function queueDataAssetJob(probeId: number, payload: Record<string, unknown>):
  Promise<{ id: number; status: string }> {
  return apiPost(`/probes/${probeId}/data-assets/jobs`, payload)
}
