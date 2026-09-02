import { apiGet, apiUpload } from './client'
import type { LocalCve, OfflineResource } from '../types/offline'

export interface OfflineImportResult {
  imported: number
  duplicates: number
  categories: Record<string, number>
  resources: Array<{ type: string; name: string; version: string; file: string }>
  manifest: Record<string, unknown>
  errors: string[]
}

export function listOfflineResources(): Promise<OfflineResource[]> {
  return apiGet('/offline/resources')
}

export function uploadOffline(file: File, resourceType: string, name?: string, version?: string): Promise<OfflineImportResult> {
  return apiUpload('/integrations/offline/upload', file, { resource_type: resourceType, name: name || '', version: version || '' })
}

export function listLocalCves(search = ''): Promise<LocalCve[]> {
  return apiGet('/offline/cves', { search })
}
