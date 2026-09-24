import { apiGet, apiPost, apiUpload } from './client'
import type { PageResult } from '../types/common'

/** One CVE rule in the local library. ``description`` is the stored JSON: the
 *  text plus, when the source published them, the product and the affected
 *  version interval the fingerprint match is confirmed against. */
export interface LocalCve {
  cve_id: string
  source: string
  severity: string
  cvss_score: number
  published: string
  modified: string
  description: string | { text?: string; product?: string; affected_versions?: string[] }
}

export interface CveSyncResult {
  keywords: string[]
  imported: number
  updated: number
  errors: string[]
}

export interface CveSyncPreview {
  fingerprints: string[]
}

export interface LibraryJob {
  id: string
  status: string
  stage?: string
  downloaded_bytes?: number
  imported?: number
  updated?: number
  error?: string
  result?: { imported: number; updated: number; preserved: number; version: string }
}

export interface OfflineImportResult {
  imported: number
  duplicates: number
  errors: string[]
}

export interface CveQuery {
  search?: string
  severity?: string
  source?: string
  /** `field` ascending, `-field` descending; see `useTableSort`. */
  order_by?: string
  page?: number
  page_size?: number
}

export function listLocalCves(
  search = '', page = 1, pageSize = 50, options: Omit<CveQuery, 'search' | 'page' | 'page_size'> = {},
): Promise<PageResult<LocalCve>> {
  return apiGet('/offline/cves', {
    search, page, page_size: pageSize,
    severity: options.severity || undefined,
    source: options.source || undefined,
    order_by: options.order_by || undefined,
  })
}

/** The products an online update would query NVD for: shown before the call so
 *  the operator sees the scope instead of firing an unbounded update. */
export function cveSyncPreview(): Promise<CveSyncPreview> {
  return apiGet('/offline/cves/fingerprints')
}

export function syncCves(keywords: string[] = []): Promise<CveSyncResult> {
  return apiPost('/offline/cves/sync', { keywords })
}

export function addCve(payload: {
  cve_id: string; severity: string; cvss_score: number; description: string
}): Promise<{ cve_id: string }> {
  return apiPost('/offline/cves', payload)
}

/** Manual import of a JSON/CSV/YAML CVE bundle (the offline path). */
export function importCveFile(file: File): Promise<OfflineImportResult> {
  return apiUpload('/integrations/offline/upload', file, { resource_type: 'cve' })
}

export function updateGrypeLibrary(): Promise<LibraryJob> {
  return apiPost('/offline/grype/update')
}

export function importGrypeLibrary(file: File): Promise<LibraryJob> {
  return apiUpload('/offline/grype/import', file, undefined, { timeout: 1800000 })
}

export function grypeJob(identifier: string): Promise<LibraryJob> {
  return apiGet(`/offline/grype/jobs/${identifier}`)
}
