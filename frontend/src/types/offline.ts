export interface OfflineResource {
  id: number
  resource_type: string
  name: string
  version: string
  count: number
  status: string
  storage_path: string
  manifest_path: string
  resource_metadata: Record<string, unknown>
  imported_at: string
}

export interface LocalCve {
  cve_id: string
  source: string
  severity: string
  cvss_score: number
  published: string
  modified: string
  description: Record<string, unknown> | string
}
