import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { Asset } from '../types/asset'

/** One CVE hit the threat-intel engine matched against a scanned service. */
export interface ServiceCve {
  rule_id: string
  cve_id: string
  severity: string
  cvss_score: number
  confidence: number
  confirmed: boolean
  match_reason: string
  library_source: string
  recommendation: string
  finding_id: number
}

/** A scanned port: the service fingerprint plus what it matched. */
export interface NetworkAsset extends Asset {
  source: string
  product: string
  version: string
  banner: string
  tls: Record<string, unknown>
  public_exposed: boolean
  cves: ServiceCve[]
  cve_count: number
  confirmed_cve_count: number
  max_cvss: number
}

export interface NetworkAssetSummary {
  assets: number
  hosts: number
  services: number
  vulnerable_hosts: number
  cves: number
  confirmed_hits: number
  by_severity: Array<{ severity: string; count: number }>
  sources: string[]
}

export interface NetworkAssetQuery {
  search?: string
  severity?: string
  only_vulnerable?: boolean
  source?: string
  /** `field` ascending, `-field` descending; see `useTableSort`. */
  order_by?: string
  page?: number
  page_size?: number
}

export function listNetworkAssets(query: NetworkAssetQuery = {}): Promise<PageResult<NetworkAsset>> {
  return apiGet('/network/assets', { ...query })
}

export function getNetworkAssetSummary(): Promise<NetworkAssetSummary> {
  return apiGet('/network/assets/summary')
}
