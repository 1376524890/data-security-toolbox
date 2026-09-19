import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { DataAsset, DataAssetDetail } from '../types/dataAsset'

export interface DataAssetQuery {
  search?: string
  sensitivity?: string
  asset_type?: string
  source?: string
  probe_id?: number
  page: number
  page_size: number
}

export function listDataAssets(query: DataAssetQuery): Promise<PageResult<DataAsset>> {
  return apiGet('/data/assets', query as unknown as Record<string, unknown>)
}

export function getDataAsset(id: number): Promise<DataAssetDetail> {
  return apiGet(`/data/assets/${id}`)
}

export interface SensitiveFindings {
  categories: Array<{ category: string; count: number; severity: string; risk_score: number }>
  entities: Array<{ category: string; count: number }>
  details: Array<{
    id: number
    engine: string
    rule_id: string
    severity: string
    risk_level: string
    risk_score: number
    file: string
    target_id: string
    counts: Record<string, number>
    secret_count: number
  }>
  sources: Array<{ source: string; kind: string; count: number }>
  totals: {
    findings: number
    categories: number
    entities: number
    objects: number
    instances: number
    detections: number
    data_assets: number
  }
  pagination: { page: number; page_size: number; total: number; pages: number }
  note: string
  data_assets: {
    total: number
    by_sensitivity: Record<string, number>
    observed: { total: number; by_sensitivity: Record<string, number> }
    not_observed: { total: number; by_sensitivity: Record<string, number> }
  }
}

export function getSensitiveFindings(query: { page?: number; page_size?: number } = {}): Promise<SensitiveFindings> {
  return apiGet('/sensitive/findings', query as Record<string, unknown>)
}
