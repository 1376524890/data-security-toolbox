import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { DataAsset, DataAssetDetail } from '../types/dataAsset'

export function listDataAssets(query: { search?: string; sensitivity?: string; asset_type?: string; source?: string; page: number; page_size: number }): Promise<PageResult<DataAsset>> {
  return apiGet('/data/assets', query as unknown as Record<string, unknown>)
}

export function getDataAsset(id: number): Promise<DataAssetDetail> {
  return apiGet(`/data/assets/${id}`)
}

export interface SensitiveFindings {
  categories: Array<{ category: string; count: number; severity: string; risk_score: number }>
  details: Array<{ id: number; rule_id: string; severity: string; risk_level: string; file: string; target_id: string; counts: Record<string, number>; secret_count: number }>
  data_assets: { total: number; by_sensitivity: Record<string, number> }
}

export function getSensitiveFindings(): Promise<SensitiveFindings> {
  return apiGet('/sensitive/findings')
}
