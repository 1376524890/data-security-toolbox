import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { DataAsset, DataAssetDetail } from '../types/dataAsset'

export function listDataAssets(query: { search?: string; sensitivity?: string; asset_type?: string; source?: string; page: number; page_size: number }): Promise<PageResult<DataAsset>> {
  return apiGet('/data/assets', query as unknown as Record<string, unknown>)
}

export function getDataAsset(id: number): Promise<DataAssetDetail> {
  return apiGet(`/data/assets/${id}`)
}
