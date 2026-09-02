import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { Asset, AssetDetail } from '../types/asset'

export interface AssetQuery {
  risk?: string
  asset_type?: string
  ip?: string
  hostname?: string
  probe_id?: number
  search?: string
  page: number
  page_size: number
}

export function listAssets(query: AssetQuery): Promise<PageResult<Asset>> {
  return apiGet('/assets', query as unknown as Record<string, unknown>)
}

export function getAsset(id: number): Promise<AssetDetail> {
  return apiGet(`/assets/${id}`)
}
