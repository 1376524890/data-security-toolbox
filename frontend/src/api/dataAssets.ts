import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { DataAsset, DataAssetDetail } from '../types/dataAsset'

export interface DataAssetQuery {
  search?: string
  sensitivity?: string
  asset_type?: string
  source?: string
  probe_id?: number
  /** `field` ascending, `-field` descending; see `useTableSort`. */
  order_by?: string
  page: number
  page_size: number
}

export function listDataAssets(query: DataAssetQuery): Promise<PageResult<DataAsset>> {
  return apiGet('/data/assets', query as unknown as Record<string, unknown>)
}

export function getDataAsset(id: number): Promise<DataAssetDetail> {
  return apiGet(`/data/assets/${id}`)
}
