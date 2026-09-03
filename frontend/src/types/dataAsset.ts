import type { DetectionFinding } from './finding'

export interface DataColumn {
  name: string
  sensitivity?: string
  detected_type?: string
  confidence?: number
  count?: number
  categories?: string[]
}

export interface DataAsset {
  id: number
  name: string
  asset_type: string
  sensitivity: string
  source: string
  columns: DataColumn[]
  extra?: Record<string, unknown>
  created_at: string
}

export interface DataAssetDetail {
  data_asset: DataAsset
  findings: DetectionFinding[]
  pii_summary: Record<string, number>
}
