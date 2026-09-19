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
  probe_id?: number | null
  probe?: string
  host?: string
  path?: string
  size?: number
  categories?: string[]
  status?: string
  observed_at?: string
  extra?: Record<string, unknown>
  created_at: string
}

export interface DataAssetDetail {
  data_asset: DataAsset
  findings: DetectionFinding[]
  /** Sensitive field count per category (legacy shape). */
  pii_summary: Record<string, number>
  /** Fields and sample hits are different units; both are reported. */
  pii_summary_detail?: Record<string, { fields: number; sample_hits: number }>
  summary?: {
    asset_type?: string
    sensitive_field_count?: number
    sample_hits?: number
    units?: string
    note?: string
  }
}
