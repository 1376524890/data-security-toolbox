import type { DetectionFinding } from './finding'
import type { Incident } from './incident'
import type { DataAsset } from './dataAsset'
import type { Ioc } from './ioc'

export interface Asset {
  id: number
  probe_id?: number | null
  ip: string
  hostname: string
  os: string
  port: number
  protocol: string
  service: string
  asset_type: string
  risk_level: string
  sensitive_categories: string[]
  metadata?: Record<string, unknown>
  first_seen?: string
  last_seen?: string
}

export interface AssetRelation { source_node: string; source_type: string; target_node: string; target_type: string; relation: string; risk: string }

export interface AssetDetail {
  asset: Asset
  findings: DetectionFinding[]
  incidents: Incident[]
  data_assets: DataAsset[]
  iocs: Ioc[]
  relations: AssetRelation[]
}
