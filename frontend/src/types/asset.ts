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

export interface AssetDetail {
  asset: Asset
  findings: unknown[]
  incidents: unknown[]
  data_assets: unknown[]
  iocs: unknown[]
  relations: Array<Record<string, string>>
}
