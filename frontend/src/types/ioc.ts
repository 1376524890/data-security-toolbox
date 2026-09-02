export interface Ioc {
  id: number
  type: string
  value: string
  source: string
  first_seen: string
  last_seen: string
  tags: string[]
  metadata?: Record<string, unknown>
  created_at: string
}

export interface IocAssociation {
  ioc: Ioc
  findings: unknown[]
  incidents: unknown[]
  assets: unknown[]
}
