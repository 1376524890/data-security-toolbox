import { apiGet, apiPost } from './client'

export interface EgressPolicy {
  whitelist: string[]
  blacklist: string[]
  internal_cidrs: string[]
  region_table_present: boolean
  table_path: string
}

export function getEgressPolicy(): Promise<EgressPolicy> {
  return apiGet<EgressPolicy>('/egress/policy')
}

export function saveEgressPolicy(payload: Pick<EgressPolicy, 'whitelist' | 'blacklist' |
  'internal_cidrs'>): Promise<Pick<EgressPolicy, 'whitelist' | 'blacklist' | 'internal_cidrs'>> {
  return apiPost('/egress/policy', payload)
}
