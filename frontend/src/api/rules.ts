import { apiGet } from './client'

export interface RuleItem {
  type: string
  name: string
  path: string
  content: string
  size: number
}

export function listRules(type?: 'sigma' | 'suricata' | 'yara'): Promise<{ items: RuleItem[]; total: number }> {
  return apiGet('/rules', type ? { type } : {})
}
