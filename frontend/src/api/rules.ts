import { apiGet } from './client'

export interface RuleItem {
  type: string
  /** Internal name of the engine that loads this rule file. */
  engine: string
  name: string
  path: string
  content: string
  size: number
}

export interface RuleQuery {
  type?: 'sigma' | 'suricata' | 'yara'
  engine?: string
}

export function listRules(query: RuleQuery = {}): Promise<{ items: RuleItem[]; total: number }> {
  const params: Record<string, unknown> = {}
  if (query.type) params.rule_type = query.type
  if (query.engine) params.engine = query.engine
  return apiGet('/rules', params)
}
