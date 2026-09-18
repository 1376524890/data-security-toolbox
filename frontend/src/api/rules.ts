import { apiGet } from './client'

export interface RuleItem {
  type: string
  /** Internal name of the engine that loads this rule file. */
  engine: string
  name: string
  path: string
  content: string
  size: number
  rule_id?: string
  execution?: 'active' | 'external' | 'unsupported' | 'incomplete'
}

export interface RuleQuery {
  type?: 'sigma' | 'suricata' | 'yara'
  engine?: string
  include_content?: boolean
}

export function listRules(query: RuleQuery = {}): Promise<{ items: RuleItem[]; total: number }> {
  const params: Record<string, unknown> = {}
  if (query.type) params.rule_type = query.type
  if (query.engine) params.engine = query.engine
  if (query.include_content !== undefined) params.include_content = query.include_content
  return apiGet('/rules', params)
}

export function getRuleContent(rule: RuleItem): Promise<RuleItem> {
  return apiGet('/rules/content', { engine: rule.engine, path: rule.path })
}
