import { apiGet, apiPost } from './client'

/** A published version of the central rule set. Immutable once published. */
export interface RuleSetVersion {
  id: number
  version: string
  status: 'published' | 'superseded' | string
  rule_count: number
  sha256: string
  schema_version: string
  engine_version: string
  min_agent_version: string
  origin_version: string
  changelog: string
  published_by: string
  created_at: string
}

export interface WorkingRule {
  rule_id: string
  name: string
  entity: string
  pattern: string
  confidence: number
  validator: string
  enabled: boolean
  rule_source: string
  level: string
  field_hints?: string[]
  keywords?: string[]
  field_only?: boolean
}

export interface RuleSetSummary {
  id: number
  name: string
  description: string
  active_version: RuleSetVersion | null
  working_rule_count: number
  capabilities: Record<string, unknown>
}

export function listRuleSets(): Promise<{ items: RuleSetSummary[]; total: number }> {
  return apiGet('/rulesets')
}

export function listWorkingRules(ruleSetId: number): Promise<{ items: WorkingRule[]; total: number }> {
  return apiGet(`/rulesets/${ruleSetId}/rules`)
}

export function listRuleSetVersions(ruleSetId: number): Promise<{ items: RuleSetVersion[]; total: number; active_version: string }> {
  return apiGet(`/rulesets/${ruleSetId}/versions`)
}

export function publishRuleSetVersion(
  ruleSetId: number,
  payload: { version: string; changelog?: string; min_agent_version?: string },
): Promise<RuleSetVersion> {
  return apiPost(`/rulesets/${ruleSetId}/versions`, payload)
}

export function rollbackRuleSetVersion(
  ruleSetId: number,
  payload: { to_version: string; changelog?: string },
): Promise<RuleSetVersion> {
  return apiPost(`/rulesets/${ruleSetId}/rollback`, payload)
}
